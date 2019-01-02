package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	gdb "github.com/benjojo/dive-into-dos/remotegdb"
	"github.com/bnagy/gapstone"
)

type Webdata struct {
	Filename string
	SC       []syscallCapture
}

type syscallCapture struct {
	Opcode           int    `json:"Opcode"`
	Time             string `json:"Time"`
	Registers        gdb.X86Registers
	DS, PostCode     []byte
	Marker           int
	PostCodeLocation int
}

func main() {
	urladdr := flag.String("url", "", "the target sample URL")
	flag.Parse()
	log.SetFlags(log.Lshortfile | log.Ltime)

	if *urladdr == "" {
		flag.Usage()
		return
	}

	resp, err := http.Get(*urladdr)
	if err != nil {
		log.Fatalf("Unable to fetch job, %s", err.Error())
	}

	b, _ := ioutil.ReadAll(resp.Body)
	WD := Webdata{}
	err = json.Unmarshal(b, &WD)
	if err != nil {
		log.Fatalf("Unable to decode job %s", err.Error())
	}

	utimes := make([]time.Time, 0)
	udates := make([]time.Time, 0)
	donepc := make(map[int]bool)

	for _, call := range WD.SC {
		if call.Opcode == 0x2A {
			if donepc[call.PostCodeLocation] {
				continue
			}
			donepc[call.PostCodeLocation] = true

			paths := SolveForDate(call)
			if len(paths) == 0 || len(paths) == 1 {
				continue
			}
			// idk handle it

			for _, v := range paths {
				udates = append(udates, v[0])
			}
		}

		if call.Opcode == 0x2C {
			if donepc[call.PostCodeLocation] {
				continue
			}
			donepc[call.PostCodeLocation] = true

			paths := SolveForTime(call)
			if len(paths) == 0 || len(paths) == 1 {
				continue
			}

			for _, v := range paths {
				utimes = append(utimes, v[0])
			}

		}
	}

	// now we need to calculate tests

	jobs := make([]SideJob, 0)

	bits, _ := url.Parse(*urladdr)
	idn, _ := strconv.ParseInt(bits.Query().Get("id"), 10, 64)

	if len(utimes) == 0 && len(udates) != 0 {
		// Compile for dates
		for _, v := range udates {
			SJ := SideJob{}
			SJ.DateBased = true
			SJ.TimeBased = false

			SJ.Day = v.Day()
			SJ.Year = v.Year()
			SJ.Month = int(v.Month())
			SJ.OriginalID = int(idn)

			jobs = append(jobs, SJ)
		}

	} else if len(udates) == 0 && len(utimes) != 0 {
		// Compile for time

		for _, v := range utimes {
			SJ := SideJob{}
			SJ.DateBased = false
			SJ.TimeBased = true

			SJ.Hour = v.Hour()
			SJ.Min = v.Minute()
			SJ.Second = v.Second()
			SJ.OriginalID = int(idn)

			jobs = append(jobs, SJ)
		}
	} else if len(udates) == 0 && len(utimes) == 0 {
		// None
	} else {
		// Both

		for _, timeS := range utimes {
			for _, dateS := range utimes {

				SJ := SideJob{}
				SJ.DateBased = true
				SJ.TimeBased = true

				SJ.Day = dateS.Day()
				SJ.Year = dateS.Year()
				SJ.Month = int(dateS.Month())

				SJ.Hour = timeS.Hour()
				SJ.Min = timeS.Minute()
				SJ.Second = timeS.Second()
				SJ.OriginalID = int(idn)

				jobs = append(jobs, SJ)
			}
		}
	}

	log.Printf("Puzzle solver results:")
	for _, v := range jobs {
		log.Printf("%#v\n", v)

		b, _ := json.Marshal(v)

		req, _ := http.Post("http://localhost:9998/addsidejob", "application/json", bytes.NewReader(b))
		req.Body.Close()
	}

}

type SideJob struct {
	DateBased                           bool
	Day, Month, Year, Hour, Min, Second int
	TimeBased                           bool
	OriginalID                          int
	SideJobID                           int
}

func SolveForTime(in syscallCapture) map[string][]time.Time {
	// This will emulate x86 until a different solution is found.

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		// gapstone.CS_MODE_32,
		gapstone.CS_MODE_16,
	)

	defer engine.Close()
	maj, min := engine.Version()
	log.Printf("Hello Capstone! Version: %v.%v\n", maj, min)
	log.Printf("Code: %x", in.PostCode)

	insns, err := engine.Disasm(
		[]byte(in.PostCode),         // code buffer
		uint64(in.PostCodeLocation), // starting address
		0,                           // insns to disassemble, 0 for all
	)

	if err != nil {
		log.Fatalf("unable to disasm: %s", err.Error())
	}

	log.Printf("Disasm:\n")
	for _, insn := range insns {
		log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		// buffer += fmt.Sprintf("0x%x:\t%s\t\t%s\n</br>", insn.Address, insn.Mnemonic, insn.OpStr)
	}

	DHmonth := 1 // 1-12
	DLday := 1   // 1-31

	testingdate := time.Date(1980, time.Month(DHmonth), DLday, 0, 0, 0, 0, time.Local)

	dateToPath := make(map[string][]time.Time)

	for {
		Dhour, Dmins, Dseconds := testingdate.Hour(), testingdate.Minute(), testingdate.Second()
		// and run the test here

		injectRegisters := in.Registers
		injectRegisters = setRegister("ch", uint16(Dhour), injectRegisters)
		injectRegisters = setRegister("cl", uint16(Dmins), injectRegisters)
		injectRegisters = setRegister("dh", uint16(Dseconds), injectRegisters)
		injectRegisters = setRegister("dl", uint16(0), injectRegisters)

		path := runFunctionWithRegisters(insns, in.PostCodeLocation, injectRegisters)

		pstr := fmt.Sprintf("%v", path)
		timearray := dateToPath[pstr]
		if timearray == nil {
			timearray = make([]time.Time, 0)
		}
		timearray = append(timearray, testingdate)
		dateToPath[pstr] = timearray

		// Done?
		// set it again for the loop

		testingdate = testingdate.Add(time.Second)
		if testingdate.Day() != 1 {
			break
		}
	}

	log.Printf("Paths:")
	for k, v := range dateToPath {
		log.Printf("For the path: %s", k)
		if len(v) > 20 {
			log.Printf("\n\nDate: %v\n", v[:20])
		} else {
			log.Printf("\n\nDate: %v\n", v)

		}
	}

	return dateToPath
}

func SolveForDate(in syscallCapture) map[string][]time.Time {
	// This will emulate x86 until a different solution is found.

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		// gapstone.CS_MODE_32,
		gapstone.CS_MODE_16,
	)

	defer engine.Close()
	maj, min := engine.Version()
	log.Printf("Hello Capstone! Version: %v.%v\n", maj, min)
	log.Printf("Code: %x", in.PostCode)

	insns, err := engine.Disasm(
		[]byte(in.PostCode),         // code buffer
		uint64(in.PostCodeLocation), // starting address
		0,                           // insns to disassemble, 0 for all
	)

	if err != nil {
		log.Fatalf("unable to disasm: %s", err.Error())
	}

	log.Printf("Disasm:\n")
	for _, insn := range insns {
		log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		// buffer += fmt.Sprintf("0x%x:\t%s\t\t%s\n</br>", insn.Address, insn.Mnemonic, insn.OpStr)
	}

	t, err := lazyScan(insns)
	if err == nil {
		log.Printf("Possible solution: %q", t)
	} else {
		log.Printf("failed")
	}

	DHmonth := 1 // 1-12
	DLday := 1   // 1-31

	testingdate := time.Date(1980, time.Month(DHmonth), DLday, 5, 5, 5, 5, time.Local)

	dateToPath := make(map[string][]time.Time)

	for {
		ALdayofweek := int(testingdate.Weekday())
		Dyear, DHmonth, DLday := testingdate.Date()
		// and run the test here

		injectRegisters := in.Registers
		injectRegisters.Al = uint8(ALdayofweek)
		injectRegisters = setRegister("al", uint16(injectRegisters.Al), injectRegisters)
		// injectRegisters.Dx = binary.LittleEndian.Uint16([]byte{byte(DLday), byte(DHmonth)})
		injectRegisters = setRegister("dl", uint16(byte(DLday)), injectRegisters)
		injectRegisters = setRegister("dh", uint16(byte(DHmonth)), injectRegisters)
		injectRegisters.Ecx = uint32(Dyear)
		injectRegisters = setRegister("cx", uint16(Dyear), injectRegisters)

		path := runFunctionWithRegisters(insns, in.PostCodeLocation, injectRegisters)

		pstr := fmt.Sprintf("%v", path)
		timearray := dateToPath[pstr]
		if timearray == nil {
			timearray = make([]time.Time, 0)
		}
		timearray = append(timearray, testingdate)
		dateToPath[pstr] = timearray

		// Done?
		// set it again for the loop

		Dyear, DHmonth, DLday = testingdate.AddDate(0, 0, 1).Date()
		testingdate = time.Date(Dyear, time.Month(DHmonth), DLday, 5, 5, 5, 5, time.Local)
		if Dyear == 2005 {
			break
		}
	}

	log.Printf("Paths:")
	for k, v := range dateToPath {
		log.Printf("For the path: %s", k)
		if len(v) > 20 {
			log.Printf("\n\nDate: %v\n", v[:20])
		} else {
			log.Printf("\n\nDate: %v\n", v)

		}
	}

	return dateToPath
}

func lazyScan(opcodes []gapstone.Instruction) (t time.Time, err error) {
	log.Printf("YOOOOOOOOOOOOOOOOOOOOOOOOO")

	dateRegisters := map[string]bool{"al": true, "ax": true, "cx": true, "dh": true, "dl": true, "dx": true}
	for _, v := range opcodes {
		if v.Mnemonic == "cmp" {
			parts := strings.Split(v.OpStr, ",")
			for k, v := range parts {
				parts[k] = strings.Trim(v, " \t\n\r")
			}

			if !dateRegisters[parts[0]] {
				// It does not compare a date register
				continue
			}

			// If we are at this point then we are CMPing date registers.

			if parts[0] == "ax" {
				log.Printf("a CMP with a AX comparison for date, this is not traceable due to lack of context")
				return time.Time{}, nil
			}

			if parts[0] == "al" {
				// Day of week!
				day := 14
				for {
					tdate := time.Date(1995, time.Month(2), day, 5, 5, 5, 0, time.Local)
					targetDOW, err := parsePram(parts[1])

					// simpleint, err := strconv.ParseInt(parts[1], 10, 64)
					// if err != nil {
					// 	// must be an addr
					// 	simpleint = int64(resolveAddress(parts[1]))
					if err != nil {
						log.Printf("failed to parse CMP, %s", parts[1])
						break
					}
					// }

					if int(targetDOW) == int(tdate.Weekday()) {
						// Cool, that' works for me
						log.Printf("DOW trigger, %q", tdate.Weekday())
						return tdate, nil
					}
					day++
					if day == 30 {
						break
					}
				}
				log.Printf("failed to find date needed for AL")
				return time.Time{}, fmt.Errorf("Unable to find solution")
			}

			if parts[0] == "cx" {
				targetyear, err := parsePram(parts[1])
				if err != nil {
					log.Printf("failed to parse CMP, %s", parts[1])
					return time.Time{}, fmt.Errorf("Unable to find solution")
				}
				tdate := time.Date(int(targetyear), time.Month(2), 14, 5, 5, 5, 0, time.Local)
				log.Printf("Year trigger, %d", targetyear)
				return tdate, nil
			}

			if parts[0] == "dh" {
				month, err := parsePram(parts[1])
				if err != nil {
					log.Printf("failed to parse CMP, %s", parts[1])
					return time.Time{}, fmt.Errorf("Unable to find solution")
				}
				tdate := time.Date(1995, time.Month(month), 14, 5, 5, 5, 0, time.Local)
				log.Printf("Month trigger, %d", month)
				return tdate, nil
			}

			if parts[0] == "dl" {
				day, err := parsePram(parts[1])
				if err != nil {
					log.Printf("failed to parse CMP, %s", parts[1])
					return time.Time{}, fmt.Errorf("Unable to find solution")
				}
				tdate := time.Date(1995, 1, int(day), 5, 5, 5, 0, time.Local)
				log.Printf("Day trigger, %d", day)
				return tdate, nil
			}

			if parts[0] == "dx" {
				// Oh. Shit.

				// They are checking a combo of day and month in a single cmp.
				dx, err := parsePram(parts[1])
				if err != nil {
					log.Printf("failed to parse CMP, %s", parts[1])
					return time.Time{}, fmt.Errorf("Unable to find solution")
				}
				// log.Printf("YOOOOOOOOOOOOOOOOOOOOOOOOO")
				urgh := make([]byte, 2)
				binary.LittleEndian.PutUint16(urgh, uint16(dx))
				log.Printf("DX check %#v %x", parts, urgh)

				tdate := time.Date(1995, time.Month(urgh[1]), int(urgh[0]), 5, 5, 5, 0, time.Local)
				log.Printf("Day and Month trigger, %d the %d", time.Month(urgh[1]), int(urgh[0]))

				return tdate, nil
			}

		}
		return time.Time{}, fmt.Errorf("Unable to find solution")
		// Fuck it lol
	}

	return time.Time{}, fmt.Errorf("Unable to find solution")
}

func parsePram(in string) (int, error) {
	simpleint, err := strconv.ParseInt(in, 10, 64)
	if err != nil {
		// must be an addr
		simpleint = int64(resolveAddress(in))
		if simpleint == 999999999 {
			log.Printf("failed to parse pram, %s", in)
			return 0, fmt.Errorf("Failed to get anything reasonable")
		}
		return int(simpleint), nil
	}
	return int(simpleint), nil
}

var maxopcodes = 10000

type eflags struct {
	CF, PF, AF, ZF, SF, TF, IF, DF, OF bool
}

// Runs a x86 snippet and logs where it is going until it reaches the end or the max op code limit
func runFunctionWithRegisters(opcodes []gapstone.Instruction, startloc int, oreg gdb.X86Registers) []uint {
	execpath := make([]uint, 0)
	ptr := 0
	OpsRan := 0

	CPUFlags := eflags{}
	CMPOp1 := uint16(0)
	CMPOp2 := uint16(0)

	state := oreg
	for {
		OpsRan++
		if OpsRan > maxopcodes {
			return execpath
		}

		execpath = append(execpath, opcodes[ptr].Address) // log path

		// clean up the parts of the opstr for later use
		parts := strings.Split(opcodes[ptr].OpStr, ",")
		for k, v := range parts {
			parts[k] = strings.Trim(v, " \t\n\r")
		}

		// log.Printf("0x%x:\t%s\t\t%s\n", opcodes[ptr].Address, opcodes[ptr].Mnemonic, opcodes[ptr].OpStr)

		for _, v := range parts {
			if strings.Contains(v, "ptr") {
				log.Printf("data access to a memory pointer happened, this can't be simulated, exiting.")
				return execpath // Unhappy path
			}
		}

		// Check if it's a conditional jump
		switch opcodes[ptr].Mnemonic {
		case "jz", "je":
			if (CMPOp1 - CMPOp2) == 0 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "ja":
			if CMPOp1 > CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jne":
			// log.Printf("JNE does %x != %x", CMPOp1, CMPOp2)
			if CMPOp1 != CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jmp":
			nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
			if nextptr != -1 {
				ptr = nextptr
				continue
			} else {
				return execpath
			}
		case "jb":
			if CMPOp1 < CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jae":
			if CMPOp1 < CMPOp2 || CMPOp1 == CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jbe":
			if CMPOp1 > CMPOp2 || CMPOp1 == CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jl":
			if CMPOp1 < CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jge":
			if CMPOp1 > CMPOp2 || CMPOp1 == CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "jg":
			if CMPOp1 > CMPOp2 {
				nextptr := FindAddressPtr(opcodes, resolveAddress(opcodes[ptr].OpStr))
				if nextptr != -1 {
					ptr = nextptr
					continue
				} else {
					return execpath
				}
			}
			ptr++
			continue
		case "loop":
			// Will almost never end well, end simulation
			return execpath
		case "lea":
			// Will almost never end well, end simulation
			return execpath
		case "ret", "call", "les", "out", "iret":
			// End the simulation, since not possible
			return execpath
		}

		// Check if it's maths
		switch opcodes[ptr].Mnemonic {
		case "cmp":
			// ok, so it is normally formualted like:
			// cmp	cx, 0x7bc
			// or
			// cmp	dx, cx

			// so we will split the ops in two and then I guess run some
			// test maths on them, CPU flags are going to be a pain but that's
			// just like in the world of x86!

			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram CMP! WTF?! %#v", parts)
			}

			if isRegister(parts[0]) {
				CMPOp1 = resolveRegister(parts[0], state)
			} else if resolveAddress(parts[0]) != 999999999 {
				// It's an address! neat.
				CMPOp1 = uint16(resolveAddress(parts[0]))
			} else {
				log.Printf("Unsupported CMP %#v", parts)
				return execpath
			}

			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else if resolveAddress(parts[1]) != 999999999 {
				// It's an address! neat.
				CMPOp2 = uint16(resolveAddress(parts[1]))
			} else {
				log.Printf("Unsupported CMP %#v", parts)
				return execpath
			}

			ptr++
			continue
		case "sub":
			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram SUB! WTF?! %#v", parts)
			}

			CMPOp1 = resolveRegister(parts[0], state)
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			state = setRegister(parts[0], CMPOp1-CMPOp2, state)
			ptr++
			continue
		case "inc":
			CMPOp1 = resolveRegister(parts[0], state)
			state = setRegister(parts[0], CMPOp1+1, state)
			ptr++
			continue
		case "or":
			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram ADD! WTF?! %#v", parts)
			}

			CMPOp1 = resolveRegister(parts[0], state)
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			state = setRegister(parts[0], CMPOp1|CMPOp2, state)
			ptr++
			continue
		case "xor":
			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram ADD! WTF?! %#v", parts)
			}

			CMPOp1 = resolveRegister(parts[0], state)
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			state = setRegister(parts[0], CMPOp1^CMPOp2, state)
			ptr++
			continue
		case "add":
			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram ADD! WTF?! %#v", parts)
			}

			CMPOp1 = resolveRegister(parts[0], state)
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			state = setRegister(parts[0], CMPOp1+CMPOp2, state)
			ptr++
			continue
		case "and":
			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram ADD! WTF?! %#v", parts)
			}

			CMPOp1 = resolveRegister(parts[0], state)
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			state = setRegister(parts[0], CMPOp1&CMPOp2, state)
			ptr++
			continue

		case "dec":
			CMPOp1 = resolveRegister(parts[0], state)
			state = setRegister(parts[0], CMPOp1-1, state)
			ptr++
			continue
		case "shl":
			// Fuck this lol
			if len(parts) != 2 {
				log.Fatalf("there is a more than two pram SHL! WTF?! %#v", parts)
			}

			CMPOp1 = resolveRegister(parts[0], state)
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			if CMPOp2 == 1 {
				state = setRegister(parts[0], CMPOp1*2, state)
			} else {
				for i := uint16(0); i < CMPOp2; i++ {
					CMPOp1 = CMPOp1 * 2
				}
				state = setRegister(parts[0], CMPOp1, state)
			}
			ptr++
			continue
		case "mul":
			if len(parts) != 1 {
				log.Fatalf("Invalid MUL! %#v", parts)
			}

			CMPOp1 = resolveRegister("al", state)
			if isRegister(parts[0]) {
				CMPOp2 = resolveRegister(parts[0], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[0]))
			}

			state = setRegister("ax", CMPOp1*CMPOp2, state)
			ptr++
			continue
		// case "not":
		// case "test":
		case "cld":
			CPUFlags.DF = false
			ptr++
			continue

		// case "xchg":
		//https://www.felixcloutier.com/x86/XCHG.html

		case "nop", "cli", "sti":
			// Nice
			ptr++
			continue
		}

		// // Stack
		// // Check if it's maths
		// switch opcodes[ptr].Mnemonic {
		// case "pop":
		// case "push":
		// case "pushf":
		// 	// Push Flags
		// }

		// Mov:
		if opcodes[ptr].Mnemonic == "mov" {
			if isRegister(parts[1]) {
				CMPOp2 = resolveRegister(parts[1], state)
			} else {
				CMPOp2 = uint16(resolveAddress(parts[1]))
			}

			state = setRegister(parts[0], CMPOp2, state)
			ptr++
			continue
		}

		if opcodes[ptr].Mnemonic == "stosw" {
			// https://www.felixcloutier.com/x86/STOS:STOSB:STOSW:STOSD:STOSQ.html
		}

		//log.Printf("Bailing out since I've hit an unsupported opcode %s\t%s", opcodes[ptr].Mnemonic, opcodes[ptr].OpStr)
		break
	}

	return execpath
}

func setRegister(register string, value uint16, g gdb.X86Registers) gdb.X86Registers {
	if !isRegister(register) {
		log.Printf("!!! Register set with a invalid register name! %s", register)
		return g
	}

	switch register {
	case "ax":
		g.Eax = uint32(value)
		return g
	case "bx":
		g.Ebx = uint32(value)
		return g
	case "cx":
		g.Ecx = uint32(value)
		return g
	case "dx":
		g.Edx = uint32(value)
		return g

		// lol you are now fucked

	case "ah":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Eax))
		// AL:AH
		u16 := binary.LittleEndian.Uint16([]byte{reg[0], byte(value)})
		g.Eax = uint32(u16)
		return g

	case "al":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Eax))
		// AL:AH
		u16 := binary.LittleEndian.Uint16([]byte{byte(value), reg[1]})
		g.Eax = uint32(u16)
		return g

	case "bh":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ebx))
		// AL:AH
		u16 := binary.LittleEndian.Uint16([]byte{reg[0], byte(value)})
		g.Ebx = uint32(u16)
		return g
	case "bl":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ebx))
		// AL:AH
		u16 := binary.LittleEndian.Uint16([]byte{byte(value), reg[1]})
		g.Ebx = uint32(u16)
		return g

	case "ch":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ecx))
		// AL:AH
		u16 := binary.LittleEndian.Uint16([]byte{reg[0], byte(value)})
		g.Ecx = uint32(u16)
		return g
	case "cl":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ecx))
		// AL:AH
		u16 := binary.LittleEndian.Uint16([]byte{byte(value), reg[1]})
		g.Ecx = uint32(u16)
		return g

	case "dh":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Edx))
		// DL:DH
		u16 := binary.LittleEndian.Uint16([]byte{reg[0], byte(value)})
		g.Edx = uint32(u16)
		return g

	case "dl":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Edx))
		// DL:DH
		u16 := binary.LittleEndian.Uint16([]byte{byte(value), reg[1]})
		g.Edx = uint32(u16)
		return g

	case "bp":
		g.Ebp = uint32(value)
		return g

	case "si":
		g.Esi = uint32(value)
		return g

	case "di":
		g.Edi = uint32(value)
		return g

	case "sp":
		g.Esp = uint32(value)
		return g

	}

	log.Fatalf("Boom, Unknown register, still got past filter")
	return g

}

func isRegister(in string) bool {
	if in == "ax" || in == "ah" || in == "al" ||
		in == "bh" || in == "bl" || in == "bx" ||
		in == "ch" || in == "cl" || in == "cx" ||
		in == "dh" || in == "dl" || in == "dx" ||
		in == "bp" || in == "si" || in == "di" || in == "sp" {
		return true
	}
	return false
}

func resolveRegister(register string, g gdb.X86Registers) uint16 {
	switch register {
	case "ax":
		return uint16(g.Eax)
	case "bx":
		return uint16(g.Ebx)
	case "cx":
		return uint16(g.Ecx)
	case "dx":
		return uint16(g.Edx)

		// lol you are now fucked

	case "ah":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Eax))
		return uint16(reg[1])

	case "al":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Eax))
		return uint16(reg[0])

	case "bh":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ebx))
		return uint16(reg[1])

	case "bl":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ebx))
		return uint16(reg[0])

	case "ch":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ecx))
		return uint16(reg[1])

	case "cl":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Ecx))
		return uint16(reg[0])

	case "dh":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Edx))
		return uint16(reg[1])

	case "dl":
		reg := make([]byte, 2)
		binary.LittleEndian.PutUint16(reg, uint16(g.Edx))
		return uint16(reg[0])

	case "bp":
		return uint16(g.Ebp)

	case "si":
		return uint16(g.Esi)

	case "di":
		return uint16(g.Edi)

	case "sp":
		return uint16(g.Esp)

	}
	log.Fatalf("UNKNOWN REGISTER %s", register)
	return 0
}

func resolveAddress(in string) uint {
	if !strings.HasPrefix(in, "0x") {
		i, err := strconv.ParseInt(in, 10, 64)
		if err == nil {
			return uint(i)
		}
		return 999999999
	}
	// log.Printf("Hello from 0x parsing land")
	s := strings.Split(in, "x")
	if len(s) != 2 {
		return 999999999
	}

	if len(s[1])%2 == 1 {
		// we need to pad one
		s[1] = "0" + s[1]
	}

	i, err := strconv.ParseUint(s[1], 16, 20)
	if err != nil {
		return 999999999
	}

	return uint(i)
}

func FindAddressPtr(opcodes []gapstone.Instruction, target uint) int {
	for k, v := range opcodes {
		if v.Address == target {
			return k
		}
	}

	return -1
}
