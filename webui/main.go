package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"crawshaw.io/sqlite"
	gdb "github.com/benjojo/dive-into-dos/remotegdb"
	"github.com/bnagy/gapstone"
)

func main() {

	var err error
	dbpool, err = sqlite.Open("file:data.db", 0, 10)
	if err != nil {
		log.Fatalf("Unable to open SQLliteDB %s", err)
	}

	http.HandleFunc("/", listAll)
	http.HandleFunc("/time", listAllTime)
	http.HandleFunc("/favicon.ico", nothing)
	http.HandleFunc("/robots.txt", nothing)
	http.HandleFunc("/sample", sampleview)
	http.HandleFunc("/gif", getGIF)

	log.Fatalf("Failed to listen %s", http.ListenAndServe(":8888", nil).Error())
}

func nothing(rw http.ResponseWriter, req *http.Request) {

}

type syscallCapture struct {
	Opcode           int    `json:"Opcode"`
	Time             string `json:"Time"`
	Registers        gdb.X86Registers
	DS, PostCode     []byte
	Marker           int
	PostCodeLocation int
}

var giflock sync.Mutex

func getGIF(rw http.ResponseWriter, req *http.Request) {
	/*
		ffmpeg -i $1 -vf "fps=15,palettegen" -y /tmp/palette.png
		ffmpeg -i $1 -i /tmp/palette.png -lavfi "fps=15 [x]; [x][1:v] paletteuse" -
	*/

	id := req.URL.Query().Get("id")

	iid, _ := strconv.ParseInt(id, 10, 64)
	subiid := 0
	if iid == 0 {
		subid := req.URL.Query().Get("subid")

		siid, _ := strconv.ParseInt(subid, 10, 64)
		if siid != 0 {
			subiid = int(siid)
		} else {
			return
		}
	}

	conn := dbpool.Get(req.Context().Done())
	defer dbpool.Put(conn)

	query := "SELECT flv FROM samples WHERE sample_id = $sid LIMIT 1"

	if subiid != 0 {
		query = "SELECT flv FROM subtasks WHERE subtask_id = $sid LIMIT 1"
	}

	giflock.Lock()
	defer giflock.Unlock()

	stmt, err := conn.Prepare(query)
	if err != nil {
		Error(rw, err)
		return
	}

	if subiid != 0 {
		stmt.SetInt64("$sid", int64(subiid))
	} else {
		stmt.SetInt64("$sid", iid)
	}
	flvbytes := make([]byte, 10*10e6)

	for {
		hasRow, err := stmt.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}
		break
	}
	n := stmt.GetBytes("flv", flvbytes)
	ioutil.WriteFile("/tmp/lol.flv", flvbytes[:n], 0777)
	stmt.Finalize()

	pg := exec.Command("ffmpeg", "-i", "/tmp/lol.flv", "-vf", "fps=15,palettegen", "-y", "/tmp/palette.png")
	pg.Stderr = os.Stderr
	pg.Stdout = os.Stdout
	pg.Run()
	pg.Wait()

	// Yeah I don't actually care about the output here
	pg2 := exec.Command("ffmpeg", "-i", "/tmp/lol.flv", "-i", "/tmp/palette.png", "-lavfi", "fps=15 [x]; [x][1:v] paletteuse", "-f", "gif", "-")
	pg2.Stderr = os.Stderr
	stdout, _ := pg2.StdoutPipe()
	pg2.Start()
	rw.Header().Set("Content-Type", "image/gif")
	rw.WriteHeader(200)
	io.Copy(rw, stdout)
	pg2.Wait()

}

func cleanUpSyscalls(in []syscallCapture) []syscallCapture {
	if len(in) < 10 {
		return in
	}

	if in[0].Opcode == 64 &&
		in[1].Opcode == 41 &&
		in[2].Opcode == 41 &&
		in[3].Opcode == 41 &&
		in[4].Opcode == 26 &&
		in[5].Opcode == 71 &&
		in[6].Opcode == 78 &&
		in[7].Opcode == 71 &&
		in[8].Opcode == 73 &&
		in[9].Opcode == 75 {
		in = in[10:]
	}

	for k, v := range in {
		if v.Opcode == 72 {

			if len(in)-k < 8 {
				// Checking if we have enough syscalls ahead of us
				// for this check to work.
				return in
			}

			if in[k+1].Opcode == 72 &&
				in[k+2].Opcode == 37 &&
				in[k+3].Opcode == 37 &&
				in[k+4].Opcode == 37 &&
				in[k+5].Opcode == 62 &&
				in[k+6].Opcode == 62 {
				return in[:k-1]
			}
		}
	}

	return in
}

type sampleFeatures struct {
	Finishes, LooksAtTime, WritesToFiles bool
}

func getFlagsFromSample(syscalls string) (f sampleFeatures, clean []syscallCapture) {
	var SysCalls []syscallCapture

	json.Unmarshal([]byte(syscalls), &SysCalls)
	CleanSySCalls := cleanUpSyscalls(SysCalls)

	len := len(SysCalls)
	if len == 0 {
		return f, CleanSySCalls
	}

	// check if has suspect syscalls that normally happen when waiting for DOS input
	if (SysCalls[len-1].Opcode == 10) && (SysCalls[len-2].Opcode == 93) {
		f.Finishes = true
	}

	for _, v := range CleanSySCalls {
		if v.Opcode == 44 {
			f.LooksAtTime = true
		}

		if v.Opcode == 42 {
			f.LooksAtTime = true
		}

		if v.Opcode == 65 || // Unlink
			v.Opcode == 0x17 || // Rename
			v.Opcode == 0x40 || // Write file or device
			v.Opcode == 0x41 || // Unlink 2
			v.Opcode == 0x13 || // Unlink
			v.Opcode == 0x5A || // Create unique file
			v.Opcode == 0x56 { // Rename 2
			f.WritesToFiles = true
		}

	}

	return f, CleanSySCalls
}

func sampleview(rw http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")

	iid, _ := strconv.ParseInt(id, 10, 64)
	if iid == 0 {
		return
	}

	conn := dbpool.Get(req.Context().Done())
	defer dbpool.Put(conn)

	stmt, err := conn.Prepare("SELECT filename,syscalls FROM samples WHERE sample_id = $sid LIMIT 1")
	if err != nil {
		Error(rw, err)
		return
	}

	stmt.SetInt64("$sid", iid)
	var filename, syscalls string

	for {
		hasRow, err := stmt.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}

		filename = stmt.GetText("filename")
		syscalls = stmt.GetText("syscalls")
		break
	}
	stmt.Finalize()

	var SysCalls []syscallCapture

	json.Unmarshal([]byte(syscalls), &SysCalls)
	TSC := SysCalls
	SysCalls = cleanUpSyscalls(SysCalls)

	if req.URL.Query().Get("raw") != "" {
		log.Printf("Weeeeeeeeeeeeee")
		b, err := json.Marshal(struct {
			Filename string
			SC       []syscallCapture
		}{
			Filename: filename,
			SC:       TSC,
		})

		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.WriteHeader(200)
		rw.Write(b)
		return
	}

	// Now we render!

	rw.Write([]byte(`<!DOCTYPE html>
	<html>
	<head>
	<style>
	table, th, td {
		border: 1px solid black;
	}
	.false {
		background-color: lightcoral;
	}
	.true {
		background-color: lightgreen;
	}
	</style>
	</head>
	<body>
	
	<h1>Sample viewer</h1>`))

	rw.Write([]byte(fmt.Sprintf("<h2>%s</h2>\n<p>.</p><h2>GIF</h2>", filename)))

	rw.Write([]byte(fmt.Sprintf("<img src=\"/gif?id=%d>\"\n<h2>Syscalls:</h2>", iid)))

	rw.Write([]byte(`<table style="width:100%">
	  <tr>
		<th>Time</th>
		<th>Syscall Op</th> 
		<th>Syscall Name</th>
	  </tr>`))

	for _, v := range SysCalls {
		rw.Write([]byte(fmt.Sprintf(`
	  <tr> <td>%s</td> <td>%d</td> <td>PC: %x | %s %s</td></tr>`,
			v.Time, v.Opcode, v.PostCodeLocation, getSyscallName(v.Opcode), AnnotateSyscall(v.Opcode, v.Registers, v))))
	}

	rw.Write([]byte(`</table>`))

	rw.Write([]byte(`<hl>`))

	// Now lookup the sub-tasks

	stmt2, err := conn.Prepare("SELECT subtask_id,state,syscalls FROM subtasks WHERE sample_id = $sid AND evaluated = 2")
	if err != nil {
		Error(rw, err)
		return
	}

	stmt2.SetInt64("$sid", iid)

	for {
		var subtaskID int64
		var state, syscallblob string

		hasRow, err := stmt2.Step()
		if err != nil {
			Error(rw, err)
			break
		} else if !hasRow {
			log.Print("uh")
			break
		}

		state = stmt2.GetText("state")
		syscallblob = stmt2.GetText("syscalls")
		subtaskID = stmt2.GetInt64("subtask_id")

		rw.Write([]byte(fmt.Sprintf("<h2>%s</h2>\n<p>.</p><h2>GIF</h2>", state)))

		rw.Write([]byte(fmt.Sprintf("<img src=/gif?subid=%d>\n<h2>Syscalls:</h2>", subtaskID)))

		var SysCalls []syscallCapture

		json.Unmarshal([]byte(syscallblob), &SysCalls)
		// TSC := SysCalls
		SysCalls = cleanUpSyscalls(SysCalls)

		rw.Write([]byte(`<table style="width:100%">
	<tr>
	  <th>Time</th>
	  <th>Syscall Op</th> 
	  <th>Syscall Name</th>
	</tr>`))

		for _, v := range SysCalls {
			rw.Write([]byte(fmt.Sprintf(`
	<tr> <td>%s</td> <td>%d</td> <td>PC: %x | %s %s</td></tr>`,
				v.Time, v.Opcode, v.PostCodeLocation, getSyscallName(v.Opcode), AnnotateSyscall(v.Opcode, v.Registers, v))))
		}

		rw.Write([]byte(`</table>`))

		rw.Write([]byte(`<hl>`))

	}
	stmt2.Finalize()

	rw.Write([]byte(`
	  </body>
	  </html>`))
}

var dbpool *sqlite.Pool

func getSyscallName(in int) string {
	switch in {
	case 0x00:
		return "Program terminate"
	case 0x01:
		return "Character input"
	case 0x02:
		return "Character output"
	case 0x03:
		return "Auxiliary input"
	case 0x04:
		return "Auxiliary output"
	case 0x05:
		return "Printer output"
	case 0x06:
		return "Direct console I/O"
	case 0x07:
		return "Direct console input without echo"
	case 0x08:
		return "Console input without echo"
	case 0x09:
		return "Display string"
	case 0x0A:
		return "Buffered keyboard input"
	case 0x0B:
		return "Get input status"
	case 0x0C:
		return "Flush input buffer and input"
	case 0x0D:
		return "Disk reset"
	case 0x0E:
		return "Set default drive"
	case 0x0F:
		return "Open file"
	case 0x10:
		return "Close file"
	case 0x11:
		return "Find first file"
	case 0x12:
		return "Find next file"
	case 0x13:
		return "Delete file"
	case 0x14:
		return "Sequential read"
	case 0x15:
		return "Sequential write"
	case 0x16:
		return "Create or truncate file"
	case 0x17:
		return "Rename file"
	case 0x18:
		return "Reserved"
	case 0x19:
		return "Get default drive"
	case 0x1A:
		return "Set disk transfer address"
	case 0x1B:
		return "Get allocation info for default drive"
	case 0x1C:
		return "Get allocation info for specified drive"
	case 0x1D:
		return "Reserved"
	case 0x1E:
		return "Reserved"
	case 0x1F:
		return "Get disk parameter block for default drive"
	case 0x20:
		return "Reserved"
	case 0x21:
		return "Random read"
	case 0x22:
		return "Random write"
	case 0x23:
		return "Get file size in records"
	case 0x24:
		return "Set random record number"
	case 0x25:
		return "Set interrupt vector"
	case 0x26:
		return "Create PSP"
	case 0x27:
		return "Random block read"
	case 0x28:
		return "Random block write"
	case 0x29:
		return "Parse filename"
	case 0x2A:
		return "Get date"
	case 0x2B:
		return "Set date"
	case 0x2C:
		return "Get time"
	case 0x2D:
		return "Set time"
	case 0x2E:
		return "Set verify flag"
	case 0x2F:
		return "Get disk transfer address"
	case 0x30:
		return "Get DOS version"
	case 0x31:
		return "Terminate and stay resident"
	case 0x32:
		return "Get disk parameter block for specified drive"
	case 0x33:
		return "Get or set Ctrl-Break"
	case 0x34:
		return "Get InDOS flag pointer"
	case 0x35:
		return "Get interrupt vector"
	case 0x36:
		return "Get free disk space"
	case 0x37:
		return "Get or set switch character"
	case 0x38:
		return "Get or set country info"
	case 0x39:
		return "Create subdirectory"
	case 0x3A:
		return "Remove subdirectory"
	case 0x3B:
		return "Change current directory"
	case 0x3C:
		return "Create or truncate file"
	case 0x3D:
		return "Open file"
	case 0x3E:
		return "Close file"
	case 0x3F:
		return "Read file or device"
	case 0x40:
		return "Write file or device"
	case 0x41:
		return "Delete file"
	case 0x42:
		return "Move file pointer"
	case 0x43:
		return "Get or set file attributes"
	case 0x44:
		return "I/O control for devices"
	case 0x45:
		return "Duplicate handle"
	case 0x46:
		return "Redirect handle"
	case 0x47:
		return "Get current directory"
	case 0x48:
		return "Allocate memory"
	case 0x49:
		return "Release memory"
	case 0x4A:
		return "Reallocate memory"
	case 0x4B:
		return "Execute program"
	case 0x4C:
		return "Terminate with return code"
	case 0x4D:
		return "Get program return code"
	case 0x4E:
		return "Find first file"
	case 0x4F:
		return "Find next file"
	case 0x50:
		return "Set current PSP"
	case 0x51:
		return "Get current PSP"
	case 0x52:
		return "Get DOS internal pointers (SYSVARS)"
	case 0x53:
		return "Create disk parameter block"
	case 0x54:
		return "Get verify flag"
	case 0x55:
		return "Create program PSP"
	case 0x56:
		return "Rename file"
	case 0x57:
		return "Get or set file date and time"
	case 0x58:
		return "case 0xGet or set allocation strateg:"
	case 0x59:
		return "Get extended error info"
	case 0x5A:
		return "Create unique file"
	case 0x5B:
		return "Create new file"
	case 0x5C:
		return "Lock or unlock file"
	case 0x5D:
		return "File sharing functions"
	case 0x5E:
		return "Network functions"
	case 0x5F:
		return "Network redirection functions"
	case 0x60:
		return "Qualify filename"
	case 0x61:
		return "Reserved"
	case 0x62:
		return "Get current PSP"
	case 0x63:
		return "Get DBCS lead byte table pointer"
	case 0x64:
		return "Set wait for external event flag"
	case 0x65:
		return "Get extended country info"
	case 0x66:
		return "Get or set code page"
	case 0x67:
		return "Set handle count"
	case 0x68:
		return "Commit file"
	case 0x69:
		return "Get or set media id"
	case 0x6A:
		return "Commit file"
	case 0x6B:
		return "Reserved"
	case 0x6C:
		return "Extended open/create file"
	}

	return "UNKNOWN!"
}

func int16ToHex(in uint16) string {
	bs := make([]byte, 2)
	binary.LittleEndian.PutUint16(bs, in)
	return hex.EncodeToString(bs)
}

func AnnotateSyscall(Ah int, R gdb.X86Registers, full syscallCapture) string {
	switch Ah {
	case 0x02:
		return fmt.Sprintf("(Char = '%s')", int16ToHex(R.Dx)[:2])
	case 0x09:
		i := strings.IndexByte(string(full.DS), '$')
		if i == -1 {
			return "(Could not find end pointer)"
		}
		return fmt.Sprintf("(String= '%s')", string(full.DS[:i]))
	case 0x0E:
		// return "Set default drive"
		b, _ := hex.DecodeString(int16ToHex(R.Dx)[:2])
		return fmt.Sprintf("(Drive = '%s')", string('A'+b[0]))
	case 0x0F:
		return fmt.Sprintf("(Filename = '%s')", string(full.DS))
	case 0x3D: // Open File using Handle
		i := strings.IndexByte(string(full.DS), 0x00)
		if i == -1 {
			return ""
		}
		// return fmt.Sprintf("(Filename = '%s') / RC</br>%s", string(full.DS[:i]), dumpReturnCode(full))
		return fmt.Sprintf("(Filename = '%s')", string(full.DS[:i]))
	case 0x3F: // Read using Handle
		return fmt.Sprintf("(Read %d bytes on handle %d)", R.Ecx, R.Bx)
	case 0x40: // Write using handle
		return fmt.Sprintf("(Write %d bytes on handle %d)", R.Ecx, R.Bx)
	case 0x41: // Delete using Handle
		i := strings.IndexByte(string(full.DS), 0x00)
		if i == -1 {
			return ""
		}
		return fmt.Sprintf("(Filename = '%s')", string(full.DS[:i]))
	case 0x44: // Get/Set File Attributes
		i := strings.IndexByte(string(full.DS), 0x00)
		if i == -1 {
			return ""
		}
		if R.Al == 00 {
			return fmt.Sprintf("(Get for = '%s')", string(full.DS[:i]))
		}
		return fmt.Sprintf("(Set for = '%s')", string(full.DS[:i]))

	case 0x25:
		return fmt.Sprintf("(Interrupt = '%d' AKA '%s')", R.Ah, getSyscallName(int(R.Ah)))
		// return "Set Interrupt Vector"
	case 0x31:
		return fmt.Sprintf("(Return code = '%d' | Memory size = '%d')", R.Ah, R.Dx)
		// return "Terminate and stay resident"
	case 0x35:
		return fmt.Sprintf("(Interrupt = '%d' AKA '%s')", R.Ah, getSyscallName(int(R.Ah)))
		// return "Get Interrupt Vector"
	case 0x4C:
		return fmt.Sprintf("(Return code = '%d')", R.Ah)
	// return "Terminate with return code"
	case 0x2A: // Get Date
		return dumpReturnCode(full)
	case 0x2C: // Get Time
		return dumpReturnCode(full)
	}
	return ""
}

func dumpReturnCode(all syscallCapture) string {
	log.Printf("wow ! \n\n%#v\n", all)

	buffer := "(DISAM FAILED)"
	if len(all.PostCode) == 0 {
		return buffer
	}

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		// gapstone.CS_MODE_32,
		gapstone.CS_MODE_16,
	)

	if err == nil {

		defer engine.Close()
		buffer = ""
		maj, min := engine.Version()
		log.Printf("Hello one! Version: %v.%v\n", maj, min)
		log.Printf("Code: %x", all.PostCode)

		insns, err := engine.Disasm(
			[]byte(all.PostCode),         // code buffer
			uint64(all.PostCodeLocation), // starting address
			20,                           // insns to disassemble, 0 for all
		)

		if err == nil {
			log.Printf("Disasm:\n")
			for _, insn := range insns {
				log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				buffer += fmt.Sprintf("0x%x:\t%s\t\t%s\n</br>", insn.Address, insn.Mnemonic, insn.OpStr)
			}
			return buffer
		} else {
			log.Printf("FUCK \n\n\n\n FUCK FUUUUUUUUUUUUUUCK~ \n\n\n %s \n\n\n", err.Error())
		}
	}
	return buffer
}

func listAllTime(rw http.ResponseWriter, req *http.Request) {
	conn := dbpool.Get(req.Context().Done())
	defer dbpool.Put(conn)

	stmt, err := conn.Prepare("SELECT DISTINCT(sample_id) as A FROM subtasks WHERE evaluated = 2;") // ORDER BY filename DESC
	if err != nil {
		Error(rw, err)
		return
	}
	defer stmt.Finalize()

	rw.Write([]byte(`<!DOCTYPE html>
	<html>
	<head>
	<style>
	table, th, td {
		border: 1px solid black;
	}
	.false {
		background-color: lightcoral;
	}
	.true {
		background-color: lightgreen;
	}
	</style>
	</head>
	<body>
	
	<h2>Malware listing</h2>
	
	<table style="width:100%">
	  <tr>
		<th>ID</th>
		<th>Filename</th> 
		<th>Diff syscalls</th> 
		<th>Diff Removes Files</th> 
		<th>Diff Hangs system</th> 
		<th>Link</th>
	  </tr>`))

	for {
		hasRow, err := stmt.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}

		var jobid int64
		// var sampleName string

		jobid = stmt.GetInt64("A")

		stmt2, err := conn.Prepare("SELECT syscalls FROM subtasks WHERE sample_id = $SID;") // ORDER BY filename DESC
		if err != nil {
			Error(rw, err)
			return
		}

		stmt2.SetInt64("$SID", jobid)
		syscallsamples := make([][]byte, 0)

		for {
			rr, err := stmt2.Step()
			if !rr || err != nil {
				break
			}

			syscallblob := make([]byte, 1e6*15)
			n := stmt2.GetBytes("syscalls", syscallblob)
			// syscallblob

			syscallsamples = append(syscallsamples, []byte(syscallblob[:n]))
		}
		stmt2.Finalize()
		stmt2, err = conn.Prepare("SELECT filename,syscalls FROM samples WHERE sample_id = $SID;") // ORDER BY filename DESC
		if err != nil {
			Error(rw, err)
			return
		}

		stmt2.SetInt64("$SID", jobid)
		filename := ""
		for {
			rr, err := stmt2.Step()
			if !rr || err != nil {
				break
			}

			syscallblob := stmt2.GetText("syscalls")
			filename = stmt2.GetText("filename")
			// syscallblob
			// fmt.Printf("\n%v\n", syscallblob)

			syscallsamples = append(syscallsamples, []byte(syscallblob))
		}
		stmt2.Finalize()

		//
		// We have all the syscall blobs now in syscallsamples
		//

		// <th>ID</th>
		// <th>Filename</th>
		// <th>Diff syscalls</th>
		// <th>Diff Removes Files</th>
		// <th>Diff Hangs system</th>
		// <th>Link</th>

		syscalllen := make(map[int]int)
		removesfiles := 0
		hangssystem := 0

		for _, v := range syscallsamples {
			var SysCalls []syscallCapture

			json.Unmarshal([]byte(v), &SysCalls)
			CleanSySCalls := cleanUpSyscalls(SysCalls)

			rfiles := false

			syscalllen[len(SysCalls)]++

			for _, scall := range CleanSySCalls {
				if scall.Opcode == 0x41 {
					rfiles = true
				}

				if scall.Opcode == 0x13 {
					rfiles = true
				}
			}

			if rfiles {
				removesfiles++
			}

			if len(SysCalls) > 2 &&
				SysCalls[len(SysCalls)-2].Opcode == 93 && SysCalls[len(SysCalls)-1].Opcode == 10 {

			} else {
				hangssystem++
			}
		}

		rw.Write([]byte(fmt.Sprintf(`
<tr> <td>%d</td>
<td>%s</td>
<td class="%v">%v</td>
<td class="%v">%v</td>
<td class="%v">%v</td>
<td><a href="/sample?id=%d">Link</a></td></tr>`, jobid, filename,
			len(syscalllen) != 1, len(syscalllen) != 1,
			removesfiles != len(syscallsamples) && removesfiles != 0, removesfiles != len(syscallsamples) && removesfiles != 0,
			hangssystem != len(syscallsamples), hangssystem != len(syscallsamples),
			jobid)))

		fmt.Printf("Sample: %d,\n\n Sampleset %d, \n Samples that remove files %d\nSamples that hang %d\nLendist: %v\n\n----\n", jobid, len(syscallsamples), removesfiles, hangssystem, syscalllen)

	}

	rw.Write([]byte(`
</table>

</body>
</html>`))
}

func listAll(rw http.ResponseWriter, req *http.Request) {
	conn := dbpool.Get(req.Context().Done())
	defer dbpool.Put(conn)

	stmt, err := conn.Prepare("SELECT sample_id,filename,syscalls FROM samples WHERE evaluated = 2") // ORDER BY filename DESC
	if err != nil {
		Error(rw, err)
		return
	}
	defer stmt.Finalize()

	rw.Write([]byte(`<!DOCTYPE html>
	<html>
	<head>
	<style>
	table, th, td {
		border: 1px solid black;
	}
	.false {
		background-color: lightcoral;
	}
	.true {
		background-color: lightgreen;
	}
	</style>
	</head>
	<body>
	
	<h2>Malware listing</h2>
	
	<table style="width:100%">
	  <tr>
		<th>ID</th>
		<th>Filename</th> 
		<th>Program Finishes</th> 
		<th>Checks Time</th> 
		<th>Modifies Files</th> 
		<th>Does something</th> 
		<th>Link</th>
	  </tr>`))

	for {
		hasRow, err := stmt.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}

		var jobid int64
		var sampleName string

		jobid = stmt.GetInt64("sample_id")
		sampleName = stmt.GetText("filename")
		samples := stmt.GetText("syscalls")
		sFeatures, fCalls := getFlagsFromSample(samples)

		rw.Write([]byte(fmt.Sprintf(`
<tr> <td>%d</td>
<td>%s</td>
<td class="%v">%v</td>
<td class="%v">%v</td>
<td class="%v">%v</td>
<td class="%v">%v</td>
<td><a href="/sample?id=%d">Link</a></td></tr>`, jobid, sampleName,
			sFeatures.Finishes, sFeatures.Finishes,
			sFeatures.LooksAtTime, sFeatures.LooksAtTime,
			sFeatures.WritesToFiles, sFeatures.WritesToFiles,
			len(fCalls) != 0, len(fCalls) != 0,
			jobid)))

	}

	rw.Write([]byte(`
</table>

</body>
</html>`))
}

func Error(rw http.ResponseWriter, err error) {
	log.Printf("ERR: %s ", err.Error())
	http.Error(rw, err.Error(), http.StatusInternalServerError)
}
