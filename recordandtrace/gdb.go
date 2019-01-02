package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	gdb "github.com/benjojo/dive-into-dos/remotegdb"
)

type dosSyscall struct {
	Time             time.Time
	Opcode           uint8
	Registers        gdb.X86Registers
	DS, PostCode     []byte
	PostCodeLocation int
	Marker           int
}

type gdbTrace struct {
	Actions []dosSyscall
	stop    bool
	g       *gdb.GDBConnection
	l       sync.Mutex
	Hack    net.Conn
}

// F8 40 19 00
var magicBreakpoint = 0x4289 // old
// var magicBreakpoint = 0x1940f8

func startTraceMSDOS(gdbsocket string) *gdbTrace {
	c, err := net.Dial("unix", gdbsocket)
	if err != nil {
		log.Fatal("Unabel to dial GDB socket")
	}

	gcon := gdb.NewConnection(c)
	gcon.SetBreakpoint(magicBreakpoint, true)

	syscallList := make([]dosSyscall, 0)

	gobj := &gdbTrace{
		g:       gcon,
		Actions: syscallList,
		Hack:    c,
	}
	go gobj.backgroundTrace()
	return gobj
}

func (g *gdbTrace) Stop() {
	g.stop = true
}

func (g *gdbTrace) didCommandFinish() bool {
	g.l.Lock()
	defer g.l.Unlock()

	len := len(g.Actions)
	if len == 0 {
		return false
	}

	// check if has suspect syscalls that normally happen when waiting for DOS input
	if (g.Actions[len-1].Opcode == 10) && (g.Actions[len-2].Opcode == 93) {
		return true
	}

	return false
}

func (g *gdbTrace) SetMarker() {
	g.l.Lock()
	defer g.l.Unlock()

	g.Actions = append(g.Actions, dosSyscall{Time: time.Now(), Marker: 1})
}

func (g *gdbTrace) backgroundTrace() {
	g.g.Continue()
	// magicBreakpoint
	g.g.UnsetBreakpoint(magicBreakpoint, true)
	g.g.Step()
	R, err := g.g.GetRegisters()
	if err != nil && !g.stop {
		log.Fatalf("failed to register %s", err.Error())
	}

	// fmt.Printf("AH: %02x AKA: %s\n", R.Al, opCodes[fmt.Sprintf("%02x", R.Al)])
	g.l.Lock()
	g.Actions = append(g.Actions, dosSyscall{Time: time.Now(), Opcode: R.Al, Registers: R})
	g.l.Unlock()

	for {
		g.g.SetBreakpoint(magicBreakpoint, true)
		g.g.Continue()
		g.g.UnsetBreakpoint(magicBreakpoint, true)
		g.g.Step()
		R, err := g.g.GetRegisters()
		if err != nil {
			if !g.stop {
				log.Fatalf("failed to register %s", err.Error())
			} else {
				log.Printf("Tracing disabled")
				return
			}
		}
		fmt.Print(".")

		DsPTR := int(R.Ds*16) + int(R.Dx)

		// if R.Al == 9 {
		// 	fmt.Printf("DEBUG: DsPTR location is %x\n", DsPTR)
		// 	fmt.Printf("DEBUG: DSS: %x   DSS2: %x  DS: %x  EDX: %x   DX: %x   ", R.Dss, R.Dss2, R.Ds, R.Edx, R.Dx)

		// 	fmt.Printf("\n\n%#v\n", R)
		// }

		DSA, err := g.g.GetMemory(DsPTR, 100)
		if err != nil {
			log.Printf("Failed to get DS:DX for debug capture: %s", err.Error())
		}

		// We need to get the code ran after the syscall, the two values we need to get these
		// have been placed on the stack, so we need SS:SP
		StackPTR := int(uint32(R.Ss)*16) + int(R.Esp)
		Stack, err := g.g.GetMemory(StackPTR, 10)
		if err != nil {
			log.Printf("Failed to get SS:SP for debug capture: %s", err.Error())
		}

		// fmt.Printf("SS: %x   ESP: %x   ", R.Ss, R.Esp)
		// fmt.Printf("STACK PTR: %x\n", StackPTR)
		// fmt.Printf("STACK: %x\n", Stack)

		// Stack look here like:
		// 07 01 94 10
		// When we want it to look like:
		// 01 07 10 94

		// Meaning:
		// AA BB CC DD
		// To
		// BB AA DD CC

		// This is because we need to construct a PTR again for the code, so like:

		// 1094:0107 = Code Address Return

		// Major := binary.LittleEndian.Uint16([]byte{Stack[3], Stack[2]})
		Major := binary.LittleEndian.Uint16([]byte{Stack[2], Stack[3]})
		Minor := binary.LittleEndian.Uint16([]byte{Stack[0], Stack[1]})

		CodePTR := int(int32(Major)*16) + int(Minor)
		ReturnCode, err := g.g.GetMemory(CodePTR, 50)
		if err != nil {
			log.Printf("Failed to get return code for debug capture: %s", err.Error())
		}
		// fmt.Printf("Urgh CS: %x   EIP: %x\n", Major, Minor)

		if R.Al == 42 {
			// fmt.Printf("RCode: %x\n", ReturnCode)

			// go FuckItProxy(g.Hack)

			// g.l.Lock()
			// log.Printf("Launching the fuck it proxy!")
			// time.Sleep(time.Hour)

		}

		g.l.Lock()
		g.Actions = append(g.Actions, dosSyscall{Time: time.Now(), Opcode: R.Al, Registers: R, DS: DSA, PostCode: ReturnCode, PostCodeLocation: CodePTR})
		g.l.Unlock()
	}
}

func FuckItProxy(lol net.Conn) {
	l, err := net.Listen("tcp4", "localhost:1234")
	if err != nil {
		log.Printf("FuckItProxy was not able to run\n\n\n\n\n%s\n\n", err)
		return
	}

	conn, _ := l.Accept()

	go func() {
		io.Copy(conn, lol)
	}()
	io.Copy(lol, conn)

}
