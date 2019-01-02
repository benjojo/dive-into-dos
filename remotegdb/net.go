package gdb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

type GDBConnection struct {
	c          io.ReadWriter
	askedVcont bool
}

func NewConnection(C io.ReadWriter) *GDBConnection {
	C.Write([]byte("+"))

	g := &GDBConnection{
		c: C,
	}

	g.checksumAndSend("qSupported:xmlRegisters=i386,arm,mips")

	time.Sleep(time.Millisecond * 500)
	throwaway := make([]byte, 100000)
	g.c.Read(throwaway)

	g.checksumAndSend("Hg0")
	time.Sleep(time.Millisecond * 500)
	throwaway = make([]byte, 100000)
	g.c.Read(throwaway)

	return g
}

type X86Registers struct {
	Eax    uint32
	Ecx    uint32
	Edx    uint32
	Ebx    uint32
	Esp    uint32
	Ebp    uint32
	Esi    uint32
	Edi    uint32
	Eip    uint32
	Eflags uint32
	Cs     uint32
	Ss     uint16
	Ds     uint32
	Dss    uint16
	Dss2   uint16
	Dss3   uint16
	Es     uint32
	Ess    uint16
	Fs     uint32
	Gs     uint32
	Ax     uint16
	Dx     uint16
	Bx     uint16
	Ah     uint8
	Al     uint8
}

func (g *GDBConnection) GetRegisters() (o X86Registers, err error) {
	g.checksumAndSend("g") // https://www.reddit.com/r/ggggg/
	rout, err := g.readAndChecksum()
	if err != nil {
		return o, err // ERR
	}

	// 00840000
	// f90000007f00000000000000900a0000000000000d010000fb010000d24000004600000019000000160100001601000016010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000801f0000

	hexs, err := hex.DecodeString(rout[:len(rout)-1])
	if err != nil {
		return o, err
	}

	o.Eax = binary.LittleEndian.Uint32(hexs[0 : 0+4])
	o.Ax = binary.LittleEndian.Uint16(hexs[0 : 0+2])
	o.Ah = uint8(hexs[0])
	o.Al = uint8(hexs[1])

	o.Ecx = binary.LittleEndian.Uint32(hexs[4 : 4+4])
	o.Edx = binary.LittleEndian.Uint32(hexs[8 : 8+4])
	o.Dx = binary.LittleEndian.Uint16(hexs[8 : 8+2])

	o.Ebx = binary.LittleEndian.Uint32(hexs[12 : 12+4])
	o.Bx = binary.LittleEndian.Uint16(hexs[12 : 12+2])

	// o.Esp = binary.LittleEndian.Uint32(hexs[16 : 16+4])
	// comes in like
	// 00009412
	// should look like
	// 0000:1294
	// 11223344
	// 11224433
	ESPstart := 16
	SPR := make([]byte, 4)
	SPR[1], SPR[0], SPR[3], SPR[2] = hexs[ESPstart+1], hexs[ESPstart], hexs[ESPstart+3], hexs[ESPstart+2]
	o.Esp = binary.LittleEndian.Uint32(SPR)
	// fmt.Printf("IS THIS WHAT YOU WANT? SPR = %x AND ESP = %x\n", SPR, o.Esp)

	o.Ebp = binary.LittleEndian.Uint32(hexs[20 : 20+4])
	o.Esi = binary.LittleEndian.Uint32(hexs[24 : 24+4])
	o.Edi = binary.LittleEndian.Uint32(hexs[28 : 28+4])
	o.Eip = binary.LittleEndian.Uint32(hexs[32 : 32+4])
	o.Eflags = binary.LittleEndian.Uint32(hexs[36 : 36+4])
	// o.Cs = binary.LittleEndian.Uint32(hexs[40 : 40+4])
	// o.Ss = binary.LittleEndian.Uint32(hexs[44 : 44+4])
	// o.Ds = binary.LittleEndian.Uint32(hexs[48 : 48+4])

	// comes in like
	// 00009412
	// should look like
	// 0000:1294
	// 11223344
	// 11224433

	CSR := make([]byte, 4)
	CSR[1], CSR[0], CSR[3], CSR[2] = hexs[45], hexs[44], hexs[42], hexs[43]

	SSR := make([]byte, 2)
	SSR[1], SSR[0] = hexs[45], hexs[44]

	DSR := make([]byte, 4)
	DSR[1], DSR[0], DSR[3], DSR[2] = hexs[53], hexs[52], hexs[50], hexs[51]

	o.Cs = binary.LittleEndian.Uint32(CSR[:])
	o.Ss = binary.LittleEndian.Uint16(SSR[:])
	o.Ds = binary.LittleEndian.Uint32(DSR[:])

	fmt.Printf("\nRAW REGS: %x\n\n", hexs)
	// fmt.Printf("HAHAH %x OR! %x\n", CSR)
	o.Dss = binary.LittleEndian.Uint16(hexs[48 : 48+2])
	o.Dss2 = binary.LittleEndian.Uint16(hexs[50 : 50+2])
	o.Es = binary.LittleEndian.Uint32(hexs[52 : 52+4])
	o.Ess = binary.LittleEndian.Uint16(hexs[52 : 52+2])
	o.Fs = binary.LittleEndian.Uint32(hexs[56 : 56+4])
	o.Gs = binary.LittleEndian.Uint32(hexs[60 : 60+4])

	return o, err
}

func (g *GDBConnection) Continue() {
	if !g.askedVcont {
		// fuck it, I'm going to assume it works
		g.checksumAndSend("vCont?")
		time.Sleep(time.Millisecond * 50)
		g.readAndChecksum()
		g.askedVcont = true
	}
	g.checksumAndSend("vCont;c")
	g.readAndChecksum()
}

func (g *GDBConnection) Step() {
	g.checksumAndSend("vCont;s")
	g.readAndChecksum()
}

func (g *GDBConnection) SetBreakpoint(address int, hardwareBreakpoint bool) error {
	hardwarebit := 1
	if hardwareBreakpoint != true {
		hardwarebit = 0
	}

	err := g.checksumAndSend(fmt.Sprintf("Z%d,%04x,1", hardwarebit, address))
	if err != nil {
		return err
	}

	_, err = g.readAndChecksum()
	if err != nil {
		return err
	}

	return nil
}

func (g *GDBConnection) GetMemory(address int, length int) (ram []byte, err error) {

	err = g.checksumAndSend(fmt.Sprintf("m%x,%d", address, length))
	if err != nil {
		return ram, err
	}

	rams, err := g.readAndChecksum()
	if err != nil {
		return ram, err
	}

	if len(rams)%2 == 1 {
		rams = rams + "0"
	}

	ram, err = hex.DecodeString(rams)

	return ram, err
}

func (g *GDBConnection) UnsetBreakpoint(address int, hardwareBreakpoint bool) error {
	hardwarebit := 1
	if hardwareBreakpoint != true {
		hardwarebit = 0
	}

	err := g.checksumAndSend(fmt.Sprintf("z%d,%04x,1", hardwarebit, address))
	if err != nil {
		return err
	}

	_, err = g.readAndChecksum()
	if err != nil {
		return err
	}

	return nil
}

var EremoteGDBerror = fmt.Errorf("The remove GDB stub was unable to decode message")

func (g *GDBConnection) checksumAndSend(msg string) error {
	cs := byte(0)
	for _, v := range []byte(msg) {
		cs += v
	}

	message := fmt.Sprintf("$%s#%02x", msg, cs)

	n, err := g.c.Write([]byte(message))
	if err != nil {
		return err
	}

	if n != len(message) {
		// Uh. fuck?
		panic("Window too full, not bothered to write this code yet.")
	}

	o := make([]byte, 1)
	_, err = g.c.Read(o)
	if err != nil {
		return err
	}

	if o[0] == byte('+') {
		return nil
	}
	return EremoteGDBerror
}

var EbadGDBresponce = fmt.Errorf("GDB Stub gave back an abnormal response")

func (g *GDBConnection) readAndChecksum() (string, error) {
	jumbobuffer := make([]byte, 0)

	mini := make([]byte, 1)
	g.c.Read(mini)

	if mini[0] == '+' {
		g.c.Read(mini)
	}

	if mini[0] != '$' {
		fmt.Printf("???????? %s ?????????/\n", string(mini))
		return string(mini), EbadGDBresponce
	}

	for {
		mini := make([]byte, 128000)
		n, err := g.c.Read(mini)
		if err != nil {
			return "", err
		}

		hashash := false
		hashpos := 0
		for k, v := range mini[:n] {
			if v == '#' {
				hashash = true
				hashpos = k
			}
		}

		if hashash {
			if hashpos == 0 {
				break
			}
			jumbobuffer = append(jumbobuffer, mini[:hashpos-1]...)
			break
		}
		jumbobuffer = append(jumbobuffer, mini...)
	}

	g.c.Write([]byte("+"))
	return string(jumbobuffer), nil
}
