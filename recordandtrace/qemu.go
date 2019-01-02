package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

func startQEMU(hda, fdd string) (VNCPort int, GDBSocket string, monitor string, qemu *exec.Cmd, err error) {
	VNCPort = freePort()
	GDBSocket = fmt.Sprintf("./gdbsocket-%d.socket", time.Now().UnixNano())
	monitor = fmt.Sprintf("./monitor-%d.socket", time.Now().UnixNano())

	qemuS := exec.Command("/usr/bin/qemu-system-x86_64", "-hda", hda,
		"-s", "-m", "1", "-fda", fdd,
		"-vnc", fmt.Sprintf(":%d", VNCPort-9000),
		"-chardev", fmt.Sprintf("socket,id=gdbs,path=%s,server,nowait", GDBSocket),
		"-gdb", "chardev:gdbs",
		"-chardev", fmt.Sprintf("socket,id=monitor,path=%s,server,nowait", monitor),
		"-monitor", "chardev:monitor")

	qemuS.Stderr = os.Stderr
	go qemuS.Run()
	return VNCPort, GDBSocket, monitor, qemuS, err
}

func freePort() int {
	for {
		addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")
		l, _ := net.ListenTCP("tcp", addr)
		defer l.Close()
		if l.Addr().(*net.TCPAddr).Port < 9005 {
			continue
		}

		return l.Addr().(*net.TCPAddr).Port
	}

}

func qemuSendKeys(key string, socket string) {
	c, err := net.Dial("unix", socket)

	if err != nil {
		log.Fatalf("Unable to send key, becuase socket does not work %s", err.Error())
	}

	dummy := make([]byte, 1000)
	// n, _ := c.Read(dummy)
	c.Read(dummy)
	// fmt.Print("A" + string(dummy[:n]))
	c.Write([]byte("\n"))
	dummy = make([]byte, 1000)
	// n, _ = c.Read(dummy)
	c.Read(dummy)

	// fmt.Print("B" + string(dummy[:n]))

	time.Sleep(time.Millisecond * 100)

	c.Write([]byte(fmt.Sprintf("\nsendkey %s\n", key)))
	dummy = make([]byte, 1000)
	// fmt.Print("C" + string(dummy[:n]))
	// n, _ = c.Read(dummy)
	c.Read(dummy)

	time.Sleep(time.Millisecond * 50)

	c.Close()
}
