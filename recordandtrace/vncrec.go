package main

import (
	"crypto/rand"
	"fmt"
	"os/exec"
)

type vncRecorder struct {
	p        *exec.Cmd
	filename string
}

func startVNCRecording(vncport int) *vncRecorder {
	r := vncRecorder{}
	r.filename = fmt.Sprintf("%s.flv", randString(10))
	r.p = exec.Command("flvrec.py",
		"-o", r.filename, fmt.Sprintf("localhost:%d", vncport-9000))
	go r.p.Start()
	// if err != nil {
	// 	log.Fatalf("Unable to start VNC recorder %s", err.Error())
	// }
	return &r
}

func (v *vncRecorder) stop() string {
	v.p.Process.Kill()
	v.p.Wait()
	return v.filename
}

func randString(n int) string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}
