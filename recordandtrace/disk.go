package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"
)

func makeDisk(malwarebase64, filename string) (hda, fdd string) {
	// First, Copy the base HDD image over to make a backup
	hda = fmt.Sprintf("./temphdd-%d.hda", time.Now().UnixNano())
	hdaFD, err := os.Create(hda)
	if err != nil {
		log.Fatalf("Failed to make init HDD | Create file %s", err)
	}

	basehdaFD, err := os.Open("./base.hda")
	if err != nil {
		log.Fatalf("Failed to make init HDD | Opening base file %s", err)
	}

	_, err = io.Copy(hdaFD, basehdaFD)
	if err != nil {
		log.Fatalf("Failed to make init HDD | copying file %s", err)
	}
	hdaFD.Close()
	basehdaFD.Close()

	// Now the Floppy disk
	floppyname := fmt.Sprintf("./tempfdd-%d.fdd", time.Now().UnixNano())
	fdd = floppyname
	fddFD, err := os.Create(floppyname)
	if err != nil {
		log.Fatalf("Failed to make init HDD | Create file %s", err)
	}

	basefddFD, err := os.Open("./base.fdd")
	if err != nil {
		log.Fatalf("Failed to make init HDD | Opening base file %s", err)
	}

	_, err = io.Copy(fddFD, basefddFD)
	if err != nil {
		log.Fatalf("Failed to make init HDD | copying file %s", err)
	}
	fddFD.Close()
	basefddFD.Close()

	// Write the malware to a temp file

	data, err := base64.StdEncoding.DecodeString(malwarebase64)
	if err != nil {
		log.Fatalf("Failed to decode malware base64 %s", err)
	}

	err = ioutil.WriteFile(filename, data, 0660)
	if err != nil {
		log.Fatalf("failed to write temp file %s", err)
	}

	// Now we need to put our sample on the floppy disk!

	fatboycmd := exec.Command("fatboy", floppyname, "add", filename)
	fatboycmd.Start()
	fatboycmd.Wait()

	// We should have the images in place now.
	os.Remove(filename)
	return hda, fdd
}

func areDisksDifferent(cleanpath, testpath string) bool {
	b1, _ := ioutil.ReadFile(cleanpath)
	b2, _ := ioutil.ReadFile(testpath)

	h1 := md5.Sum(b1)
	h2 := md5.Sum(b2)

	for i := 0; i < 15; i++ {
		if h1[i] != h2[i] {
			return true
		}
	}
	return false
}

func compressDisk(path string) []byte {
	b1, _ := ioutil.ReadFile(path)
	o := make([]byte, 0)
	buf := bytes.NewBuffer(o)
	gzr, _ := gzip.NewWriterLevel(buf, gzip.BestCompression)
	gzr.Write(b1)
	return buf.Bytes()
}
