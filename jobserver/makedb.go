package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"crawshaw.io/sqlite"
)

func makeDB() {
	pool, err := sqlite.Open("file:data.db", 0, 10)
	if err != nil {
		log.Fatalf("unable make database! %s", err.Error())
	}

	// hmm, now we open the tar file.
	fd, err := os.Open("data.tar")
	if err != nil {
		log.Fatalf("unable open tar! %s", err.Error())
	}

	rdtar := tar.NewReader(fd)

	conn := pool.Get(nil)
	if conn == nil {
		return
	}

	stmt, _, err := conn.PrepareTransient(`CREATE TABLE samples (
		sample_id integer PRIMARY KEY AUTOINCREMENT,
		filename text NOT NULL,
		filetype text NOT NULL,
		samplebinary BLOB NOT NULL,
		evaluated integer,
		givenout integer,
		flv BLOB,
		floppydisk BLOB,
		syscalls BLOB
	   );`)
	if err != nil {
		log.Fatalf("Table setup error 1 %s", err.Error())
	}

	_, err = stmt.Step()
	if err != nil {
		log.Fatalf("Table setup error 2 %s", err.Error())
	}

	if err := stmt.Finalize(); err != nil {
		log.Fatalf("Table setup error 3 %s", err.Error())
	}
	conn.Close()
	conn = pool.Get(nil)
	if conn == nil {
		return
	}

	rdtar.Next()
	for {
		stmt, err = conn.Prepare(
			"INSERT INTO samples (filename, filetype, samplebinary) VALUES ($filename, $filetype, $sample);")

		if err != nil {
			log.Fatalf("Insert setup error %s", err.Error())
		}

		header, err := rdtar.Next()
		if err != nil {
			log.Printf("done? %s", err.Error())
			break
		}
		samplebin := make([]byte, 500*1024)
		n, _ := rdtar.Read(samplebin)

		stmt.SetBytes("$sample", samplebin[:n])
		stmt.SetText("$filename", header.Name)
		stmt.SetText("$filetype", getMagic(samplebin[:n]))
		_, err = stmt.Step()
		if err != nil {
			log.Printf("Insert error %s", err.Error())
		}
		stmt.Finalize()
		fmt.Print(".")
	}
	conn.Close()
	pool.Close()
	// defer pool.Put(conn)
}

func getMagic(data []byte) string {
	filecmd := exec.Command("/usr/bin/file", "-")

	stdi, _ := filecmd.StdinPipe()

	if filecmd.Stdout != nil {
		return ""
	}
	if filecmd.Stderr != nil {
		return ""
	}
	var b bytes.Buffer
	filecmd.Stdout = &b
	filecmd.Stderr = &b
	filecmd.Start()

	stdi.Write(data)
	stdi.Close()
	filecmd.Wait()

	output := b.Bytes()
	os := string(output)
	if strings.Contains(os, "/dev/stdin:") {
		return strings.Split(os, ":")[1]
	}
	return ""
}

// filename text NOT NULL,
// filetype text NOT NULL,
// samplebinary BLOB NOT NULL,
