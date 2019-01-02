package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	sidejobEnabled := flag.Bool("sidejobs", false, "Should I look for side jobs instead")

	flag.Parse()
	fmt.Print("Loading data...\n")

	// Steps:
	// [+] Obtain Manifest
	job, err := getJob(*sidejobEnabled)
	if err != nil {
		log.Fatalf("Unable to fetch job, %s", err.Error())
	}
	log.Print("[+] Obtained Manifest")

	// [+] Make floppy disk image + Hard Disk
	filename := "test.com"
	if job.Binary.Type == "MZ" {
		filename = "test.exe"
	}

	hddimage, fddimage := makeDisk(job.Binary.Data, filename)
	log.Print("[+] Make floppy disk image + Hard Disk")

	// [+] Start QEMU in Stopped GDB mode and monitor mode set to stdin
	vncport, gdbsocketpath, monitorsocketpath, qemuProcess, err := startQEMU(hddimage, fddimage)
	if err != nil {
		log.Fatalf("Unable to start qemu ! %q", err.Error())
	}
	log.Print("[+] Start QEMU in Stopped GDB mode + Monitor + VNC")

	// [+] Check boot every second for complete
	time.Sleep(time.Second * 6)

	// [+] Send keys to change drive, type in exec name
	log.Print("[+] Send keys to change drive, type in exec name")

	if *sidejobEnabled {
		log.Print("[+] Typing in date")

		if job.SideJob.DateBased {
			qemuSendKeys("d", monitorsocketpath)
			qemuSendKeys("a", monitorsocketpath)
			qemuSendKeys("t", monitorsocketpath)
			qemuSendKeys("e", monitorsocketpath)
			qemuSendKeys("kp_enter", monitorsocketpath)
			time.Sleep(time.Millisecond * 200)

			datestr := fmt.Sprintf("%02d-%02d-%d", job.SideJob.Month, job.SideJob.Day, job.SideJob.Year)

			for _, v := range []byte(datestr) {
				switch v {
				case '0':
					qemuSendKeys("0", monitorsocketpath)
				case '1':
					qemuSendKeys("1", monitorsocketpath)
				case '2':
					qemuSendKeys("2", monitorsocketpath)
				case '3':
					qemuSendKeys("3", monitorsocketpath)
				case '4':
					qemuSendKeys("4", monitorsocketpath)
				case '5':
					qemuSendKeys("5", monitorsocketpath)
				case '6':
					qemuSendKeys("6", monitorsocketpath)
				case '7':
					qemuSendKeys("7", monitorsocketpath)
				case '8':
					qemuSendKeys("8", monitorsocketpath)
				case '9':
					qemuSendKeys("9", monitorsocketpath)
				case '-':
					qemuSendKeys("minus", monitorsocketpath)
				}
			}

			qemuSendKeys("kp_enter", monitorsocketpath)
			time.Sleep(time.Millisecond * 200)

		}

		// Can't and won't always be correct, but we can try
		if job.SideJob.TimeBased {
			qemuSendKeys("t", monitorsocketpath)
			qemuSendKeys("i", monitorsocketpath)
			qemuSendKeys("m", monitorsocketpath)
			qemuSendKeys("e", monitorsocketpath)
			qemuSendKeys("kp_enter", monitorsocketpath)
			time.Sleep(time.Millisecond * 200)

			timestr := fmt.Sprintf("%02d:%02d:%02d.0", job.SideJob.Hour, job.SideJob.Min, job.SideJob.Second)

			for _, v := range []byte(timestr) {
				switch v {
				case '0':
					qemuSendKeys("0", monitorsocketpath)
				case '1':
					qemuSendKeys("1", monitorsocketpath)
				case '2':
					qemuSendKeys("2", monitorsocketpath)
				case '3':
					qemuSendKeys("3", monitorsocketpath)
				case '4':
					qemuSendKeys("4", monitorsocketpath)
				case '5':
					qemuSendKeys("5", monitorsocketpath)
				case '6':
					qemuSendKeys("6", monitorsocketpath)
				case '7':
					qemuSendKeys("7", monitorsocketpath)
				case '8':
					qemuSendKeys("8", monitorsocketpath)
				case '9':
					qemuSendKeys("9", monitorsocketpath)
				case ':':
					qemuSendKeys("shift-semicolon", monitorsocketpath)
				case '.':
					qemuSendKeys("dot", monitorsocketpath)
				}
			}

			qemuSendKeys("kp_enter", monitorsocketpath)
			time.Sleep(time.Millisecond * 200)
			log.Print("[+] Typing in binary path")

		}
	}

	qemuSendKeys("a", monitorsocketpath)
	qemuSendKeys("shift-semicolon", monitorsocketpath)
	qemuSendKeys("kp_enter", monitorsocketpath)
	time.Sleep(time.Millisecond * 200)
	qemuSendKeys("t", monitorsocketpath)
	qemuSendKeys("e", monitorsocketpath)
	qemuSendKeys("s", monitorsocketpath)
	qemuSendKeys("t", monitorsocketpath)
	qemuSendKeys("dot", monitorsocketpath)
	if job.Binary.Type == "MZ" {
		qemuSendKeys("e", monitorsocketpath)
		qemuSendKeys("x", monitorsocketpath)
		qemuSendKeys("e", monitorsocketpath)
	} else {
		qemuSendKeys("c", monitorsocketpath)
		qemuSendKeys("o", monitorsocketpath)
		qemuSendKeys("m", monitorsocketpath)
	}
	// qemuSendKeys("p", monitorsocketpath)
	// qemuSendKeys("a", monitorsocketpath)
	// qemuSendKeys("h", monitorsocketpath)
	// qemuSendKeys("dot", monitorsocketpath)
	// qemuSendKeys("c", monitorsocketpath)
	// qemuSendKeys("o", monitorsocketpath)
	// qemuSendKeys("m", monitorsocketpath)

	// [+] Install trace handle breakpoint
	log.Print("[+] Install trace handle breakpoint")

	gdbtracer := startTraceMSDOS(gdbsocketpath)

	// [+] Start VNC recorder
	log.Print("[+] Start VNC recorder")

	vncr := startVNCRecording(vncport)
	// [+] Send enter
	log.Print("[+] Send enter")

	qemuSendKeys("kp_enter", monitorsocketpath)

	// [+] Wait 15 seconds
	log.Print("[+] Wait 15 seconds")

	time.Sleep(time.Second * 15)

	if gdbtracer.didCommandFinish() {
		log.Print("[+] Marking and then trying to run a few short commands to test infections")

		gdbtracer.SetMarker()
		qemuSendKeys("p", monitorsocketpath)
		qemuSendKeys("r", monitorsocketpath)
		qemuSendKeys("i", monitorsocketpath)
		qemuSendKeys("n", monitorsocketpath)
		qemuSendKeys("t", monitorsocketpath)
		qemuSendKeys("dot", monitorsocketpath)
		qemuSendKeys("c", monitorsocketpath)
		qemuSendKeys("o", monitorsocketpath)
		qemuSendKeys("m", monitorsocketpath)
		gdbtracer.SetMarker()
		qemuSendKeys("kp_enter", monitorsocketpath)

		log.Print("[+] Send enter")
		time.Sleep(time.Second * 2)
	}

	// [+] Stop recorder
	log.Print("[+] Stop recorder")

	vncrecFN := vncr.stop()
	syscalls := gdbtracer.Actions

	// [+] Stop QEMU
	log.Print("[+] Stop QEMU")

	gdbtracer.SetMarker() // TEMP: REMOVE ASAP
	gdbtracer.Stop()
	qemuProcess.Process.Kill()
	qemuProcess.Wait()

	// [+] Check floppy for changes
	log.Print("[+] Check floppy for changes")
	var diskimg []byte
	if areDisksDifferent(fddimage, "./base.fdd") {
		diskimg = compressDisk(fddimage)
	}

	// [+] Send (Recording + Diff binarys + GDB Trace log)
	log.Print("[+] Send (Recording + Diff binarys + GDB Trace log)")
	err = SubmitJob(vncrecFN, diskimg, syscalls, *job)
	if err != nil {
		log.Printf("[-] Failed to send, %s", err.Error())
	}

	os.Remove(monitorsocketpath)
	os.Remove(gdbsocketpath)
	os.Remove(hddimage)
	os.Remove(fddimage)
	os.Remove(vncrecFN)

	// log.Printf("VNC: %s \n syscalls: %+v", vncrecFN, syscalls)
}
