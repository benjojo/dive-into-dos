package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

/*
{
	"ID": "abc123",
	"JobName": "Virus.DOS.Techo",
	"Binary": {
		"Type": "MZ",
		"Data": "abcd"
	}
}
*/

type JobData struct {
	Binary struct {
		Data string `json:"Data"`
		Type string `json:"Type"`
	} `json:"Binary"`
	ID         int    `json:"ID"`
	JobName    string `json:"JobName"`
	HasSideJob bool
	SideJob    SideJob `json:"SideJob"`
}

type SideJob struct {
	DateBased                           bool
	Day, Month, Year, Hour, Min, Second int
	TimeBased                           bool
	OriginalID                          int
	SideJobID                           int
}

type JobFeedback struct {
	DoneAt       time.Time
	FLV          []byte
	FloppyDisk   []byte
	Syscalls     []dosSyscall
	RequestedJob JobData
}

var (
	jobserver = flag.String("jobserver", "", "Job server IP to fetch a job from")
)

func getJob(sidejob bool) (j *JobData, err error) {
	jj := JobData{}
	var jobdata []byte
	if *jobserver != "" {

		url := fmt.Sprintf("%s/newjob", *jobserver)

		if sidejob {
			url = fmt.Sprintf("%s/getsidejob", *jobserver)
		}

		resp, err :=
			http.Get(url)

		if err != nil {
			return j, err
		}

		jobdata, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return j, err
		}
	} else {
		jobdata, err = ioutil.ReadFile("./job.json")
		if err != nil {
			return j, err
		}
	}

	err = json.Unmarshal(jobdata, &jj)
	fmt.Printf("[+] Got job: %s\n", jj.JobName)
	return &jj, err
}

func SubmitJob(flvpath string, fddimage []byte, syscalls []dosSyscall, OJob JobData) error {
	JF := JobFeedback{
		DoneAt: time.Now(),
	}

	JF.FloppyDisk = fddimage

	JF.Syscalls = syscalls

	b, _ := ioutil.ReadFile(flvpath)
	JF.FLV = b
	JF.RequestedJob = OJob

	jsonbytes, _ := json.Marshal(JF)

	if *jobserver != "" {
		buf := bytes.NewReader(jsonbytes)
		url := fmt.Sprintf("%s/jobdone", *jobserver)

		if OJob.HasSideJob {
			url = fmt.Sprintf("%s/sidejobdone", *jobserver)
		}
		_, err := http.Post(url, "application/json", buf)
		return err

	} else {
		fmt.Print(string(jsonbytes))
	}

	return nil
}
