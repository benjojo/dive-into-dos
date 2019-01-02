package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"crawshaw.io/sqlite"
	gdb "github.com/benjojo/dive-into-dos/remotegdb"
)

var (
	gendb  = flag.Bool("generatedb", false, "take a tar and produce a init database")
	dbpool *sqlite.Pool
)

func main() {
	flag.Parse()

	if *gendb {
		makeDB()
		return
	}

	var err error
	dbpool, err = sqlite.Open("file:data.db", 0, 10)
	if err != nil {
		log.Fatalf("Unable to open SQLliteDB %s", err)
	}

	http.HandleFunc("/newjob", handleNewJob)
	http.HandleFunc("/jobdone", handleJobDone)
	http.HandleFunc("/addsidejob", handleSideJob)
	http.HandleFunc("/getsidejob", fetchSideJob)
	http.HandleFunc("/sidejobdone", logSideJob)
	http.ListenAndServe(":9998", http.DefaultServeMux)
}

type SideJob struct {
	DateBased                           bool
	Day, Month, Year, Hour, Min, Second int
	TimeBased                           bool
	OriginalID                          int
	SideJobID                           int
}

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

func fetchSideJob(rw http.ResponseWriter, req *http.Request) {
	conn := dbpool.Get(req.Context().Done())
	if conn == nil {
		log.Printf("nil connection")
		return
	}
	defer dbpool.Put(conn)

	JD := JobData{}

	stmt, err := conn.Prepare("SELECT subtask_id,sample_id,state FROM subtasks WHERE evaluated = 0 LIMIT 1")
	if err != nil {
		Error(rw, err)
		return
	}
	uniqLock.Lock()
	defer uniqLock.Unlock()
	SID := int64(0)
	for {
		hasRow, err := stmt.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}

		JD.HasSideJob = true

		subState := stmt.GetText("state")
		SJ := SideJob{}
		json.Unmarshal([]byte(subState), &SJ)
		JD.SideJob = SJ
		JD.SideJob.SideJobID = int(stmt.GetInt64("subtask_id"))
		JD.SideJob.OriginalID = int(stmt.GetInt64("sample_id"))

	}

	stmt2, err := conn.Prepare("SELECT sample_id,filename,filetype,samplebinary FROM samples WHERE sample_id = $SID LIMIT 1")
	if err != nil {
		Error(rw, err)
		return
	}

	stmt2.SetInt64("$SID", int64(JD.SideJob.OriginalID))

	for {
		hasRow, err := stmt2.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}
		SID = stmt2.GetInt64("sample_id")
		JD.ID = int(SID)
		JD.JobName = stmt2.GetText("filename")
		Ftype := stmt2.GetText("filetype")
		if strings.Contains(Ftype, "MS-DOS executable") {
			JD.Binary.Type = "MZ"
		} else {
			JD.Binary.Type = "COM"
		}

		sample := make([]byte, 512*1024)

		n := stmt2.GetBytes("samplebinary", sample)

		JD.Binary.Data = base64.StdEncoding.EncodeToString(sample[:n])
		break
	}
	stmt2.Finalize()

	stmt2, err = conn.Prepare("UPDATE subtasks SET evaluated = 1 WHERE subtask_id = $sid")
	if err != nil {
		Error(rw, err)
		return
	}
	stmt2.SetInt64("$sid", int64(JD.SideJob.SideJobID))
	_, err = stmt2.Step()
	if err != nil {
		Error(rw, err)
		return
	}
	err = stmt2.Finalize()
	if err != nil {
		Error(rw, err)
		return
	}

	b, _ := json.Marshal(JD)
	rw.Write(b)

	return
}

func handleSideJob(rw http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		Error(rw, err)
		return
	}

	SJ := SideJob{}
	err = json.Unmarshal(data, &SJ)
	if err != nil {
		Error(rw, err)
		return
	}

	if SJ.OriginalID == 0 {
		log.Printf("Invalid data, 0121")
		return
	}

	// ok we have the data, so let's store the sub-task

	conn := dbpool.Get(req.Context().Done())
	if conn == nil {
		log.Printf("nil connection")
		return
	}
	defer dbpool.Put(conn)

	/*
		CREATE TABLE subtasks (
			subtask_id integer PRIMARY KEY AUTOINCREMENT,
			sample_id integer,
			evaluated integer,
			flv BLOB,
			floppydisk BLOB,
			state BLOB,
			syscalls BLOB
		   );

	*/
	stmt, err := conn.Prepare("INSERT INTO subtasks (sample_id,state,evaluated) VALUES ($sid, $state, 0);")
	if err != nil {
		Error(rw, err)
		return
	}
	stmt.SetInt64("$sid", int64(SJ.OriginalID))
	stmt.SetBytes("$state", data)

	_, err = stmt.Step()
	if err != nil {
		Error(rw, err)
		return
	}
	err = stmt.Finalize()
	if err != nil {
		Error(rw, err)
		return
	}

	return
}

var uniqLock sync.Mutex

func handleNewJob(rw http.ResponseWriter, req *http.Request) {
	conn := dbpool.Get(req.Context().Done())
	if conn == nil {
		log.Printf("nil connection")
		return
	}
	defer dbpool.Put(conn)

	JD := JobData{}

	stmt, err := conn.Prepare("SELECT sample_id,filename,filetype,samplebinary FROM samples WHERE evaluated = 0 LIMIT 1")
	if err != nil {
		Error(rw, err)
		return
	}
	uniqLock.Lock()
	defer uniqLock.Unlock()

	SID := int64(0)
	for {
		hasRow, err := stmt.Step()
		if err != nil {
			Error(rw, err)
			return
		} else if !hasRow {
			log.Print("uh")
			break
		}
		SID = stmt.GetInt64("sample_id")
		JD.ID = int(SID)
		JD.JobName = stmt.GetText("filename")
		Ftype := stmt.GetText("filetype")
		if strings.Contains(Ftype, "MS-DOS executable") {
			JD.Binary.Type = "MZ"
		} else {
			JD.Binary.Type = "COM"
		}

		sample := make([]byte, 512*1024)

		n := stmt.GetBytes("samplebinary", sample)

		JD.Binary.Data = base64.StdEncoding.EncodeToString(sample[:n])
		break
	}
	stmt.Finalize()

	stmt, err = conn.Prepare("UPDATE samples SET evaluated = 1 WHERE sample_id = $sid")
	if err != nil {
		Error(rw, err)
		return
	}
	stmt.SetInt64("$sid", SID)
	_, err = stmt.Step()
	if err != nil {
		Error(rw, err)
		return
	}
	err = stmt.Finalize()
	if err != nil {
		Error(rw, err)
		return
	}

	b, _ := json.Marshal(JD)
	rw.Write(b)

}

func Error(rw http.ResponseWriter, err error) {
	log.Printf("ERR: %s ", err.Error())
	http.Error(rw, err.Error(), http.StatusInternalServerError)
}

type dosSyscall struct {
	Time             time.Time
	Opcode           uint8
	Registers        gdb.X86Registers
	DS, PostCode     []byte
	Marker           int
	PostCodeLocation int
}

type JobFeedback struct {
	DoneAt       time.Time
	FLV          []byte
	FloppyDisk   []byte
	Syscalls     []dosSyscall
	RequestedJob JobData
}

func logSideJob(rw http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		Error(rw, err)
		return
	}

	JF := JobFeedback{}

	log.Printf("wtf %s", string(data))

	err = json.Unmarshal(data, &JF)
	if err != nil {
		Error(rw, err)
		return
	}

	conn := dbpool.Get(req.Context().Done())
	if conn == nil {
		log.Printf("nil connection")
		return
	}
	defer dbpool.Put(conn)

	/*
		CREATE TABLE subtasks (
			subtask_id integer PRIMARY KEY AUTOINCREMENT,
			sample_id integer,
			evaluated integer,
			flv BLOB,
			floppydisk BLOB,
			state BLOB,
			syscalls BLOB
		   );

	*/

	stmt, err := conn.Prepare("UPDATE subtasks SET flv = $flv, floppydisk = $floppy, syscalls = $syscalls, evaluated = 2 WHERE subtask_id = $sid")
	if err != nil {
		Error(rw, err)
		return
	}
	stmt.SetInt64("$sid", int64(JF.RequestedJob.SideJob.SideJobID))

	stmt.SetBytes("$flv", JF.FLV)
	stmt.SetBytes("$floppy", JF.FloppyDisk)
	JFSys, _ := json.Marshal(JF.Syscalls)
	stmt.SetBytes("$syscalls", JFSys)
	_, err = stmt.Step()
	if err != nil {
		Error(rw, err)
		return
	}
	err = stmt.Finalize()
	if err != nil {
		Error(rw, err)
		return
	}

}

func handleJobDone(rw http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		Error(rw, err)
		return
	}

	JF := JobFeedback{}

	log.Printf("wtf %s", string(data))

	err = json.Unmarshal(data, &JF)
	if err != nil {
		Error(rw, err)
		return
	}

	conn := dbpool.Get(req.Context().Done())
	if conn == nil {
		log.Printf("nil connection")
		return
	}
	defer dbpool.Put(conn)

	stmt, err := conn.Prepare("UPDATE samples SET flv = $flv, floppydisk = $floppy, syscalls = $syscalls, evaluated = 2 WHERE sample_id = $sid")
	if err != nil {
		Error(rw, err)
		return
	}
	stmt.SetInt64("$sid", int64(JF.RequestedJob.ID))

	stmt.SetBytes("$flv", JF.FLV)
	stmt.SetBytes("$floppy", JF.FloppyDisk)
	JFSys, _ := json.Marshal(JF.Syscalls)
	stmt.SetBytes("$syscalls", JFSys)
	_, err = stmt.Step()
	if err != nil {
		Error(rw, err)
		return
	}
	err = stmt.Finalize()
	if err != nil {
		Error(rw, err)
		return
	}

}
