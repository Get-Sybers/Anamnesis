package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"flashback/internal/car"
	"flashback/internal/carmodel"
	"flashback/internal/enrich"
	"flashback/internal/normalize"
	"flashback/internal/store"
	"flashback/internal/timeline"
	"flashback/internal/value"
)

func tag(ev car.Event) car.Event { ev["source_image"] = "img.mem"; return ev }

func procRec(pid, ppid, offset int, name, path, ts string) car.Event {
	return tag(normalize.Normalize("windows.piiat.processes", car.Record{
		"Offset": offset, "Guid": fmt.Sprintf("proc-%x", offset), "PID": pid, "PPID": ppid,
		"ImageFileName": name, "Path": path, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": ts, "DllCount": 0,
		"LoadedDlls": nil, "Hidden": false}))
}

func s(ev car.Event, k string) string { return value.Str(ev[k]) }

func writeJSONL(t *testing.T, path string, recs []car.Record) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, r := range recs {
		b, _ := json.Marshal(r)
		f.Write(b)
		f.WriteString("\n")
	}
}

func TestStoreAndOutputs(t *testing.T) {
	dir := t.TempDir()
	p := procRec(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00")
	f := tag(normalize.Normalize("windows.filescan", car.Record{"Offset": 3, "Name": `\x\y.txt`}))
	th := tag(normalize.Normalize("windows.thrdscan", car.Record{
		"Offset": 9, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
	events := enrich.Enrich([]car.Event{p, f, th})

	st, err := store.Open(filepath.Join(dir, "car.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, _ := st.InsertEvents(events); n != 3 {
		t.Fatalf("inserted %d, want 3", n)
	}
	st.InsertContext("img.mem", "windows.info", []car.Record{{"Variable": "Is64Bit", "Value": "True"}})

	counts, _ := st.Counts()
	if counts["process"] != 1 || counts["file"] != 1 || counts["thread"] != 1 || len(counts) != 3 {
		t.Fatalf("counts = %v", counts)
	}
	tl, _ := st.IterTimeline()
	if len(tl) != 2 || s(tl[0], "car_object") != "process" || s(tl[1], "car_object") != "thread" {
		t.Fatalf("timeline objects = %v", objs(tl))
	}

	tlPath := filepath.Join(dir, "timeline.json")
	n, err := timeline.WriteTimelineJSON(st, tlPath, "")
	if err != nil || n != 2 {
		t.Fatalf("write timeline n=%d err=%v", n, err)
	}
	rows := readJSONL(t, tlPath)
	superset := carmodel.AllFields()
	for _, row := range rows {
		for _, k := range []string{"timestamp", "car_object", "car_action", "guid"} {
			if _, ok := row[k]; !ok {
				t.Errorf("timeline row missing meta %q", k)
			}
		}
		for _, fld := range superset {
			if _, ok := row[fld]; !ok {
				t.Errorf("timeline row missing superset field %q", fld)
			}
		}
	}
	if s(rows[0], "car_object") != "process" || s(rows[1], "car_object") != "thread" {
		t.Errorf("row objects = %v/%v", rows[0]["car_object"], rows[1]["car_object"])
	}
	if s(rows[1], "owning_guid") != "proc-a" {
		t.Errorf("thread owning_guid = %v", rows[1]["owning_guid"])
	}

	written, err := timeline.WriteObjectCSVs(st, filepath.Join(dir, "car"))
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 3 || written["process"] != 1 {
		t.Errorf("csvs written = %v", written)
	}
	head := csvHeader(t, filepath.Join(dir, "car", "process.csv"))
	if !head["command_line"] || !head["guid"] || head["car_object"] {
		t.Errorf("process.csv header = %v", head)
	}
}

func TestSupersededBuiltinJSONLSkipped(t *testing.T) {
	dir := t.TempDir()
	plug := filepath.Join(dir, "plugins")
	os.MkdirAll(plug, 0o755)
	writeJSONL(t, filepath.Join(plug, "windows.sessions.jsonl"), []car.Record{{
		"Session ID": 1, "User Name": `HOST\Steve`, "Process ID": 10,
		"Process": "x.exe", "Create Time": "2019-01-28T19:40:32+00:00"}})
	writeJSONL(t, filepath.Join(plug, "windows.piiat.sessions.jsonl"), []car.Record{{
		"OwnerOffset": 10, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
		"LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
		"CreateTime": "2019-01-28T19:40:32+00:00"}})
	st, err := BuildStore(dir, "img.mem")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	counts, _ := st.Counts()
	if counts["user_session"] != 1 {
		t.Fatalf("user_session count = %d, want 1 (no double-counted logon)", counts["user_session"])
	}
	rows, _ := st.IterObject("user_session")
	if s(rows[0], "login_id") != "0x338f0" {
		t.Errorf("login_id = %v (LUID identity should win)", rows[0]["login_id"])
	}
}

func TestMalfindOverlayRetrievesStoredProcess(t *testing.T) {
	dir := t.TempDir()
	plug := filepath.Join(dir, "plugins")
	os.MkdirAll(plug, 0o755)
	writeJSONL(t, filepath.Join(plug, "windows.piiat.processes.jsonl"), []car.Record{{
		"Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
		"ImageFileName": "MsMpEng.exe", "Path": `C:\W\MsMpEng.exe`, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": "2020-01-01T00:00:10+00:00", "DllCount": 0,
		"LoadedDlls": nil, "Hidden": false, "Sid": nil, "User": nil, "LogonId": nil,
		"Cwd": nil, "IntegrityLevel": nil, "EnvVars": nil}})
	writeJSONL(t, filepath.Join(plug, "windows.malfind.jsonl"), []car.Record{{
		"PID": 10, "Process": "MsMpEng.exe", "Start VPN": 0x1a0000, "End VPN": 0x1a0fff,
		"Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS", "CommitCharge": 1,
		"PrivateMemory": 1, "Disasm": "56 57", "Hexdump": "56 57"}})
	st, err := BuildStore(dir, "img.mem")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	counts, _ := st.Counts()
	if _, ok := counts["module"]; ok {
		t.Error("malfind must not be persisted as a module row")
	}

	ov := timeline.MalfindOverlay(st, dir)
	if len(ov) != 1 {
		t.Fatalf("overlay len = %d, want 1", len(ov))
	}
	e := ov[0]
	if s(e, "car_object") != "module" || s(e, "car_action") != "load" || s(e, "owning_guid") != "proc-a" {
		t.Errorf("overlay meta = %#v", e)
	}
	if s(e, "image_path") != `C:\W\MsMpEng.exe` || s(e, "timestamp") != "2020-01-01T00:00:10+00:00" {
		t.Errorf("overlay retrieved fields = %v / %v", e["image_path"], e["timestamp"])
	}
	if ba, _ := value.Int(e["base_address"]); ba != 0x1a0000 {
		t.Errorf("base_address = %v", e["base_address"])
	}
	nat := e["_native"].(map[string]any)
	if nat["Protection"] != "PAGE_EXECUTE_READWRITE" {
		t.Errorf("native Protection = %v", nat["Protection"])
	}

	tlPath := filepath.Join(dir, "timeline.json")
	timeline.WriteTimelineJSON(st, tlPath, dir)
	mf := 0
	for _, r := range readJSONL(t, tlPath) {
		if s(r, "source_plugin") == "windows.malfind" {
			mf++
			if s(r, "owning_guid") != "proc-a" {
				t.Errorf("timelined malfind owning_guid = %v", r["owning_guid"])
			}
		}
	}
	if mf != 1 {
		t.Errorf("timelined malfind rows = %d, want 1", mf)
	}
}

// ---- helpers ----

func objs(evs []car.Event) []string {
	var o []string
	for _, e := range evs {
		o = append(o, s(e, "car_object"))
	}
	return o
}

func readJSONL(t *testing.T, path string) []car.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []car.Event
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var m car.Event
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("bad timeline line: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func csvHeader(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(b)
	if len(lines) == 0 {
		return nil
	}
	h := map[string]bool{}
	for _, col := range splitCSV(string(lines[0])) {
		h[col] = true
	}
	return h
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			out = append(out, cur)
			cur = ""
		} else if c != '\r' {
			cur += string(c)
		}
	}
	out = append(out, cur)
	return out
}
