package enrich

import (
	"fmt"
	"testing"

	"flashback/internal/car"
	"flashback/internal/carmodel"
	"flashback/internal/normalize"
	"flashback/internal/value"
)

// ---- helpers (mirror tests/test_car_pipeline.py) ---------------------------

func tag(ev car.Event) car.Event { ev["source_image"] = "img.mem"; return ev }

func proc(pid, ppid, offset int, name, path, ts string) car.Event {
	return normalize.Normalize("windows.piiat.processes", car.Record{
		"Offset": offset, "Guid": fmt.Sprintf("proc-%x", offset), "PID": pid, "PPID": ppid,
		"ImageFileName": name, "Path": path, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": ts, "DllCount": 0,
		"LoadedDlls": nil, "Hidden": false})
}

func s(ev car.Event, k string) string { return value.Str(ev[k]) }
func i(ev car.Event, k string) int64  { n, _ := value.Int(ev[k]); return n }

func byObj(evs []car.Event) map[string]car.Event {
	m := map[string]car.Event{}
	for _, e := range evs {
		o := value.Str(e["car_object"])
		if _, ok := m[o]; !ok {
			m[o] = e
		}
	}
	return m
}

func ofObj(evs []car.Event, obj string) []car.Event {
	var r []car.Event
	for _, e := range evs {
		if value.Str(e["car_object"]) == obj {
			r = append(r, e)
		}
	}
	return r
}

// ---- tests -----------------------------------------------------------------

func TestSpokeInheritsOwnerHeuristic(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	th := tag(normalize.Normalize("windows.thrdscan", car.Record{
		"Offset": 99, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
	out := Enrich([]car.Event{p, th})
	e := ofObj(out, "thread")[0]
	if s(e, "owning_guid") != "proc-a" || s(e, "link_confidence") != "heuristic" {
		t.Errorf("owning_guid=%v conf=%v", e["owning_guid"], e["link_confidence"])
	}
	if carmodel.FieldSet("thread")["image_path"] {
		t.Error("thread should not have image_path field")
	}
}

func TestPIDReuseDisambiguatedByCreateTimeWindow(t *testing.T) {
	old := tag(proc(10, 4, 0xa, "old.exe", `C:\old.exe`, "2020-01-01T00:00:10+00:00"))
	nw := tag(proc(10, 4, 0xb, "new.exe", `C:\new.exe`, "2020-01-01T09:00:00+00:00"))
	early := tag(normalize.Normalize("windows.thrdscan", car.Record{
		"Offset": 1, "PID": 10, "TID": 1, "CreateTime": "2020-01-01T00:30:00+00:00"}))
	late := tag(normalize.Normalize("windows.thrdscan", car.Record{
		"Offset": 2, "PID": 10, "TID": 2, "CreateTime": "2020-01-01T10:00:00+00:00"}))
	out := Enrich([]car.Event{old, nw, early, late})
	th := map[int64]car.Event{}
	for _, e := range ofObj(out, "thread") {
		th[i(e, "tgt_tid")] = e
	}
	if s(th[1], "owning_guid") != "proc-a" {
		t.Errorf("thread1 owner=%v want proc-a", th[1]["owning_guid"])
	}
	if s(th[2], "owning_guid") != "proc-b" {
		t.Errorf("thread2 owner=%v want proc-b", th[2]["owning_guid"])
	}
}

func TestParentLinkFillsOnlyNull(t *testing.T) {
	parent := tag(proc(4, 0, 0x1, "par.exe", `C:\par.exe`, "2020-01-01T00:00:01+00:00"))
	child := tag(proc(10, 4, 0x2, "kid.exe", `C:\kid.exe`, "2020-01-01T00:00:05+00:00"))
	out := Enrich([]car.Event{parent, child})
	var kid car.Event
	for _, e := range out {
		if i(e, "pid") == 10 {
			kid = e
		}
	}
	if s(kid, "parent_guid") != "proc-1" || s(kid, "parent_image_path") != `C:\par.exe` ||
		s(kid, "parent_exe") != "par.exe" || s(kid, "link_confidence") != "heuristic" {
		t.Errorf("kid=%#v", kid)
	}
}

func TestSessionRowsCollapseAndFeedProcessUser(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	s1 := tag(normalize.Normalize("windows.sessions", car.Record{
		"Session ID": 1, "User Name": `HOST\jake`, "Create Time": "2020-01-01T00:00:02+00:00",
		"Process ID": 10, "Process": "x.exe"}))
	s2 := tag(normalize.Normalize("windows.sessions", car.Record{
		"Session ID": 1, "User Name": `HOST\jake`, "Create Time": "2020-01-01T00:00:09+00:00",
		"Process ID": 11, "Process": "y.exe"}))
	out := Enrich([]car.Event{p, s1, s2})
	sessions := ofObj(out, "user_session")
	if len(sessions) != 1 {
		t.Fatalf("want 1 collapsed session, got %d", len(sessions))
	}
	if s(sessions[0], "timestamp") != "2020-01-01T00:00:02+00:00" {
		t.Errorf("session ts=%v (want earliest)", sessions[0]["timestamp"])
	}
	if s(ofObj(out, "process")[0], "user") != `HOST\jake` {
		t.Errorf("process user=%v", ofObj(out, "process")[0]["user"])
	}
}

func TestNativeValueNeverOverwritten(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	svc := tag(normalize.Normalize("windows.svcscan", car.Record{
		"Offset": 5, "Name": "svc", "Binary": `C:\svc.exe`, "PID": 10}))
	out := Enrich([]car.Event{p, svc})
	e := ofObj(out, "service")[0]
	if s(e, "image_path") != `C:\svc.exe` || s(e, "exe") != "svc.exe" || s(e, "owning_guid") != "proc-a" {
		t.Errorf("svc=%#v", e)
	}
}

func TestDedupeSocketAcrossPluginsDualstackSurvive(t *testing.T) {
	a := tag(normalize.Normalize("windows.netscan", car.Record{
		"Offset": 7, "Proto": "TCPv4", "LocalAddr": "1.1.1.1", "LocalPort": 1,
		"ForeignAddr": "2.2.2.2", "ForeignPort": 443, "State": "ESTABLISHED",
		"PID": 10, "Owner": nil, "Created": "2020-01-01T00:01:00+00:00"}))
	b := tag(normalize.Normalize("windows.netstat", car.Record{
		"Offset": 0xFFFF7000, "Proto": "TCPv4", "LocalAddr": "1.1.1.1", "LocalPort": 1,
		"ForeignAddr": "2.2.2.2", "ForeignPort": 443, "State": "ESTABLISHED",
		"PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:00+00:00"}))
	c := tag(normalize.Normalize("windows.netscan", car.Record{
		"Offset": 7, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 1,
		"ForeignAddr": "2001:db8::5", "ForeignPort": 443, "State": "ESTABLISHED",
		"PID": 10, "Owner": nil, "Created": "2020-01-01T00:01:00+00:00"}))
	out := Enrich([]car.Event{a, b, c})
	flows := ofObj(out, "flow")
	if len(flows) != 2 {
		t.Fatalf("want 2 flows (dedup v4 + distinct v6), got %d", len(flows))
	}
	for _, f := range flows {
		if s(f, "src_ip") == "1.1.1.1" && s(f, "exe") != "x.exe" {
			t.Errorf("v4 flow should keep most-populated exe, got %v", f["exe"])
		}
	}
}

func TestModuleImagePathInheritedFromOwner(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\dir\x.exe`, "2020-01-01T00:00:10+00:00"))
	m := tag(normalize.Normalize("windows.dlllist", car.Record{
		"PID": 10, "Process": "x.exe", "Base": 0x7ff0, "Name": "ntdll.dll",
		"Path": `C:\Windows\SYSTEM32\ntdll.dll`, "LoadTime": "2020-01-01T00:00:11+00:00"}))
	if m["image_path"] != nil {
		t.Errorf("module image_path should be null at normalize, got %v", m["image_path"])
	}
	out := Enrich([]car.Event{p, m})
	mod := ofObj(out, "module")[0]
	if s(mod, "image_path") != `C:\dir\x.exe` || s(mod, "owning_guid") != "proc-a" {
		t.Errorf("mod=%#v", mod)
	}
}

func TestRegistryUserFromSIDHiveViaProfileList(t *testing.T) {
	profile := tag(normalize.Normalize("windows.piiat.registry", car.Record{
		"Hive": `\SystemRoot\System32\Config\SOFTWARE`,
		"Key":  `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1474204758-2504895174-1356074821-1001`,
		"ValueName": "ProfileImagePath", "ValueData": `C:\Users\Steve`,
		"ValueType": "REG_EXPAND_SZ", "LastWrite": "2019-01-28"}))
	sidRow := tag(normalize.Normalize("windows.piiat.registry", car.Record{
		"Hive": `\REGISTRY\USER\S-1-5-21-1474204758-2504895174-1356074821-1001`,
		"Key":  `...\Software\Microsoft\Windows\CurrentVersion\Run`,
		"ValueName": "x", "ValueData": "y", "ValueType": "REG_SZ", "LastWrite": "2019-01-29"}))
	classes := tag(normalize.Normalize("windows.piiat.registry", car.Record{
		"Hive": `\REGISTRY\USER\S-1-5-21-1474204758-2504895174-1356074821-1001_Classes`,
		"Key":  `...\ms-settings\shell\open\command`, "ValueName": "",
		"ValueData": "cmd.exe", "ValueType": "REG_SZ", "LastWrite": "2019-01-29"}))
	if sidRow["user"] != nil {
		t.Errorf("sid hive user should be nil at normalize, got %v", sidRow["user"])
	}
	out := Enrich([]car.Event{profile, sidRow, classes})
	byKey := map[string]car.Event{}
	for _, e := range ofObj(out, "registry") {
		byKey[s(e, "key")] = e
	}
	if s(byKey[s(sidRow, "key")], "user") != "Steve" {
		t.Errorf("sid row user=%v want Steve", byKey[s(sidRow, "key")]["user"])
	}
	if s(byKey[s(classes, "key")], "user") != "Steve" {
		t.Errorf("classes row user=%v want Steve", byKey[s(classes, "key")]["user"])
	}
	if byKey[s(profile, "key")]["user"] != nil {
		t.Errorf("machine hive user should stay nil, got %v", byKey[s(profile, "key")]["user"])
	}
}

func TestMatchNeverLinksToLaterCreatedProcess(t *testing.T) {
	late := tag(proc(10, 4, 0xb, "late.exe", `C:\late.exe`, "2020-01-01T09:00:00+00:00"))
	earlyThread := tag(normalize.Normalize("windows.thrdscan", car.Record{
		"Offset": 1, "PID": 10, "TID": 1, "CreateTime": "2020-01-01T00:30:00+00:00"}))
	out := Enrich([]car.Event{late, earlyThread})
	e := ofObj(out, "thread")[0]
	if e["owning_guid"] != nil || e["link_confidence"] != nil {
		t.Errorf("thread should not link to a later process: %#v", e)
	}
}

func TestDistinctUsersSameSessionIDDoNotMerge(t *testing.T) {
	s1 := tag(normalize.Normalize("windows.sessions", car.Record{
		"Session ID": 1, "User Name": `HOST\alice`, "Create Time": "2020-01-01T00:00:02+00:00",
		"Process ID": 10, "Process": "x.exe"}))
	s2 := tag(normalize.Normalize("windows.sessions", car.Record{
		"Session ID": 1, "User Name": `HOST\bob`, "Create Time": "2020-01-01T00:00:05+00:00",
		"Process ID": 11, "Process": "y.exe"}))
	out := Enrich([]car.Event{s1, s2})
	if len(ofObj(out, "user_session")) != 2 {
		t.Errorf("distinct users same session id must not merge")
	}
}

func TestOwningOffsetLinksDefinitively(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	th := tag(normalize.Normalize("windows.piiat.threads", car.Record{
		"Offset": 99, "OwnerOffset": 0xa, "PID": 10, "TID": 7,
		"CreateTime": "2020-01-01T00:00:20+00:00",
		"StackBase": 1000, "StackLimit": 900, "UserStackBase": 2000, "UserStackLimit": 1900}))
	out := Enrich([]car.Event{p, th})
	e := ofObj(out, "thread")[0]
	if s(e, "owning_guid") != "proc-a" || s(e, "link_confidence") != "definitive" {
		t.Errorf("owner=%v conf=%v", e["owning_guid"], e["link_confidence"])
	}
	if i(e, "stack_base") != 1000 || i(e, "user_stack_limit") != 1900 {
		t.Errorf("stacks: %v %v", e["stack_base"], e["user_stack_limit"])
	}
}

func TestOwningOffsetMissFallsBackToPIDHeuristic(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	th := tag(normalize.Normalize("windows.piiat.threads", car.Record{
		"Offset": 99, "OwnerOffset": 0xdead, "PID": 10, "TID": 7,
		"CreateTime": "2020-01-01T00:00:20+00:00"}))
	out := Enrich([]car.Event{p, th})
	e := ofObj(out, "thread")[0]
	if s(e, "owning_guid") != "proc-a" || s(e, "link_confidence") != "heuristic" {
		t.Errorf("owner=%v conf=%v", e["owning_guid"], e["link_confidence"])
	}
}

func TestPiiatFilesEventPerProcessObservation(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	f1 := tag(normalize.Normalize("windows.piiat.files", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "HandleValue": 4,
		"FileObjectOffset": 0xF11E, "Path": `\Device\HarddiskVolume2\secret.docx`, "GrantedAccess": 3}))
	f2 := tag(normalize.Normalize("windows.piiat.files", car.Record{
		"OwnerOffset": 0xb, "PID": 11, "ProcessName": "y.exe", "HandleValue": 8,
		"FileObjectOffset": 0xF11E, "Path": `\Device\HarddiskVolume2\secret.docx`, "GrantedAccess": 1}))
	out := Enrich([]car.Event{p, f1, f2})
	files := ofObj(out, "file")
	if len(files) != 2 {
		t.Fatalf("want 2 file observations, got %d", len(files))
	}
	var owned car.Event
	for _, f := range files {
		if s(f, "owning_guid") == "proc-a" {
			owned = f
		}
	}
	if s(owned, "link_confidence") != "definitive" || s(owned, "file_name") != "secret.docx" || i(owned, "pid") != 10 {
		t.Errorf("owned=%#v", owned)
	}
}

func TestWellKnownSIDUserCanonicalStoreWide(t *testing.T) {
	p := tag(normalize.Normalize("windows.piiat.processes", car.Record{
		"Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
		"ImageFileName": "svc.exe", "Path": `C:\svc.exe`, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": "2020-01-01T00:00:10+00:00",
		"DllCount": 0, "LoadedDlls": nil, "Hidden": false,
		"Sid": "S-1-5-19", "User": "NT Authority", "LogonId": "0x3e5"}))
	sess := tag(normalize.Normalize("windows.piiat.sessions", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "svc.exe", "SessionId": 0,
		"LogonId": "0x3e5", "Sid": "S-1-5-19", "User": "LocalService",
		"CreateTime": "2020-01-01T00:00:10+00:00"}))
	out := Enrich([]car.Event{p, sess})
	users := map[string]string{}
	for _, e := range out {
		users[s(e, "car_object")] = s(e, "user")
	}
	if users["process"] != "Local Service" || users["user_session"] != "Local Service" {
		t.Errorf("canonical user: process=%v session=%v", users["process"], users["user_session"])
	}
}

func TestTokenlessSessionRowNotPhantom(t *testing.T) {
	sess := tag(normalize.Normalize("windows.piiat.sessions", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
		"LogonId": nil, "Sid": nil, "User": nil, "CreateTime": "2020-01-01T00:00:10+00:00"}))
	out := Enrich([]car.Event{sess})
	if len(ofObj(out, "user_session")) != 0 {
		t.Error("tokenless session must not become a phantom login")
	}
}

func TestPiiatSessionsLUIDIdentityAndNativeProcessUser(t *testing.T) {
	p := normalize.Normalize("windows.piiat.processes", car.Record{
		"Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
		"ImageFileName": "x.exe", "Path": `C:\x.exe`, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": "2020-01-01T00:00:10+00:00",
		"DllCount": 0, "LoadedDlls": nil, "Hidden": false,
		"Sid": "S-1-5-21-1-2-3-1001", "User": "Steve", "LogonId": "0x338f0"})
	if s(p, "user") != "Steve" || s(p, "sid") != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("native user/sid: %v/%v", p["user"], p["sid"])
	}
	s1 := tag(normalize.Normalize("windows.piiat.sessions", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
		"LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
		"CreateTime": "2020-01-01T00:00:10+00:00"}))
	s2 := tag(normalize.Normalize("windows.piiat.sessions", car.Record{
		"OwnerOffset": 0xb, "PID": 11, "ProcessName": "y.exe", "SessionId": 1,
		"LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
		"CreateTime": "2020-01-01T00:00:30+00:00"}))
	s3 := tag(normalize.Normalize("windows.piiat.sessions", car.Record{
		"OwnerOffset": 0xc, "PID": 12, "ProcessName": "svc.exe", "SessionId": 0,
		"LogonId": "0x3e7", "Sid": "S-1-5-18", "User": "Local System",
		"CreateTime": "2020-01-01T00:00:01+00:00"}))
	out := Enrich([]car.Event{tag(p), s1, s2, s3})
	sessions := ofObj(out, "user_session")
	logons := map[string]car.Event{}
	for _, e := range sessions {
		logons[s(e, "login_id")] = e
	}
	if len(logons) != 2 || logons["0x338f0"] == nil || logons["0x3e7"] == nil {
		t.Fatalf("want one session per LUID, got %v", func() []string {
			var k []string
			for id := range logons {
				k = append(k, id)
			}
			return k
		}())
	}
	steve := logons["0x338f0"]
	if s(steve, "timestamp") != "2020-01-01T00:00:10+00:00" || s(steve, "uid") != "S-1-5-21-1-2-3-1001" {
		t.Errorf("steve session=%#v", steve)
	}
}

func TestProcessUIDFromSIDAndSpokesInherit(t *testing.T) {
	p := tag(normalize.Normalize("windows.piiat.processes", car.Record{
		"Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
		"ImageFileName": "x.exe", "Path": `C:\x.exe`, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": "2020-01-01T00:00:10+00:00",
		"DllCount": 0, "LoadedDlls": nil, "Hidden": false,
		"Sid": "S-1-5-21-1-2-3-1001", "User": "Steve", "LogonId": "0x338f0"}))
	th := tag(normalize.Normalize("windows.piiat.threads", car.Record{
		"Offset": 9, "OwnerOffset": 0xa, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
	f := tag(normalize.Normalize("windows.piiat.files", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "HandleValue": 4,
		"FileObjectOffset": 0xF11E, "Path": `\Device\HarddiskVolume2\secret.docx`, "GrantedAccess": 3}))
	out := Enrich([]car.Event{p, th, f})
	by := byObj(out)
	if carmodel.FieldSet("thread")["sid"] {
		t.Error("thread should have no sid field (uid is the SID home)")
	}
	if s(by["thread"], "uid") != "S-1-5-21-1-2-3-1001" {
		t.Errorf("thread uid=%v", by["thread"]["uid"])
	}
	if s(by["file"], "uid") != "S-1-5-21-1-2-3-1001" || s(by["file"], "user") != "Steve" {
		t.Errorf("file uid=%v user=%v", by["file"]["uid"], by["file"]["user"])
	}
}

func TestAccessEventsRideProcessWithTargetIdentity(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "csrss.exe", `C:\W\csrss.exe`, "2020-01-01T00:00:10+00:00"))
	a1 := tag(normalize.Normalize("windows.piiat.access", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "csrss.exe", "HandleValue": 756,
		"GrantedAccess": 0x1FFFFF, "TargetOffset": 0xb, "TargetPid": 996, "TargetName": "svchost.exe"}))
	a2 := tag(normalize.Normalize("windows.piiat.access", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "csrss.exe", "HandleValue": 900,
		"GrantedAccess": 0x1FFFFF, "TargetOffset": 0xc, "TargetPid": 700, "TargetName": "lsass.exe"}))
	out := Enrich([]car.Event{p, a1, a2})
	var acc []car.Event
	for _, e := range out {
		if e["car_action"] == "access" {
			acc = append(acc, e)
		}
	}
	if len(acc) != 2 {
		t.Fatalf("distinct targets must not collapse, got %d", len(acc))
	}
	names := map[string]bool{}
	for _, e := range acc {
		if s(e, "link_confidence") != "definitive" || s(e, "image_path") != `C:\W\csrss.exe` {
			t.Errorf("access ev=%#v", e)
		}
		names[s(e, "target_name")] = true
	}
	if !names["svchost.exe"] || !names["lsass.exe"] {
		t.Errorf("target names=%v", names)
	}
}

func TestMFTRowsMergeWithTimestompTell(t *testing.T) {
	si := tag(normalize.Normalize("windows.mftscan.MFTScan", car.Record{
		"Offset": 1, "Record Type": "FILE", "Record Number": 99107, "Link Count": 1,
		"MFT Type": "File", "Permissions": "a", "Attribute Type": "STANDARD_INFORMATION",
		"Created": "2015-01-01T00:00:00+00:00", "Modified": "2019-01-29T04:27:51+00:00",
		"Updated": nil, "Accessed": nil, "Filename": nil}))
	fn1 := tag(normalize.Normalize("windows.mftscan.MFTScan", car.Record{
		"Offset": 1, "Record Type": "FILE", "Record Number": 99107, "Link Count": 1,
		"MFT Type": "File", "Permissions": "a", "Attribute Type": "FILE_NAME",
		"Created": "2019-01-29T04:27:51+00:00", "Modified": nil, "Updated": nil,
		"Accessed": nil, "Filename": "CSS_1_~1.CSS"}))
	fn2 := tag(normalize.Normalize("windows.mftscan.MFTScan", car.Record{
		"Offset": 1, "Record Type": "FILE", "Record Number": 99107, "Link Count": 1,
		"MFT Type": "File", "Permissions": "a", "Attribute Type": "FILE_NAME",
		"Created": "2019-01-29T04:27:51+00:00", "Modified": nil, "Updated": nil,
		"Accessed": nil, "Filename": "evil-css[1].css"}))
	out := Enrich([]car.Event{si, fn1, fn2})
	files := ofObj(out, "file")
	if len(files) != 1 {
		t.Fatalf("want 1 merged MFT file event, got %d", len(files))
	}
	f := files[0]
	if s(f, "guid") != "file-mft-99107" || s(f, "file_name") != "evil-css[1].css" || s(f, "extension") != "css" {
		t.Errorf("f=%#v", f)
	}
	if s(f, "creation_time") != "2015-01-01T00:00:00+00:00" ||
		s(f, "previous_creation_time") != "2019-01-29T04:27:51+00:00" {
		t.Errorf("timestomp: created=%v prev=%v", f["creation_time"], f["previous_creation_time"])
	}
	if s(f, "timestamp") != s(f, "creation_time") || s(f, "car_action") != "create" {
		t.Errorf("ts/action: %v/%v", f["timestamp"], f["car_action"])
	}
}

func TestHostIdentityFillsEveryObject(t *testing.T) {
	comp := tag(normalize.Normalize("windows.piiat.registry", car.Record{
		"Hive": `\REGISTRY\MACHINE\SYSTEM`,
		"Key":  `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`,
		"ValueName": "ComputerName", "ValueData": "DESKTOP-8", "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
	dom := tag(normalize.Normalize("windows.piiat.registry", car.Record{
		"Hive": `\REGISTRY\MACHINE\SYSTEM`,
		"Key":  `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters`,
		"ValueName": "DhcpDomain", "ValueData": "localdomain", "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	th := tag(normalize.Normalize("windows.piiat.threads", car.Record{
		"Offset": 9, "OwnerOffset": 0xa, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
	fl := tag(normalize.Normalize("windows.piiat.network", car.Record{
		"Offset": 8, "OwnerOffset": 0xa, "Proto": "TCPv4", "LocalAddr": "10.0.0.2",
		"LocalPort": 5000, "ForeignAddr": "1.2.3.4", "ForeignPort": 443,
		"State": "ESTABLISHED", "PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:00+00:00"}))
	by := byObj(Enrich([]car.Event{comp, dom, p, th, fl}))
	if s(by["process"], "hostname") != "DESKTOP-8" || s(by["process"], "fqdn") != "DESKTOP-8.localdomain" {
		t.Errorf("process host=%v fqdn=%v", by["process"]["hostname"], by["process"]["fqdn"])
	}
	if s(by["thread"], "hostname") != "DESKTOP-8" || s(by["registry"], "hostname") != "DESKTOP-8" {
		t.Errorf("thread/registry hostname")
	}
	if s(by["flow"], "src_hostname") != "DESKTOP-8" || by["flow"]["dest_hostname"] != nil {
		t.Errorf("flow src=%v dest=%v", by["flow"]["src_hostname"], by["flow"]["dest_hostname"])
	}
}

func TestDottedComputerNameIsFQDN(t *testing.T) {
	comp := tag(normalize.Normalize("windows.piiat.registry", car.Record{
		"Hive": `\REGISTRY\MACHINE\SYSTEM`,
		"Key":  `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`,
		"ValueName": "ComputerName", "ValueData": "HOST1.EXAMPLE.COM", "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	proc0 := ofObj(Enrich([]car.Event{comp, p}), "process")[0]
	if s(proc0, "hostname") != "HOST1" || s(proc0, "fqdn") != "HOST1.EXAMPLE.COM" {
		t.Errorf("host=%v fqdn=%v", proc0["hostname"], proc0["fqdn"])
	}
}

func TestActiveComputerNameFallbackAndBootWins(t *testing.T) {
	mk := func(sub, data string) car.Event {
		return tag(normalize.Normalize("windows.piiat.registry", car.Record{
			"Hive": `\REGISTRY\MACHINE\SYSTEM`,
			"Key":  `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\` + sub,
			"ValueName": "ComputerName", "ValueData": data, "ValueType": "REG_SZ", "LastWrite": "2019-01-28"}))
	}
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	// active only
	got := ofObj(Enrich([]car.Event{mk("ActiveComputerName", "DESKTOP-M913391"), p}), "process")[0]
	if s(got, "hostname") != "DESKTOP-M913391" {
		t.Errorf("active fallback hostname=%v", got["hostname"])
	}
	// boot wins over active
	p2 := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	got2 := ofObj(Enrich([]car.Event{mk("ComputerName", "BOOTNAME"), mk("ActiveComputerName", "RENAMED"), p2}), "process")[0]
	if s(got2, "hostname") != "BOOTNAME" {
		t.Errorf("boot should win, hostname=%v", got2["hostname"])
	}
}

func TestNoRegistryLeavesHostnameNull(t *testing.T) {
	p := tag(proc(10, 4, 0xa, "x.exe", `C:\x.exe`, "2020-01-01T00:00:10+00:00"))
	out := Enrich([]car.Event{p})
	if out[0]["hostname"] != nil || out[0]["fqdn"] != nil {
		t.Errorf("hostname/fqdn should be null: %v/%v", out[0]["hostname"], out[0]["fqdn"])
	}
}

func TestLoginSuccessfulTrueByExistence(t *testing.T) {
	sess := tag(normalize.Normalize("windows.piiat.sessions", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "SessionId": 1,
		"LogonId": "0x338f0", "Sid": "S-1-5-21-1-2-3-1001", "User": "Steve",
		"CreateTime": "2020-01-01T00:00:10+00:00"}))
	out := Enrich([]car.Event{sess})
	if ofObj(out, "user_session")[0]["login_successful"] != true {
		t.Error("login_successful should be true by existence")
	}
	b := normalize.Normalize("windows.sessions", car.Record{
		"Session ID": 1, "User Name": `HOST\jake`, "Create Time": "2020-01-01T00:00:02+00:00",
		"Process ID": 10, "Process": "x.exe"})
	if b["login_successful"] != true {
		t.Error("built-in session login_successful should be true")
	}
}
