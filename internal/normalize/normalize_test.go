package normalize

import (
	"testing"

	"anamnesis/internal/car"
	"anamnesis/internal/value"
)

// procRec mirrors tests/test_car_pipeline.py::_proc's raw record.
func procRec(pid, ppid, offset int, name string, path any, ts string) car.Record {
	return car.Record{
		"Offset": offset, "Guid": "proc-" + hexs(offset), "PID": pid, "PPID": ppid,
		"ImageFileName": name, "Path": path, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": ts, "DllCount": 0,
		"LoadedDlls": nil, "Hidden": false,
	}
}

func hexs(n int) string {
	const d = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{d[n&0xf]}, b...)
		n >>= 4
	}
	return string(b)
}

func str(ev car.Event, k string) string { return value.Str(ev[k]) }
func i64(ev car.Event, k string) int64  { n, _ := value.Int(ev[k]); return n }

func TestNormalizeProcessExeIsBasename(t *testing.T) {
	ev := Normalize("windows.anamnesis.processes", procRec(10, 4, 0xabc, "x.exe", `C:\dir\x.exe`, "2020-01-01T00:00:10+00:00"))
	if str(ev, "car_object") != "process" || str(ev, "car_action") != "create" {
		t.Fatalf("object/action: %v/%v", ev["car_object"], ev["car_action"])
	}
	if str(ev, "guid") != "proc-abc" {
		t.Errorf("guid = %v", ev["guid"])
	}
	if str(ev, "exe") != "x.exe" || str(ev, "image_path") != `C:\dir\x.exe` {
		t.Errorf("exe=%v image_path=%v", ev["exe"], ev["image_path"])
	}
}

func TestNormalizeEpochSentinelTimestampDropped(t *testing.T) {
	ev := Normalize("windows.thrdscan", car.Record{
		"Offset": 1, "PID": 4, "TID": 8, "CreateTime": "1601-01-01T00:00:00+00:00"})
	if ev["timestamp"] != nil {
		t.Errorf("timestamp = %v, want nil", ev["timestamp"])
	}
	if str(ev, "guid") != "thread-1" || i64(ev, "owning_pid") != 4 {
		t.Errorf("guid=%v owning_pid=%v", ev["guid"], ev["owning_pid"])
	}
}

func TestNormalizeRegistryUserFromHiveAndAction(t *testing.T) {
	ev := Normalize("windows.anamnesis.registry", car.Record{
		"Hive": `\??\C:\Users\alice\NTUSER.DAT`, "Key": `Software\Run`,
		"ValueName": "x", "ValueData": "y", "ValueType": "REG_SZ", "LastWrite": "2020-01-02"})
	if str(ev, "car_action") != "value_edit" || str(ev, "user") != "alice" {
		t.Errorf("action=%v user=%v", ev["car_action"], ev["user"])
	}
}

func TestNormalizeUnmappedPluginReturnsNil(t *testing.T) {
	if Normalize("windows.info", car.Record{"Variable": "Is64Bit"}) != nil {
		t.Error("unmapped plugin should normalize to nil")
	}
}

func TestNetscanListenerIsSocketConnectionIsFlow(t *testing.T) {
	listener := Normalize("windows.netscan", car.Record{
		"Offset": 7, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 3389,
		"ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
		"PID": 10, "Owner": "svchost.exe", "Created": "2020-01-01T00:01:00+00:00"})
	if str(listener, "car_object") != "socket" || str(listener, "car_action") != "listen" {
		t.Fatalf("listener object/action: %v/%v", listener["car_object"], listener["car_action"])
	}
	if i64(listener, "local_port") != 3389 || str(listener, "protocol") != "TCP" || str(listener, "family") != "ipv4" {
		t.Errorf("listener port=%v proto=%v family=%v", listener["local_port"], listener["protocol"], listener["family"])
	}
	conn := Normalize("windows.netscan", car.Record{
		"Offset": 8, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 5000,
		"ForeignAddr": "2001:db8::5", "ForeignPort": 443, "State": "ESTABLISHED",
		"PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:01+00:00"})
	if str(conn, "car_object") != "flow" || str(conn, "transport_protocol") != "TCP" {
		t.Errorf("conn object=%v transport=%v", conn["car_object"], conn["transport_protocol"])
	}
	if str(conn, "start_time") != "2020-01-01T00:01:01+00:00" {
		t.Errorf("start_time = %v", conn["start_time"])
	}
}

func TestRegistryDefaultValueKeepsItsGuid(t *testing.T) {
	ev := Normalize("windows.anamnesis.registry", car.Record{
		"Hive": "SOFTWARE", "Key": `Microsoft\Windows\Run`, "ValueName": "",
		"ValueData": "x", "ValueType": "REG_SZ", "LastWrite": "2020-01-02"})
	if str(ev, "guid") != `registry-SOFTWARE-Microsoft\Windows\Run-` {
		t.Errorf("guid = %q", ev["guid"])
	}
}

func TestProcessImagePathNeverABareName(t *testing.T) {
	ev := Normalize("windows.anamnesis.processes", procRec(10, 4, 0xa, "truncatedname14", nil, "2020-01-01T00:00:10+00:00"))
	if ev["image_path"] != nil {
		t.Errorf("image_path = %v, want nil", ev["image_path"])
	}
	if str(ev, "exe") != "truncatedname14" {
		t.Errorf("exe = %v", ev["exe"])
	}
}

func TestThreadStartModuleNeverMixedSource(t *testing.T) {
	ev := Normalize("windows.anamnesis.threads", car.Record{
		"Offset": 1, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00",
		"Win32StartAddress": 0xBAD, "Win32StartPath": nil,
		"StartAddress": 0x100, "StartPath": `\Windows\System32\ntdll.dll`})
	if i64(ev, "start_address") != 0xBAD {
		t.Errorf("start_address = %v", ev["start_address"])
	}
	if ev["start_module"] != nil {
		t.Errorf("start_module = %v, want nil", ev["start_module"])
	}
	nat := ev["_native"].(map[string]any)
	if nat["StartPath"] != `\Windows\System32\ntdll.dll` {
		t.Errorf("native StartPath = %v", nat["StartPath"])
	}
}

func TestProcessEnvVarsAndThreadStartFunctionMapped(t *testing.T) {
	p := Normalize("windows.anamnesis.processes", car.Record{
		"Offset": 0xa, "Guid": "proc-a", "PID": 10, "PPID": 4,
		"ImageFileName": "x.exe", "Path": `C:\x.exe`, "CommandLine": "c",
		"ParentPath": nil, "CreateTime": "2020-01-01T00:00:10+00:00",
		"DllCount": 0, "LoadedDlls": nil, "Hidden": false, "Sid": nil,
		"User": nil, "LogonId": nil, "Cwd": `C:\Users\x`,
		"IntegrityLevel": "high", "EnvVars": `PATH=C:\; TEMP=C:\Temp`})
	if str(p, "env_vars") != `PATH=C:\; TEMP=C:\Temp` {
		t.Errorf("env_vars = %v", p["env_vars"])
	}
	tr := Normalize("windows.anamnesis.threads", car.Record{
		"Offset": 1, "OwnerOffset": 0xa, "PID": 10, "TID": 7,
		"CreateTime":        "2020-01-01T00:00:20+00:00",
		"Win32StartAddress": 0x140, "Win32StartPath": `\Windows\System32\mssrch.dll`,
		"Win32StartFunction": "DllCanUnloadNow+0x10",
		"StartPath":          `\Windows\System32\ntdll.dll`, "StartFunction": "RtlUserThreadStart"})
	if str(tr, "start_function") != "DllCanUnloadNow+0x10" {
		t.Errorf("start_function = %v", tr["start_function"])
	}
	if str(tr, "start_module") != `\Windows\System32\mssrch.dll` {
		t.Errorf("start_module = %v", tr["start_module"])
	}
	nat := tr["_native"].(map[string]any)
	if nat["StartFunction"] != "RtlUserThreadStart" {
		t.Errorf("native StartFunction = %v", nat["StartFunction"])
	}
}

func TestAccessEventNormalizesInitiatorAndTargetGuids(t *testing.T) {
	a := Normalize("windows.anamnesis.access", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "csrss.exe", "HandleValue": 756,
		"GrantedAccess": 0x1FFFFF, "TargetOffset": 0xb, "TargetPid": 996, "TargetName": "svchost.exe"})
	if str(a, "car_object") != "process" || str(a, "car_action") != "access" {
		t.Fatalf("object/action: %v/%v", a["car_object"], a["car_action"])
	}
	if str(a, "guid") != "proc-a" || str(a, "target_guid") != "proc-b" {
		t.Errorf("guid=%v target_guid=%v", a["guid"], a["target_guid"])
	}
}

func TestAnamnesisFilesGuidPerProcessObservation(t *testing.T) {
	f1 := Normalize("windows.anamnesis.files", car.Record{
		"OwnerOffset": 0xa, "PID": 10, "ProcessName": "x.exe", "HandleValue": 4,
		"FileObjectOffset": 0xF11E, "Path": `\Device\HarddiskVolume2\secret.docx`, "GrantedAccess": 3})
	f2 := Normalize("windows.anamnesis.files", car.Record{
		"OwnerOffset": 0xb, "PID": 11, "ProcessName": "y.exe", "HandleValue": 8,
		"FileObjectOffset": 0xF11E, "Path": `\Device\HarddiskVolume2\secret.docx`, "GrantedAccess": 1})
	if str(f1, "guid") == str(f2, "guid") {
		t.Errorf("files should have per-(file,process) guids, both = %v", f1["guid"])
	}
	if str(f1, "file_name") != "secret.docx" || i64(f1, "pid") != 10 {
		t.Errorf("file_name=%v pid=%v", f1["file_name"], f1["pid"])
	}
}
