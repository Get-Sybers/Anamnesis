package collect

import (
	"testing"
	"time"

	"anamnesis/internal/car"
	"anamnesis/internal/memprocfs"
	"anamnesis/internal/pipeline"
	"anamnesis/internal/value"
)

// fakeEngine is a canned Engine: it lets the collectors' record-shaping be tested
// end-to-end (collect -> build_store -> car.db) with no MemProcFS / memory image.
type fakeEngine struct{}

const (
	epP1 = uint64(0xaaaa) // an interesting user process (PID 10)
	epP2 = uint64(0xbbbb) // its access target (PID 4)
)

func (fakeEngine) Processes() ([]memprocfs.Process, error) {
	return []memprocfs.Process{
		{
			PID: 10, PPID: 4, EPROCESS: epP1, Name: "x.exe", Path: `C:\x.exe`,
			CommandLine: `x.exe -k`, CreateTime: "2020-01-01T00:00:10+00:00",
			SID: "S-1-5-21-1-2-3-1001", User: "Steve", LogonID: "0x338f0", SessionID: 1,
			DLLPaths: []string{`C:\Windows\System32\ntdll.dll`},
		},
		{PID: 4, PPID: 0, EPROCESS: epP2, Name: "System", CreateTime: "2020-01-01T00:00:01+00:00"},
	}, nil
}

func (fakeEngine) ActivePIDs() (map[uint32]bool, error) {
	return map[uint32]bool{10: true, 4: true}, nil
}

func (fakeEngine) Modules(pid uint32) ([]memprocfs.Module, error) {
	if pid != 10 {
		return nil, nil
	}
	return []memprocfs.Module{{
		Base: 0x7ff0, Name: "ntdll.dll",
		Path: `C:\Windows\System32\ntdll.dll`, LoadTime: "2020-01-01T00:00:11+00:00",
	}}, nil
}

func (fakeEngine) Threads(pid uint32) ([]memprocfs.Thread, error) {
	if pid != 10 {
		return nil, nil
	}
	return []memprocfs.Thread{{
		TID: 7, ETHREAD: 0x1111, CreateTime: "2020-01-01T00:00:20+00:00",
		Win32StartAddress: 0x140, StackBase: 1000, StackLimit: 900,
	}}, nil
}

func (fakeEngine) Handles(pid uint32) ([]memprocfs.Handle, error) {
	if pid != 10 {
		return nil, nil
	}
	return []memprocfs.Handle{
		{
			Type: "File", HandleValue: 4, GrantedAccess: 0x120089, ObjectVA: 0xF11E,
			Name: `\Device\HarddiskVolume2\secret.docx`,
		},
		{
			Type: "Process", HandleValue: 900, GrantedAccess: 0x1FFFFF,
			TargetPID: 4, TargetName: "System", TargetEPROCESS: epP2,
		},
	}, nil
}

func (fakeEngine) NetEntries() ([]memprocfs.NetEntry, error) {
	return []memprocfs.NetEntry{{
		Offset: 0x2000, Proto: "TCPv4", LocalAddr: "10.0.0.2",
		LocalPort: 5000, ForeignAddr: "1.2.3.4", ForeignPort: 443, State: "ESTABLISHED",
		PID: 10, Owner: "x.exe", Created: "2020-01-01T00:01:00+00:00",
	}}, nil
}

func (fakeEngine) Services() ([]memprocfs.Service, error) {
	return []memprocfs.Service{{
		Offset: 0x5, Name: "svc", PID: 10, Binary: `C:\svc.exe`,
		State: "RUNNING",
	}}, nil
}

func (fakeEngine) Drivers() ([]memprocfs.Driver, error) {
	return []memprocfs.Driver{{Offset: 0x9, Name: "ntfs.sys", Path: `C:\Windows\System32\drivers\ntfs.sys`, Base: 0xfff0}}, nil
}

func (fakeEngine) RegistryValues(_ []string) ([]memprocfs.RegValue, error) {
	return []memprocfs.RegValue{{
		Hive:      `\REGISTRY\MACHINE\SYSTEM`,
		Key:       `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`,
		ValueName: "ComputerName", ValueType: "REG_SZ", ValueData: "DESKTOP-8",
		LastWrite: "2019-01-28T00:00:00+00:00",
	}}, nil
}

func (fakeEngine) Info() (map[string]string, error)          { return map[string]string{"Is64Bit": "True"}, nil }
func (fakeEngine) Banners() ([]string, error)                { return []string{"Windows 10"}, nil }
func (fakeEngine) MFT() ([]memprocfs.MFTRecord, error)       { return nil, nil }
func (fakeEngine) FileScan() ([]memprocfs.FileObject, error) { return nil, nil }
func (fakeEngine) Malfind() ([]memprocfs.MalRegion, error)   { return nil, nil }
func (fakeEngine) Close() error                              { return nil }

func TestCollectorsToCarDB(t *testing.T) {
	dir := t.TempDir()
	results, stalled := Run(fakeEngine{}, dir, Names(), 0)
	if stalled != "" {
		t.Fatalf("unexpected stall: %s", stalled)
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("collector %s failed: %s", r.Plugin, r.Error)
		}
	}
	st, err := pipeline.BuildStore(dir, "img.mem")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// process: 2 create rows + 1 access row (the Process handle p1 -> p2)
	procRows, _ := st.IterObject("process")
	creates, accesses := 0, 0
	var p1 map[string]any
	for _, e := range procRows {
		switch e["car_action"] {
		case "create":
			creates++
			if value.Str(e["guid"]) == memprocfs.ProcGUID(epP1) {
				p1 = e
			}
		case "access":
			accesses++
			if value.Str(e["target_guid"]) != memprocfs.ProcGUID(epP2) {
				t.Errorf("access target_guid = %v, want %s", e["target_guid"], memprocfs.ProcGUID(epP2))
			}
			if value.Str(e["link_confidence"]) != "definitive" {
				t.Errorf("access link_confidence = %v", e["link_confidence"])
			}
		}
	}
	if creates != 2 || accesses != 1 {
		t.Fatalf("process rows: %d create, %d access (want 2, 1)", creates, accesses)
	}
	if p1 == nil || value.Str(p1["hostname"]) != "DESKTOP-8" {
		t.Errorf("process hostname (host identity) = %v", p1["hostname"])
	}
	if value.Str(p1["user"]) != "Steve" || value.Str(p1["command_line"]) != `x.exe -k` {
		t.Errorf("process native fields: user=%v cmd=%v", p1["user"], p1["command_line"])
	}

	assertDefinitive := func(obj string) {
		rows, _ := st.IterObject(obj)
		if len(rows) != 1 {
			t.Fatalf("%s rows = %d, want 1", obj, len(rows))
		}
		if value.Str(rows[0]["owning_guid"]) != memprocfs.ProcGUID(epP1) ||
			value.Str(rows[0]["link_confidence"]) != "definitive" {
			t.Errorf("%s owner=%v conf=%v (want definitive proc link)", obj,
				rows[0]["owning_guid"], rows[0]["link_confidence"])
		}
	}
	assertDefinitive("thread")
	assertDefinitive("module")
	assertDefinitive("file")
	assertDefinitive("flow")

	counts, _ := st.Counts()
	if counts["driver"] != 1 || counts["service"] != 1 {
		t.Errorf("driver=%d service=%d", counts["driver"], counts["service"])
	}
	if counts["user_session"] != 1 { // p1 has a LUID; System (no token) drops
		t.Errorf("user_session = %d, want 1", counts["user_session"])
	}
	// registry ComputerName row is stored and drove host identity
	if counts["registry"] != 1 {
		t.Errorf("registry rows = %d, want 1", counts["registry"])
	}
}

// The stall watchdog: a collector blocked inside the native engine trips the
// timeout and is reported stalled; a healthy collector is untouched by it.
func TestRunOneStallWatchdog(t *testing.T) {
	block := Collector{Name: "block", Collect: func(memprocfs.Engine) ([]car.Record, error) {
		select {} // blocked forever, like a poisoned native call
	}}
	if _, stalled, _ := runOne(fakeEngine{}, block, 50*time.Millisecond); !stalled {
		t.Fatal("watchdog did not fire on a blocked collector")
	}
	healthy := Collector{Name: "healthy", Collect: func(memprocfs.Engine) ([]car.Record, error) {
		return []car.Record{{"k": "v"}}, nil
	}}
	recs, stalled, err := runOne(fakeEngine{}, healthy, time.Second)
	if stalled || err != nil || len(recs) != 1 {
		t.Fatalf("healthy collector misreported: stalled=%v err=%v recs=%d", stalled, err, len(recs))
	}
}
