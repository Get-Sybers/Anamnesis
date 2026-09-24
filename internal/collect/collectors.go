package collect

import (
	"sort"
	"strings"

	"anamnesis/internal/car"
	"anamnesis/internal/memprocfs"
)

// collectProcesses -> windows.anamnesis.processes. One row per process, keyed by the
// _EPROCESS virtual address (Offset/Guid). Hidden = present but not in the active
// list (the psscan/pslist contrast, here process enumeration vs the active list).
func collectProcesses(eng memprocfs.Engine) ([]car.Record, error) {
	active, _ := eng.ActivePIDs()
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	recs := make([]car.Record, 0, len(procs))
	for _, p := range procs {
		recs = append(recs, car.Record{
			"Offset": p.EPROCESS, "Guid": memprocfs.ProcGUID(p.EPROCESS),
			"PID": int(p.PID), "PPID": int(p.PPID), "ImageFileName": p.Name,
			"Path": nilIfEmpty(p.Path), "CommandLine": nilIfEmpty(p.CommandLine),
			"ParentPath": nilIfEmpty(p.ParentPath), "CreateTime": nilIfEmpty(p.CreateTime),
			"DllCount": len(p.DLLPaths), "LoadedDlls": joinOrNil(p.DLLPaths),
			"Hidden": active != nil && !active[p.PID],
			"Sid":    nilIfEmpty(p.SID), "User": nilIfEmpty(p.User),
			"LogonId": nilIfEmpty(p.LogonID), "Cwd": nilIfEmpty(p.Cwd),
			"IntegrityLevel": nilIfEmpty(p.IntegrityLevel), "EnvVars": nilIfEmpty(p.EnvVars),
			"Recovery": nilIfEmpty(p.Recovery),
			"ExitTime": nilIfEmpty(p.ExitTime), "Unlinked": p.Unlinked,
			"Terminated": p.Terminated, "ObjTypeChecked": p.ObjTypeChecked,
			"ObjTypeConfirmed": p.ObjTypeConfirmed,
		})
	}
	return recs, nil
}

// collectTerminated -> windows.anamnesis.terminated: one row per process whose
// _EPROCESS records an exit time — the CAR process/terminate event.
func collectTerminated(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		if p.ExitTime == "" {
			continue
		}
		recs = append(recs, car.Record{
			"Offset": p.EPROCESS, "Guid": memprocfs.ProcGUID(p.EPROCESS),
			"PID": int(p.PID), "PPID": int(p.PPID), "ImageFileName": p.Name,
			"Path": nilIfEmpty(p.Path), "CommandLine": nilIfEmpty(p.CommandLine),
			"CreateTime": nilIfEmpty(p.CreateTime), "ExitTime": nilIfEmpty(p.ExitTime),
			"Sid": nilIfEmpty(p.SID), "User": nilIfEmpty(p.User),
		})
	}
	return recs, nil
}

// collectPslist -> windows.pslist (context: the active-list contrast).
func collectPslist(eng memprocfs.Engine) ([]car.Record, error) {
	active, _ := eng.ActivePIDs()
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		if active != nil && !active[p.PID] {
			continue
		}
		recs = append(recs, car.Record{
			"Offset": p.EPROCESS, "PID": int(p.PID), "PPID": int(p.PPID),
			"ImageFileName": p.Name, "CreateTime": nilIfEmpty(p.CreateTime),
		})
	}
	return recs, nil
}

// collectThreads -> windows.anamnesis.threads. OwnerOffset stamped from the process
// being enumerated, so the owner link is definitive.
func collectThreads(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		ths, err := eng.Threads(p.PID)
		if err != nil {
			continue
		}
		for _, t := range ths {
			recs = append(recs, car.Record{
				"Offset": t.ETHREAD, "OwnerOffset": p.EPROCESS, "PID": int(p.PID), "TID": int(t.TID),
				"CreateTime": nilIfEmpty(t.CreateTime), "ExitTime": nilIfEmpty(t.ExitTime),
				"Win32StartAddress": t.Win32StartAddress, "Win32StartPath": nilIfEmpty(t.Win32StartPath),
				"Win32StartFunction": nilIfEmpty(t.Win32StartFunction),
				"StartAddress":       t.StartAddress, "StartPath": nilIfEmpty(t.StartPath),
				"StartFunction": nilIfEmpty(t.StartFunction),
				"StackBase":     t.StackBase, "StackLimit": t.StackLimit,
				"UserStackBase": t.UserStackBase, "UserStackLimit": t.UserStackLimit,
				"Unbacked": t.Unbacked,
			})
		}
	}
	return recs, nil
}

// collectModules -> windows.anamnesis.modules. OwnerOffset stamped from the process.
func collectModules(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		mods, err := eng.Modules(p.PID)
		if err != nil {
			continue
		}
		for _, m := range mods {
			recs = append(recs, car.Record{
				"OwnerOffset": p.EPROCESS, "PID": int(p.PID), "Base": m.Base,
				"Name": nilIfEmpty(m.Name), "Path": nilIfEmpty(m.Path),
				"LoadTime": nilIfEmpty(m.LoadTime), "Size": m.Size,
				"LoadCount": m.LoadCount, "ProcessName": nilIfEmpty(p.Name),
				"Company": nilIfEmpty(m.Company), "Description": nilIfEmpty(m.Descr),
				"Version": nilIfEmpty(m.Version),
			})
		}
	}
	return recs, nil
}

func netRecords(eng memprocfs.Engine, withOwner bool) ([]car.Record, error) {
	nets, err := eng.NetEntries()
	if err != nil {
		return nil, err
	}
	pidToEP := map[uint32]uint64{}
	if withOwner {
		if procs, err := eng.Processes(); err == nil {
			for _, p := range procs {
				pidToEP[p.PID] = p.EPROCESS
			}
		}
	}
	var recs []car.Record
	for _, n := range nets {
		r := car.Record{
			"Offset": n.Offset, "Proto": n.Proto, "LocalAddr": n.LocalAddr, "LocalPort": n.LocalPort,
			"ForeignAddr": nilIfEmpty(n.ForeignAddr), "ForeignPort": n.ForeignPort,
			"State": nilIfEmpty(n.State), "PID": int(n.PID), "Owner": nilIfEmpty(n.Owner),
			"Created": nilIfEmpty(n.Created),
		}
		if withOwner {
			if ep, ok := pidToEP[n.PID]; ok {
				r["OwnerOffset"] = ep
			}
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// collectNetwork -> windows.anamnesis.network (definitive owner via OwnerOffset).
func collectNetwork(eng memprocfs.Engine) ([]car.Record, error) { return netRecords(eng, true) }

// collectNetstat -> windows.netstat (second view; owner heuristic by pid).
func collectNetstat(eng memprocfs.Engine) ([]car.Record, error) { return netRecords(eng, false) }

// collectFiles -> windows.anamnesis.files. Handle-enumerated File handles, one CAR
// event per (FILE_OBJECT, observing process); owner definitive via OwnerOffset.
func collectFiles(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		hs, err := eng.Handles(p.PID)
		if err != nil {
			continue
		}
		for _, h := range hs {
			if h.Type != "File" || h.Name == "" {
				continue
			}
			recs = append(recs, car.Record{
				"OwnerOffset": p.EPROCESS, "PID": int(p.PID), "ProcessName": nilIfEmpty(p.Name),
				"HandleValue": h.HandleValue, "FileObjectOffset": h.ObjectVA,
				"Path": h.Name, "GrantedAccess": h.GrantedAccess,
			})
		}
	}
	return recs, nil
}

// collectKeys -> windows.anamnesis.keys. Key-type handles: every registry key
// a process holds open, as registry/access events — the per-process registry
// surface the curated-key snapshot cannot see. One event per (process, key),
// with the handle count and the union of granted-access bits kept raw.
func collectKeys(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		hs, err := eng.Handles(p.PID)
		if err != nil {
			continue
		}
		type agg struct {
			hive, key, path string // path: the first raw handle name seen
			access          uint64
			count           int
		}
		// Aggregation keys on the NORMALIZED (hive, key) so the same key seen
		// under different name forms (annotated vs kernel) stays one event.
		byKey := map[string]*agg{}
		var order []string
		for _, h := range hs {
			if h.Type != "Key" || h.Name == "" {
				continue
			}
			hive, key := splitRegistryPath(h.Name)
			id := hive + "\x00" + key
			if a, ok := byKey[id]; ok {
				a.access |= h.GrantedAccess
				a.count++
				continue
			}
			byKey[id] = &agg{hive: hive, key: key, path: h.Name, access: h.GrantedAccess, count: 1}
			order = append(order, id)
		}
		for _, id := range order {
			a := byKey[id]
			recs = append(recs, car.Record{
				"OwnerOffset": p.EPROCESS, "PID": int(p.PID), "ProcessName": nilIfEmpty(p.Name),
				"Hive": nilIfEmpty(a.hive), "Key": nilIfEmpty(a.key), "Path": a.path,
				"GrantedAccess": a.access, "Handles": a.count,
			})
		}
	}
	return recs, nil
}

// splitRegistryPath maps a key-handle name onto the analyst's hive + key.
// MemProcFS renders Key handles as "[<hive VA>:<cell>] <hive>\<path>"
// (optionally with a leading backslash); the kernel's own
// "\REGISTRY\MACHINE\..." / "\REGISTRY\USER\<sid>\..." forms are handled too.
// The hive-object annotation stays in the raw Path the caller keeps.
func splitRegistryPath(path string) (hive, key string) {
	s := strings.TrimPrefix(path, `\`)
	// Strip the "[va:cell] " hive-object annotation.
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "] "); i >= 0 {
			s = s[i+2:]
		}
	}
	s = strings.TrimPrefix(s, `\`)
	const machine = `REGISTRY\MACHINE\`
	const user = `REGISTRY\USER\`
	switch {
	case s == `REGISTRY\MACHINE`:
		return "HKLM", ""
	case s == `REGISTRY\USER`:
		return "HKU", ""
	case strings.HasPrefix(s, machine):
		return "HKLM", s[len(machine):]
	case strings.HasPrefix(s, user):
		rest := s[len(user):]
		if i := strings.IndexByte(rest, '\\'); i >= 0 {
			return `HKU\` + rest[:i], rest[i+1:]
		}
		return `HKU\` + rest, ""
	}
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// collectAccess -> windows.anamnesis.access. Process-type handles = observed
// "A holds access to B" facts.
func collectAccess(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		hs, err := eng.Handles(p.PID)
		if err != nil {
			continue
		}
		for _, h := range hs {
			if h.Type != "Process" {
				continue
			}
			recs = append(recs, car.Record{
				"OwnerOffset": p.EPROCESS, "PID": int(p.PID), "ProcessName": nilIfEmpty(p.Name),
				"HandleValue": h.HandleValue, "GrantedAccess": h.GrantedAccess,
				"TargetOffset": h.TargetEPROCESS, "TargetPid": int(h.TargetPID),
				"TargetName": nilIfEmpty(h.TargetName),
			})
		}
	}
	return recs, nil
}

// collectSessions -> windows.anamnesis.sessions. One row per process; the token LUID
// is the login identity (enrichment collapses to one login per LUID).
func collectSessions(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		recs = append(recs, car.Record{
			"OwnerOffset": p.EPROCESS, "PID": int(p.PID), "ProcessName": nilIfEmpty(p.Name),
			"SessionId": p.SessionID, "LogonId": nilIfEmpty(p.LogonID),
			"Sid": nilIfEmpty(p.SID), "User": nilIfEmpty(p.User),
			"CreateTime": nilIfEmpty(p.CreateTime),
		})
	}
	return recs, nil
}

// collectServices -> windows.svcscan. A running service's host process gives
// a definitive owner link: OwnerOffset from the PID->EPROCESS map (the
// service's PID is the hosting process, so the same kernel-pointer identity
// the other collectors use), not the reused PID alone.
func collectServices(eng memprocfs.Engine) ([]car.Record, error) {
	svcs, err := eng.Services()
	if err != nil {
		return nil, err
	}
	pidToEP := map[uint32]uint64{}
	if procs, perr := eng.Processes(); perr == nil {
		for _, p := range procs {
			if p.PID != 0 && p.EPROCESS != 0 {
				pidToEP[p.PID] = p.EPROCESS
			}
		}
	}
	var recs []car.Record
	for _, s := range svcs {
		r := car.Record{
			"Offset": s.Offset, "Name": nilIfEmpty(s.Name), "PID": pidOrNil(s.PID),
			"Binary": nilIfEmpty(s.Binary), "Binary (Registry)": nilIfEmpty(s.BinaryRegistry),
			"Order": s.Order, "Start": nilIfEmpty(s.Start), "State": nilIfEmpty(s.State),
			"Type": nilIfEmpty(s.Type), "Display": nilIfEmpty(s.Display), "Dll": nilIfEmpty(s.Dll),
			"UserAccount": nilIfEmpty(s.User), "UserType": nilIfEmpty(s.UserType),
		}
		if s.PID != 0 {
			if ep, ok := pidToEP[s.PID]; ok {
				r["OwnerOffset"] = ep
			}
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// collectUnloaded -> windows.anamnesis.unloaded: the kernel's unloaded-module
// residue per process — module/unload CAR events with a real timestamp;
// leftover residue is unhooking/loader-tampering evidence.
func collectUnloaded(eng memprocfs.Engine) ([]car.Record, error) {
	procs, err := eng.Processes()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, p := range procs {
		mods, err := eng.UnloadedModules(p.PID)
		if err != nil {
			continue
		}
		for _, m := range mods {
			recs = append(recs, car.Record{
				"OwnerOffset": p.EPROCESS, "PID": int(p.PID), "Base": m.Base,
				"Name": nilIfEmpty(m.Name), "Size": m.Size,
				"UnloadTime": nilIfEmpty(m.UnloadTime), "Wow64": m.Wow64,
				"ProcessName": nilIfEmpty(p.Name),
			})
		}
	}
	return recs, nil
}

// collectDrivers -> windows.modules (kernel drivers).
func collectDrivers(eng memprocfs.Engine) ([]car.Record, error) {
	drs, err := eng.Drivers()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, d := range drs {
		recs = append(recs, car.Record{
			"Offset": d.Offset, "Name": nilIfEmpty(d.Name), "Base": d.Base,
			"Path": nilIfEmpty(d.Path), "Size": d.Size,
			"ServiceKey": nilIfEmpty(d.ServiceKey),
		})
	}
	return recs, nil
}

// collectRegistry -> windows.anamnesis.registry (curated keys).
func collectRegistry(eng memprocfs.Engine) ([]car.Record, error) {
	vals, err := eng.RegistryValues(DefaultRegistryTargets)
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, v := range vals {
		recs = append(recs, car.Record{
			"Hive": v.Hive, "Key": v.Key, "ValueName": v.ValueName,
			"ValueType": nilIfEmpty(v.ValueType), "ValueData": nilIfEmpty(v.ValueData),
			"LastWrite": nilIfEmpty(v.LastWrite),
		})
	}
	return recs, nil
}

// collectInfo -> windows.info (context: image metadata).
func collectInfo(eng memprocfs.Engine) ([]car.Record, error) {
	info, err := eng.Info()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(info))
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var recs []car.Record
	for _, k := range keys {
		recs = append(recs, car.Record{"Variable": k, "Value": info[k]})
	}
	return recs, nil
}

// collectBanners -> banners.Banners (context: format-agnostic image sanity check).
func collectBanners(eng memprocfs.Engine) ([]car.Record, error) {
	banners, err := eng.Banners()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, b := range banners {
		recs = append(recs, car.Record{"Banner": b})
	}
	return recs, nil
}

// collectMFT -> windows.mftscan.MFTScan (one row per $MFT attribute).
func collectMFT(eng memprocfs.Engine) ([]car.Record, error) {
	rows, err := eng.MFT()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, m := range rows {
		recs = append(recs, car.Record{
			"Record Number": m.RecordNumber, "Attribute Type": m.AttributeType,
			"MFT Type": nilIfEmpty(m.MFTType), "Filename": nilIfEmpty(m.Filename),
			"Created": nilIfEmpty(m.Created), "Modified": nilIfEmpty(m.Modified),
			"Updated": nilIfEmpty(m.Updated), "Accessed": nilIfEmpty(m.Accessed),
			"Offset": m.Offset, "Permissions": nilIfEmpty(m.Permissions),
		})
	}
	return recs, nil
}

// collectFilescan -> windows.filescan (ownerless FILE_OBJECT scan).
func collectFilescan(eng memprocfs.Engine) ([]car.Record, error) {
	files, err := eng.FileScan()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, f := range files {
		recs = append(recs, car.Record{"Offset": f.Offset, "Name": nilIfEmpty(f.Name)})
	}
	return recs, nil
}

// collectMalfind -> windows.malfind (trigger regions; not stored, joined at output).
func collectMalfind(eng memprocfs.Engine) ([]car.Record, error) {
	regions, err := eng.Malfind()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, r := range regions {
		recs = append(recs, car.Record{
			"PID": int(r.PID), "Process": nilIfEmpty(r.Process),
			"Start VPN": r.StartVPN, "End VPN": r.EndVPN,
			"Protection": nilIfEmpty(r.Protection), "Tag": nilIfEmpty(r.Tag),
			"CommitCharge": r.CommitCharge, "PrivateMemory": r.PrivateMemory,
			"Disasm": nilIfEmpty(r.Disasm), "Hexdump": nilIfEmpty(r.Hexdump),
		})
	}
	return recs, nil
}

func joinOrNil(ss []string) any {
	if len(ss) == 0 {
		return nil
	}
	return strings.Join(ss, ", ")
}
