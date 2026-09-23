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

// collectServices -> windows.svcscan (owner heuristic by pid).
func collectServices(eng memprocfs.Engine) ([]car.Record, error) {
	svcs, err := eng.Services()
	if err != nil {
		return nil, err
	}
	var recs []car.Record
	for _, s := range svcs {
		recs = append(recs, car.Record{
			"Offset": s.Offset, "Name": nilIfEmpty(s.Name), "PID": pidOrNil(s.PID),
			"Binary": nilIfEmpty(s.Binary), "Binary (Registry)": nilIfEmpty(s.BinaryRegistry),
			"Order": s.Order, "Start": nilIfEmpty(s.Start), "State": nilIfEmpty(s.State),
			"Type": nilIfEmpty(s.Type), "Display": nilIfEmpty(s.Display), "Dll": nilIfEmpty(s.Dll),
		})
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
