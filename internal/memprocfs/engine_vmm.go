//go:build memprocfs

// This file is the MemProcFS-backed Engine, compiled only with `-tags memprocfs`
// (the hardened image builds this way). It wraps github.com/sergeyzav/gomemprocfs
// (purego, no cgo) — the vmm native library is dlopen'd at runtime from LibPath.
//
// ON-TARGET VALIDATION REQUIRED: the mappings below are written against
// gomemprocfs v0.1.3's documented API and must be validated on a real memory
// image with the vmm library present. Items explicitly deferred to that pass are
// marked TODO(on-target): process create time via PDB offset, the Hidden flag,
// thread start-module resolution, SID->name, and the forensic MFT/filescan/malfind
// collectors.
package memprocfs

import (
	"fmt"
	"strings"
	"time"

	mp "github.com/sergeyzav/gomemprocfs"
)

const defaultLib = "/opt/anamnesis/lib/vmm.so"

type vmmEngine struct {
	vmm       *mp.Vmm
	procCache []Process
	epToProc  map[uint64]procRef
	ctOffset  uint32
	ctTried   bool
	ctOK      bool
}

type procRef struct {
	pid  uint32
	name string
}

// Open opens the memory image with the MemProcFS vmm library.
func Open(imagePath string, opt OpenOptions) (Engine, error) {
	lib := opt.LibPath
	if lib == "" {
		lib = defaultLib
	}
	build := func(forensic bool) []mp.Option {
		opts := []mp.Option{mp.WithDevice(imagePath), mp.WithDisablePython()}
		if !opt.SymbolsOnline {
			opts = append(opts, mp.WithDisableSymbolServer())
		}
		if forensic {
			opts = append(opts, mp.WithForensic(1))
		}
		return opts
	}
	vmm, err := mp.NewVmm(lib, build(opt.Forensic)...)
	if err != nil && opt.Forensic {
		// forensic init can fail on a stripped image; fall back without it.
		vmm, err = mp.NewVmm(lib, build(false)...)
	}
	if err != nil {
		return nil, fmt.Errorf("MemProcFS open %s: %w", imagePath, err)
	}
	return &vmmEngine{vmm: vmm}, nil
}

func (e *vmmEngine) Close() error { return e.vmm.Close() }

// --- processes ---------------------------------------------------------------

func (e *vmmEngine) Processes() ([]Process, error) {
	if e.procCache != nil {
		return e.procCache, nil
	}
	infos, err := e.vmm.GetProcessInfoAll()
	if err != nil {
		return nil, err
	}
	pathByPID := make(map[uint32]string, len(infos))
	out := make([]Process, 0, len(infos))
	e.epToProc = make(map[uint64]procRef, len(infos))
	for i := range infos {
		pi := &infos[i]
		p := Process{
			PID: pi.PID, PPID: pi.ParentPID, EPROCESS: pi.Win.EPROCESS, DTB: pi.DTB,
			Name:           pi.Name(),
			Path:           e.str(pi.PID, mp.ProcessInformationOptStringPathUserImage),
			CommandLine:    e.str(pi.PID, mp.ProcessInformationOptStringCmdline),
			SID:            e.str(pi.PID, mp.ProcessInformationOptStringSID),
			SessionID:      int(pi.Win.SessionID),
			IntegrityLevel: integrityLevel(pi.Win.IntegrityLevel),
			CreateTime:     e.createTime(pi.PID, pi.Win.EPROCESS),
		}
		if pi.Win.LUID != 0 {
			p.LogonID = fmt.Sprintf("0x%x", pi.Win.LUID)
		}
		if p.Path != "" {
			pathByPID[pi.PID] = p.Path
		}
		out = append(out, p)
		e.epToProc[pi.Win.EPROCESS] = procRef{pid: pi.PID, name: pi.Name()}
	}
	for i := range out {
		out[i].ParentPath = pathByPID[out[i].PPID]
	}
	e.procCache = out
	return out, nil
}

// ActivePIDs: MemProcFS detects processes with multiple methods and does not
// cleanly separate the active list from scanned-only ones, so every detected PID
// is reported active (Hidden stays false). TODO(on-target): derive the active
// PsActiveProcessHead list to restore the Hidden contrast.
func (e *vmmEngine) ActivePIDs() (map[uint32]bool, error) {
	pids, err := e.vmm.GetPidList()
	if err != nil {
		return nil, err
	}
	m := make(map[uint32]bool, len(pids))
	for _, p := range pids {
		m[p] = true
	}
	return m, nil
}

func (e *vmmEngine) str(pid uint32, opt mp.ProcessInfoStringOptions) string {
	s, err := e.vmm.GetProcessInfoString(pid, opt)
	if err != nil {
		return ""
	}
	return strings.TrimRight(s, "\x00")
}

// createTime reads _EPROCESS.CreateTime via its PDB offset + a kernel memory read.
// TODO(on-target): confirm the kernel PDB module name ("nt") and kernel-read pid.
func (e *vmmEngine) createTime(pid uint32, eprocess uint64) string {
	if !e.ctTried {
		e.ctTried = true
		if off, err := e.vmm.PdbTypeChildOffset("nt", "_EPROCESS", "CreateTime"); err == nil {
			e.ctOffset, e.ctOK = off, true
		}
	}
	if !e.ctOK || eprocess == 0 {
		return ""
	}
	b, err := e.vmm.MemRead(pid, eprocess+uint64(e.ctOffset), 8)
	if err != nil || len(b) < 8 {
		return ""
	}
	return fileTimeToISO(leU64(b))
}

// --- spokes ------------------------------------------------------------------

func (e *vmmEngine) Modules(pid uint32) ([]Module, error) {
	ml, err := e.vmm.GetModuleList(pid, mp.ModuleFlag(0))
	if err != nil {
		return nil, err
	}
	out := make([]Module, 0, len(ml.Modules))
	for _, m := range ml.Modules {
		out = append(out, Module{
			Base: m.BaseAddress, Size: uint64(m.ImageSize), Name: m.Name, Path: m.FullName,
			// TODO(on-target): MemProcFS's module map carries no load time — left "".
		})
	}
	return out, nil
}

func (e *vmmEngine) Threads(pid uint32) ([]Thread, error) {
	tl, err := e.vmm.GetThreadList(pid)
	if err != nil {
		return nil, err
	}
	out := make([]Thread, 0, len(tl.Threads))
	for _, t := range tl.Threads {
		out = append(out, Thread{
			TID: t.TID, ETHREAD: t.ETHREAD,
			CreateTime: fileTimeToISO(t.CreateTime), ExitTime: fileTimeToISO(t.ExitTime),
			Win32StartAddress: t.Win32StartAddress, StartAddress: t.StartAddress,
			StackBase: t.StackBaseKernel, StackLimit: t.StackLimitKernel,
			UserStackBase: t.StackBaseUser, UserStackLimit: t.StackLimitUser,
			// TODO(on-target): resolve Win32StartPath/Function from the module map + PDBs.
		})
	}
	return out, nil
}

func (e *vmmEngine) Handles(pid uint32) ([]Handle, error) {
	hl, err := e.vmm.GetHandleList(pid)
	if err != nil {
		return nil, err
	}
	if e.epToProc == nil {
		e.Processes() // ensure the EPROCESS->process map for target resolution
	}
	out := make([]Handle, 0, len(hl.Handles))
	for _, h := range hl.Handles {
		hd := Handle{
			HandleValue: uint64(h.Handle), Type: h.Type, GrantedAccess: uint64(h.GrantedAccess),
			Name: h.Text, ObjectVA: h.Object,
		}
		if h.Type == "Process" {
			// a Process handle's underlying object IS the target _EPROCESS.
			hd.TargetEPROCESS = h.Object
			if ref, ok := e.epToProc[h.Object]; ok {
				hd.TargetPID, hd.TargetName = ref.pid, ref.name
			}
		}
		out = append(out, hd)
	}
	return out, nil
}

// --- system-wide -------------------------------------------------------------

func (e *vmmEngine) NetEntries() ([]NetEntry, error) {
	nl, err := e.vmm.GetNetList()
	if err != nil {
		return nil, err
	}
	if e.epToProc == nil {
		e.Processes()
	}
	nameByPID := map[uint32]string{}
	for _, r := range e.epToProc {
		nameByPID[r.pid] = r.name
	}
	out := make([]NetEntry, 0, len(nl.Entries))
	for _, n := range nl.Entries {
		fam := "v4"
		if n.AddressFamily == 23 { // AF_INET6
			fam = "v6"
		}
		foreign := ""
		if n.Dst.Valid {
			foreign = n.Dst.Text
		}
		out = append(out, NetEntry{
			Offset: n.Object, Proto: netProto(n.Text) + fam,
			LocalAddr: n.Src.Text, LocalPort: int(n.Src.Port),
			ForeignAddr: foreign, ForeignPort: int(n.Dst.Port),
			State: tcpState(n.State), PID: n.PID, Owner: nameByPID[n.PID],
			Created: fileTimeToISO(n.Timestamp),
		})
	}
	return out, nil
}

func (e *vmmEngine) Services() ([]Service, error) {
	sl, err := e.vmm.GetServiceList()
	if err != nil {
		return nil, err
	}
	out := make([]Service, 0, len(sl.Entries))
	for _, s := range sl.Entries {
		out = append(out, Service{
			Offset: s.Object, Name: s.ServiceName, PID: s.PID,
			Binary: s.ImagePath, BinaryRegistry: s.Path,
			State: svcState(s.Status.CurrentState), Type: svcType(s.Status.ServiceType),
			Start: svcStart(s.StartType), Display: s.DisplayName, Order: int(s.Ordinal),
		})
	}
	return out, nil
}

func (e *vmmEngine) Drivers() ([]Driver, error) {
	dl, err := e.vmm.GetKDriverList()
	if err != nil {
		return nil, err
	}
	out := make([]Driver, 0, len(dl.Entries))
	for _, d := range dl.Entries {
		out = append(out, Driver{Offset: d.Va, Name: d.Name, Path: d.Path,
			Base: d.VaDriverStart, Size: d.CbDriverSize})
	}
	return out, nil
}

// RegistryValues reads the curated keys. MemProcFS registry paths are hive-rooted
// (e.g. "HKLM\SOFTWARE\..."); each target is tried under a few roots.
// TODO(on-target): confirm the exact path roots and add per-value LastWriteTime
// (via the parent key), and SID->name via ProfileList.
func (e *vmmEngine) RegistryValues(targets []string) ([]RegValue, error) {
	var out []RegValue
	roots := []string{`HKLM\SOFTWARE\`, `HKLM\SYSTEM\`, `HKLM\`}
	for _, t := range targets {
		for _, root := range roots {
			full := root + t
			vals, err := e.vmm.GetRegistryValues(full)
			if err != nil || len(vals) == 0 {
				continue
			}
			hive := strings.SplitN(t, `\`, 2)[0]
			for _, v := range vals {
				out = append(out, RegValue{
					Hive: root + hive, Key: full, ValueName: v.Name,
					ValueType: regType(v.Type), ValueData: regData(v.Type, v.Data),
				})
			}
			break // first root that resolved wins
		}
	}
	return out, nil
}

func (e *vmmEngine) Info() (map[string]string, error) {
	get := func(o mp.ConfigOpt) uint64 { v, _ := e.vmm.ConfigGet(o); return v }
	return map[string]string{
		"NtMajorVersion": fmt.Sprintf("%d", get(mp.OptWinVersionMajor)),
		"NtMinorVersion": fmt.Sprintf("%d", get(mp.OptWinVersionMinor)),
		"NtBuildNumber":  fmt.Sprintf("%d", get(mp.OptWinVersionBuild)),
	}, nil
}

func (e *vmmEngine) Banners() ([]string, error) {
	maj, _ := e.vmm.ConfigGet(mp.OptWinVersionMajor)
	min, _ := e.vmm.ConfigGet(mp.OptWinVersionMinor)
	bld, _ := e.vmm.ConfigGet(mp.OptWinVersionBuild)
	return []string{fmt.Sprintf("Windows NT %d.%d build %d", maj, min, bld)}, nil
}

// Forensic collectors — TODO(on-target): read MemProcFS forensic VFS
// (/forensic/ntfs, /forensic/csv) for MFT + ownerless files, and derive malfind
// from the VAD map (private + executable + non-image regions).
func (e *vmmEngine) MFT() ([]MFTRecord, error)       { return nil, nil }
func (e *vmmEngine) FileScan() ([]FileObject, error) { return nil, nil }
func (e *vmmEngine) Malfind() ([]MalRegion, error)   { return nil, nil }

// --- decode helpers ----------------------------------------------------------

func leU64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// fileTimeToISO converts a Windows FILETIME (100ns since 1601-01-01) to RFC3339
// UTC, or "" for the zero/sentinel value.
func fileTimeToISO(ft uint64) string {
	if ft == 0 {
		return ""
	}
	const ftPerSec = 10000000
	const epochDiff = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	secs := int64(ft/ftPerSec) - epochDiff
	nsec := int64(ft%ftPerSec) * 100
	t := time.Unix(secs, nsec).UTC()
	if t.Year() < 1970 {
		return ""
	}
	return t.Format(time.RFC3339)
}

func netProto(text string) string {
	f := strings.Fields(text)
	if len(f) > 0 {
		p := strings.ToUpper(f[0])
		p = strings.TrimSuffix(strings.TrimSuffix(p, "V4"), "V6")
		if p == "TCP" || p == "UDP" {
			return p
		}
	}
	return "TCP"
}

// tcpState maps the Windows MIB_TCP_STATE value MemProcFS reports.
func tcpState(s uint32) string {
	switch s {
	case 2:
		return "LISTENING"
	case 5:
		return "ESTABLISHED"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 6:
		return "FIN_WAIT1"
	case 8:
		return "CLOSE_WAIT"
	case 12:
		return "TIME_WAIT"
	default:
		return ""
	}
}

func integrityLevel(l mp.ProcessIntegrityLevel) string {
	switch uint32(l) {
	case 1, 2:
		return "low"
	case 3, 4:
		return "medium"
	case 5:
		return "high"
	case 6, 7:
		return "system"
	default:
		return ""
	}
}

func svcState(s uint32) string {
	switch s {
	case 1:
		return "STOPPED"
	case 4:
		return "RUNNING"
	case 7:
		return "PAUSED"
	default:
		return ""
	}
}

func svcType(t uint32) string {
	switch {
	case t&0x10 != 0:
		return "SERVICE_WIN32_OWN_PROCESS"
	case t&0x20 != 0:
		return "SERVICE_WIN32_SHARE_PROCESS"
	case t&0x1 != 0:
		return "SERVICE_KERNEL_DRIVER"
	case t&0x2 != 0:
		return "SERVICE_FILE_SYSTEM_DRIVER"
	default:
		return ""
	}
}

func svcStart(s uint32) string {
	switch s {
	case 0:
		return "SERVICE_BOOT_START"
	case 1:
		return "SERVICE_SYSTEM_START"
	case 2:
		return "SERVICE_AUTO_START"
	case 3:
		return "SERVICE_DEMAND_START"
	case 4:
		return "SERVICE_DISABLED"
	default:
		return ""
	}
}

func regType(t uint32) string {
	switch t {
	case 1:
		return "REG_SZ"
	case 2:
		return "REG_EXPAND_SZ"
	case 3:
		return "REG_BINARY"
	case 4:
		return "REG_DWORD"
	case 7:
		return "REG_MULTI_SZ"
	case 11:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_TYPE_%d", t)
	}
}

func regData(t uint32, data []byte) string {
	switch t {
	case 1, 2, 7: // REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ
		return utf16LE(data)
	case 4: // REG_DWORD (little-endian)
		if len(data) >= 4 {
			return fmt.Sprintf("%d", uint32(data[0])|uint32(data[1])<<8|uint32(data[2])<<16|uint32(data[3])<<24)
		}
	}
	return fmt.Sprintf("%x", data)
}

func utf16LE(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		if c == 0 {
			break
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
