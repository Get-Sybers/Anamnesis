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
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	mp "github.com/sergeyzav/gomemprocfs"
)

const defaultLib = "/opt/anamnesis/lib/vmm.so"

type vmmEngine struct {
	vmm       *mp.Vmm
	lib       string // path to vmm.so; the symbol cache and offset store live beside it
	procCache []Process
	epToProc  map[uint64]procRef
	ctOffset  uint32
	ctTried   bool
	ctOK      bool
	ctSource  string // "pdb", "accessor" or "store" — what resolved ctOffset
	// Offline recovery state (recover_vmm.go).
	recTried       bool
	recCTOffset    uint32
	recCTOK        bool
	recSource      string
	recTokenOffset uint32
	recTokenOK     bool
	recPIDOffset   uint32
	recPIDOK       bool
	recExitOffset  uint32
	recExitOK      bool
	recLinksOffset uint32
	recLinksOK     bool
	linkedOnce     bool
	linkedCache    map[uint32]bool
	handleCache    map[uint32][]Handle
	userBySID      map[string]string
	recObCookie    uint8
	recObCookieOK  bool
	recProcTypeIdx uint8 // the kernel Process object-type index (set by the gate)
}

type procRef struct {
	pid  uint32
	name string
}

// Open opens the memory image with the MemProcFS vmm library. Always offline:
// the symbol server is disabled unconditionally — PDB symbols come only from
// the Symbols/ cache beside vmm.so (a bind-mounted persistent cache, or staged
// into /tmp when that cache is read-only, see stageSymbols); the fields PDBs
// would have derived are otherwise recovered from the image itself
// (recover_vmm.go).
func Open(imagePath string, opt OpenOptions) (Engine, error) {
	lib := opt.LibPath
	if lib == "" {
		lib = defaultLib
	}
	stageSymbols(lib)
	build := func(forensic bool) []mp.Option {
		opts := []mp.Option{mp.WithDevice(imagePath), mp.WithDisablePython(),
			mp.WithDisableSymbolServer()}
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
	return &vmmEngine{vmm: vmm, lib: lib}, nil
}

func (e *vmmEngine) Close() error { return e.vmm.Close() }

// stageSymbols makes the baked PDB cache visible to vmm.so. On Linux MemProcFS
// uses <dir(vmm.so)>/Symbols as its local symbol cache only when that directory
// is WRITABLE, and silently falls back to the literal "/tmp" otherwise (pdb.c
// PDB_Initialize_InitialValues) — under a hardened read-only rootfs the baked
// cache beside vmm.so would never be consulted. Mirror the same writability
// probe and copy the baked files into /tmp keeping the symsrv layout
// (<name>/<GUID+age>/<name>), so the fallback path vmm.so actually uses finds
// them. Best-effort: an unstaged PDB only costs the fields derived from it,
// but any file that could not be staged — a copy failure or a path the walk
// could not visit — is warned about, so a partial stage never fails silently.
func stageSymbols(lib string) {
	src := filepath.Join(filepath.Dir(lib), "Symbols")
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		return
	}
	if probe, err := os.CreateTemp(src, ".anamnesis-probe-*"); err == nil {
		// The cache is writable: vmm.so will read (and write) it directly.
		probe.Close()
		os.Remove(probe.Name())
		return
	}
	failed := false
	filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			failed = true // an unvisitable path is an unstaged file
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			failed = true
			return nil
		}
		dst := filepath.Join("/tmp", rel)
		if sfi, serr := os.Stat(path); serr == nil {
			if dfi, derr := os.Stat(dst); derr == nil && dfi.Size() == sfi.Size() {
				return nil // already staged (an earlier open or batch re-exec)
			}
		}
		if cerr := copyFile(path, dst); cerr != nil {
			failed = true
		}
		return nil
	})
	if failed {
		fmt.Fprintln(os.Stderr, "[anamnesis] baked symbol cache could not be fully staged to /tmp — PDB-derived fields (command_line/sid/user) may stay empty")
	}
}

// copyFile copies src to dst atomically (temp file + rename), creating parents.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".staging-*")
	if err != nil {
		return err
	}
	_, err = io.Copy(tmp, in)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// --- processes ---------------------------------------------------------------

func (e *vmmEngine) Processes() ([]Process, error) {
	if e.procCache != nil {
		return e.procCache, nil
	}
	infos, err := e.vmm.GetProcessInfoAll()
	if err != nil {
		return nil, err
	}
	e.recoverPrePass()
	pathByPID := make(map[uint32]string, len(infos))
	out := make([]Process, 0, len(infos))
	e.epToProc = make(map[uint64]procRef, len(infos))
	for i := range infos {
		pi := &infos[i]
		p := Process{
			PID: pi.PID, PPID: pi.ParentPID, EPROCESS: pi.Win.EPROCESS, DTB: pi.DTB,
			Name: pi.Name(),
			// MemProcFS falls back to the bare image NAME for kernel-side
			// processes (System, Registry); a value without a separator is not
			// a path — image_path stays honestly null, the name lives in exe.
			Path:           pathOnly(e.str(pi.PID, mp.ProcessInformationOptStringPathUserImage)),
			CommandLine:    e.str(pi.PID, mp.ProcessInformationOptStringCmdline),
			SID:            e.str(pi.PID, mp.ProcessInformationOptStringSID),
			SessionID:      int(pi.Win.SessionID),
			IntegrityLevel: integrityLevel(pi.Win.IntegrityLevel),
			CreateTime:     e.createTime(pi.PID, pi.Win.EPROCESS),
		}
		if pi.Win.LUID != 0 {
			p.LogonID = fmt.Sprintf("0x%x", pi.Win.LUID)
		}
		p.Terminated = pi.State != 0
		p.ExitTime = e.exitTimeISO(pi.Win.EPROCESS)
		e.fillProcess(&p, pi)
		if p.Path != "" {
			pathByPID[pi.PID] = p.Path
		}
		out = append(out, p)
		e.epToProc[pi.Win.EPROCESS] = procRef{pid: pi.PID, name: pi.Name()}
	}
	for i := range out {
		out[i].ParentPath = pathByPID[out[i].PPID]
	}
	// The raw ActiveProcessLinks contrast, surfaced as is — the analyst sees
	// every unlinked process; Hidden (ActivePIDs) is the consensus verdict.
	if linked := e.linkedPIDs(); linked != nil {
		for i := range out {
			if out[i].PID != 0 && !linked[out[i].PID] {
				out[i].Unlinked = true
			}
		}
	}
	e.procCache = out
	return out, nil
}

// exitTimeISO reads _EPROCESS.ExitTime — adjacent to CreateTime on every
// known x64 build — through the resolved CreateTime offset; "" while
// running, unknown, or implausible.
func (e *vmmEngine) exitTimeISO(eprocess uint64) string {
	if !e.ctOK || eprocess == 0 {
		return ""
	}
	b, err := e.vmm.MemRead(systemPID, eprocess+uint64(e.ctOffset)+8, 8)
	if err != nil || len(b) < 8 {
		return ""
	}
	ft := leU64(b)
	if ft == 0 || (e.ctSource != "pdb" && !plausibleFileTime(ft)) {
		return ""
	}
	return fileTimeToISO(ft)
}

// ActivePIDs reports each detected PID's presence on the kernel's
// ActiveProcessLinks ring — the pslist/psscan contrast. A detected process
// that is absent from the ring while its ExitStatus still reads STILL_ACTIVE
// is marked inactive (the collector's Hidden flag — the DKOM-unlinking
// primitive of docs/design/symbol-recovery.md §9); an exited process is just
// exited, never hidden. When the recovered offsets are unavailable every PID
// reports active, the honest no-contrast fallback.
func (e *vmmEngine) ActivePIDs() (map[uint32]bool, error) {
	pids, err := e.vmm.GetPidList()
	if err != nil {
		return nil, err
	}
	m := make(map[uint32]bool, len(pids))
	for _, p := range pids {
		m[p] = true
	}
	procs, perr := e.Processes() // runs the recovery pre-pass; cached
	if perr != nil {
		return m, nil
	}
	// Every detected process defaults to active — a PID absent from the pid
	// list (MemProcFS marks it terminated) must not read as hidden by key
	// absence; only the consensus below may say hidden.
	for i := range procs {
		if _, ok := m[procs[i].PID]; !ok {
			m[procs[i].PID] = true
		}
	}
	linked := e.linkedPIDs()
	if linked == nil {
		return m, nil
	}
	for i := range procs {
		p := &procs[i]
		if p.PID == 0 || linked[p.PID] {
			continue
		}
		// Consensus before the accusation (§9): an unlinked process is Hidden
		// only when three independent reads agree it is still running —
		// ExitStatus STILL_ACTIVE, ExitTime zero, and at least one thread.
		// A lingering exited EPROCESS (userinit, acquisition smear) fails
		// those and is just exited, never hidden.
		if e.stillActive(p.EPROCESS) && !e.exited(p.EPROCESS) && e.hasThreads(p.PID) {
			m[p.PID] = false
		}
	}
	return m, nil
}

// exited reads _EPROCESS.ExitTime — adjacent to CreateTime on every known
// x64 build — through the recovered offset; nonzero means the process ended.
// Without a CreateTime offset the answer is unknown and reads as exited, so
// Hidden is never claimed on missing evidence.
func (e *vmmEngine) exited(eprocess uint64) bool {
	if !e.ctOK || eprocess == 0 {
		return true
	}
	b, err := e.vmm.MemRead(systemPID, eprocess+uint64(e.ctOffset)+8, 8)
	if err != nil || len(b) < 8 {
		return true
	}
	return leU64(b) != 0
}

// hasThreads reports whether the process still owns at least one thread.
func (e *vmmEngine) hasThreads(pid uint32) bool {
	tl, err := e.vmm.GetThreadList(pid)
	return err == nil && tl != nil && len(tl.Threads) > 0
}

func (e *vmmEngine) str(pid uint32, opt mp.ProcessInfoStringOptions) string {
	s, err := e.vmm.GetProcessInfoString(pid, opt)
	if err != nil {
		return ""
	}
	return strings.TrimRight(s, "\x00")
}

// pathOnly keeps s only when it is path-shaped (carries a separator).
func pathOnly(s string) string {
	if strings.ContainsAny(s, `\/`) {
		return s
	}
	return ""
}

// createTime reads _EPROCESS.CreateTime via a kernel memory read: the offset
// comes from the PDB when the symbol cache covers the build, else from the
// offline recovery pre-pass (accessor disassembly / the offset store), whose
// value already passed the System-process plausibility gate. The read runs in
// the System process's context — _EPROCESS is global kernel memory, and a
// user process's own context cannot see it (on-target: only kernel-side
// processes ever decoded before this).
func (e *vmmEngine) createTime(pid uint32, eprocess uint64) string {
	if !e.ctTried {
		e.ctTried = true
		if off, err := e.vmm.PdbTypeChildOffset("nt", "_EPROCESS", "CreateTime"); err == nil {
			e.ctOffset, e.ctOK, e.ctSource = off, true, "pdb"
		} else if e.recCTOK {
			e.ctOffset, e.ctOK, e.ctSource = e.recCTOffset, true, e.recSource
		}
	}
	if !e.ctOK || eprocess == 0 {
		return ""
	}
	b, err := e.vmm.MemRead(systemPID, eprocess+uint64(e.ctOffset), 8)
	if err != nil || len(b) < 8 {
		return ""
	}
	ft := leU64(b)
	// A recovered offset is held to the plausibility bound per value too; the
	// PDB path keeps its historical behavior.
	if e.ctSource != "pdb" && !plausibleFileTime(ft) {
		return ""
	}
	return fileTimeToISO(ft)
}

// keyLastWrite resolves a key's own last-write time: the registry enum API
// reports it per CHILD, so the key is found among its parent's sub-keys.
func (e *vmmEngine) keyLastWrite(keyPath string) string {
	i := strings.LastIndexByte(keyPath, '\\')
	if i <= 0 {
		return ""
	}
	subs, err := e.vmm.GetRegistrySubKeys(keyPath[:i])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[anamnesis][dbg] subkeys(%q) err=%v\n", keyPath[:i], err)
		return ""
	}
	leaf := keyPath[i+1:]
	fmt.Fprintf(os.Stderr, "[anamnesis][dbg] parent=%q leaf=%q subkeys=%d sample=%q\n", keyPath[:i], leaf, len(subs), sampleNames(subs))
	for _, k := range subs {
		name := strings.TrimRight(k.Name, "\x00 ")
		if strings.EqualFold(name, leaf) {
			fmt.Fprintf(os.Stderr, "[anamnesis][dbg] matched %q lastwrite=%#x\n", name, k.LastWriteTime)
			if k.LastWriteTime != 0 {
				return fileTimeToISO(k.LastWriteTime)
			}
		}
	}
	return ""
}

// --- spokes ------------------------------------------------------------------

func (e *vmmEngine) Modules(pid uint32) ([]Module, error) {
	ml, err := e.vmm.GetModuleList(pid, mp.ModuleFlagVersionInfo)
	if err != nil {
		return nil, err
	}
	out := make([]Module, 0, len(ml.Modules))
	for _, m := range ml.Modules {
		mod := Module{
			Base: m.BaseAddress, Size: uint64(m.ImageSize), Name: m.Name, Path: m.FullName,
			// TODO(on-target): MemProcFS's module map carries no load time — left "".
		}
		if m.VersionInfo != nil {
			mod.Company, mod.Descr, mod.Version = m.VersionInfo.CompanyName, m.VersionInfo.FileDescription, m.VersionInfo.FileVersion
		}
		out = append(out, mod)
	}
	return out, nil
}

// UnloadedModules reads the kernel's unloaded-module residue for a process.
func (e *vmmEngine) UnloadedModules(pid uint32) ([]UnloadedModule, error) {
	ul, err := e.vmm.GetUnloadedModuleList(pid)
	if err != nil || ul == nil {
		return nil, err
	}
	out := make([]UnloadedModule, 0, len(ul.Modules))
	for _, m := range ul.Modules {
		out = append(out, UnloadedModule{
			Base: m.BaseAddress, Size: uint64(m.ImageSize), Name: m.Name,
			UnloadTime: fileTimeToISO(m.UnloadTime), Wow64: m.IsWow64,
		})
	}
	return out, nil
}

func (e *vmmEngine) Threads(pid uint32) ([]Thread, error) {
	tl, err := e.vmm.GetThreadList(pid)
	if err != nil {
		return nil, err
	}
	// The start addresses resolve against the process's own module map; the
	// start function is the nearest preceding export of the containing module
	// (in-memory EAT — no PDB). A Win32 start address inside no module is the
	// injected-code signal, surfaced as Unbacked.
	res := e.startResolver(pid)
	out := make([]Thread, 0, len(tl.Threads))
	for _, t := range tl.Threads {
		th := Thread{
			TID: t.TID, ETHREAD: t.ETHREAD,
			CreateTime: fileTimeToISO(t.CreateTime), ExitTime: fileTimeToISO(t.ExitTime),
			Win32StartAddress: t.Win32StartAddress, StartAddress: t.StartAddress,
			StackBase: t.StackBaseKernel, StackLimit: t.StackLimitKernel,
			UserStackBase: t.StackBaseUser, UserStackLimit: t.StackLimitUser,
		}
		if res != nil {
			var backed bool
			th.Win32StartPath, th.Win32StartFunction, backed = res.resolve(t.Win32StartAddress)
			th.StartPath, th.StartFunction, _ = res.resolve(t.StartAddress)
			th.Unbacked = t.Win32StartAddress != 0 && !backed
		}
		out = append(out, th)
	}
	return out, nil
}

// startResolver indexes a process's modules (and, lazily, their in-memory
// export tables) so thread start addresses resolve to a module path and the
// nearest preceding export — no PDB involved.
type startResolver struct {
	e    *vmmEngine
	pid  uint32
	mods []mp.Module
	eats map[string][]mp.EatEntry
}

func (e *vmmEngine) startResolver(pid uint32) *startResolver {
	ml, err := e.vmm.GetModuleList(pid, mp.ModuleFlag(0))
	if err != nil || ml == nil || len(ml.Modules) == 0 {
		return nil
	}
	mods := append([]mp.Module(nil), ml.Modules...)
	sort.Slice(mods, func(i, j int) bool { return mods[i].BaseAddress < mods[j].BaseAddress })
	return &startResolver{e: e, pid: pid, mods: mods, eats: map[string][]mp.EatEntry{}}
}

// resolve returns the containing module's path, the nearest preceding export
// (as name or name+0x<distance>), and whether the address sat inside any
// module at all.
func (r *startResolver) resolve(va uint64) (path, function string, backed bool) {
	if va == 0 {
		return "", "", false
	}
	i := sort.Search(len(r.mods), func(i int) bool { return r.mods[i].BaseAddress > va }) - 1
	if i < 0 || va >= r.mods[i].BaseAddress+uint64(r.mods[i].ImageSize) {
		return "", "", false
	}
	m := &r.mods[i]
	return m.FullName, r.nearestExport(m, va), true
}

func (r *startResolver) nearestExport(m *mp.Module, va uint64) string {
	eat, ok := r.eats[m.Name]
	if !ok {
		if el, err := r.e.vmm.GetEatList(r.pid, m.Name); err == nil && el != nil {
			eat = append([]mp.EatEntry(nil), el.Entries...)
			sort.Slice(eat, func(i, j int) bool { return eat[i].FunctionAddress < eat[j].FunctionAddress })
		}
		r.eats[m.Name] = eat // a failed fetch caches as empty
	}
	i := sort.Search(len(eat), func(i int) bool { return eat[i].FunctionAddress > va }) - 1
	if i < 0 || eat[i].FunctionAddress == 0 || eat[i].FunctionName == "" {
		return ""
	}
	if off := va - eat[i].FunctionAddress; off != 0 {
		return fmt.Sprintf("%s+0x%x", eat[i].FunctionName, off)
	}
	return eat[i].FunctionName
}

// Handles caches per PID: three collectors (files, keys, process access)
// each walk every process's handles, and the native enumeration is the
// expensive part — one GetHandleList per process serves all of them.
func (e *vmmEngine) Handles(pid uint32) ([]Handle, error) {
	if hs, ok := e.handleCache[pid]; ok {
		return hs, nil
	}
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
	if e.handleCache == nil {
		e.handleCache = map[uint32][]Handle{}
	}
	e.handleCache[pid] = out
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
			User: s.UserAccount, UserType: s.UserType,
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
			Base: d.VaDriverStart, Size: d.CbDriverSize,
			ServiceKey: d.ServiceKeyName})
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
			lastWrite := e.keyLastWrite(full)
			for _, v := range vals {
				out = append(out, RegValue{
					Hive: root + hive, Key: full, ValueName: v.Name,
					ValueType: regType(v.Type), ValueData: regData(v.Type, v.Data),
					LastWrite: lastWrite,
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

// Malfind sweeps every process's VADs for the injection shape: committed
// private memory, image- and file-backed excluded, with an executable
// protection (the 3-bit VAD protection index carries the execute bit). The
// first bytes of each hit are recorded as a hex preview; a region that reads
// all zero (decommitted or paged out) is dropped rather than shown empty.
func (e *vmmEngine) Malfind() ([]MalRegion, error) {
	procs, err := e.Processes()
	if err != nil {
		return nil, err
	}
	const (
		perProcessCap = 64
		totalCap      = 4096
		previewLen    = 64
	)
	var out []MalRegion
	for i := range procs {
		p := &procs[i]
		if p.PID == 0 {
			continue
		}
		vl, verr := e.vmm.GetVadList(p.PID, false)
		if verr != nil || vl == nil {
			continue
		}
		hits := 0
		for _, v := range vl.Vads {
			if !v.IsPrivateMemory || v.IsImage || v.IsFile || !v.IsCommitted {
				continue
			}
			if v.Protection&2 == 0 {
				continue // no execute bit in the VAD protection index
			}
			buf, cb, rerr := e.vmm.MemReadEx(p.PID, v.Start, previewLen, mp.MemFlagNone)
			if rerr != nil || cb == 0 {
				continue
			}
			// Only the cb bytes actually read count — the slice may run past
			// them (vmmReader.ReadVirtual trims the same way).
			if uint32(len(buf)) > cb {
				buf = buf[:cb]
			}
			if allZero(buf) {
				continue
			}
			out = append(out, MalRegion{
				PID: p.PID, Process: p.Name,
				StartVPN: v.Start, EndVPN: v.End,
				Protection:    vadProtection(v.Protection),
				Tag:           "VadS",
				CommitCharge:  int(v.CommitCharge),
				PrivateMemory: 1,
				Hexdump:       hexPreview(buf),
			})
			hits++
			if hits >= perProcessCap || len(out) >= totalCap {
				break
			}
		}
		if len(out) >= totalCap {
			break
		}
	}
	return out, nil
}

// vadProtection renders the 3-bit VAD protection index in its MM_* order.
func vadProtection(p uint32) string {
	names := [8]string{
		"PAGE_NOACCESS", "PAGE_READONLY", "PAGE_EXECUTE", "PAGE_EXECUTE_READ",
		"PAGE_READWRITE", "PAGE_WRITECOPY", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
	}
	return names[p&7]
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// hexPreview renders bytes as space-separated hex pairs.
func hexPreview(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

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

// sampleNames is a debug helper: the first few sub-key names.
func sampleNames(subs []mp.RegistryKey) []string {
	var out []string
	for i, k := range subs {
		if i >= 4 {
			break
		}
		out = append(out, k.Name)
	}
	return out
}
