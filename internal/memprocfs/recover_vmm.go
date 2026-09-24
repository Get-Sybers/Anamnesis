//go:build memprocfs

// Offline recovery (docs/design/symbol-recovery.md §5, §6, §2 Tier 1): with no
// PDB, the engine recovers the symbol-derived process fields from the image
// itself — the command line out of the PEB's ProcessParameters anchored on the
// image path, the SID out of the ProcessInfo buffer, the user out of the
// registry-derived SID table, and _EPROCESS.CreateTime by disassembling the
// in-memory ntoskrnl's own accessor export. Kernel offsets are cached in the
// Tier-1 offset store keyed by the build's CodeView (GUID, age), kept in the
// persistent symbol cache, so the second image of a build is a store hit.
// Everything is per-field best-effort: a failed recovery costs that field and
// never the collector.
package memprocfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	mp "github.com/sergeyzav/gomemprocfs"

	"anamnesis/internal/symbols"
)

// systemPID is the Windows System process — the kernel address space vmm
// resolves module exports and reads kernel memory through.
const systemPID = 4

// vmmReader adapts one process's virtual address space to symbols.MemReader.
type vmmReader struct {
	v   *mp.Vmm
	pid uint32
}

func (r vmmReader) ReadVirtual(va uint64, n uint32) ([]byte, bool) {
	b, cb, err := r.v.MemReadEx(r.pid, va, n, mp.MemFlagNone)
	if err != nil || cb == 0 {
		return nil, false
	}
	if uint32(len(b)) > cb {
		b = b[:cb]
	}
	return b, true
}

// kernelCode feeds symbols.RecoverOffsets the leading bytes of exported
// ntoskrnl routines, resolved through vmm's own in-memory export-table parse —
// no PDB involved.
type kernelCode struct {
	v *mp.Vmm
}

func (k kernelCode) FunctionCode(name string) ([]byte, uint64, error) {
	return k.FunctionCodeN(name, 64)
}

// FunctionCodeN reads up to n leading bytes of an exported routine — the wider
// window symbols.RecoverGlobalVA needs.
func (k kernelCode) FunctionCodeN(name string, n int) ([]byte, uint64, error) {
	if n <= 0 {
		return nil, 0, fmt.Errorf("invalid code window %d", n)
	}
	va, err := k.v.GetProcAddress(systemPID, "ntoskrnl.exe", name)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve %s: %w", name, err)
	}
	if va == 0 {
		return nil, 0, fmt.Errorf("resolve %s: export not found", name)
	}
	code, err := k.v.MemRead(systemPID, va, uint32(n))
	if err != nil {
		return nil, 0, fmt.Errorf("read %s at %#x: %w", name, va, err)
	}
	return code, va, nil
}

// recoverPrePass runs once per image before the process list is built: the
// SID→user table, the kernel build identity, and the offset-store lookup —
// on a miss the accessor battery is disassembled and the result written back
// (the self-teaching cache).
func (e *vmmEngine) recoverPrePass() {
	if e.recTried {
		return
	}
	e.recTried = true
	if ul, err := e.vmm.GetUserList(); err == nil && ul != nil {
		e.userBySID = make(map[string]string, len(ul.Entries))
		for _, u := range ul.Entries {
			if u.SID != "" && u.Text != "" {
				e.userBySID[u.SID] = u.Text
			}
		}
	}
	guid, age, err := e.kernelCodeView()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[anamnesis] offline recovery: no ntoskrnl CodeView identity (%v) — kernel-offset recovery skipped\n", err)
		return
	}
	key := symbols.StoreKey{Module: "ntoskrnl.exe", GUID: guid, Age: age}
	total := len(symbols.ProcessAccessors)

	var stored *symbols.StoreEntry
	for _, dir := range e.storeDirs() {
		if en, rerr := symbols.ReadStoredOffsets(dir, key); rerr == nil {
			stored = en
			break
		}
	}

	// A complete stored entry (every accessor recovered or known undecodable)
	// is trusted as is — the fast path, no re-recovery. Otherwise disassemble
	// the in-memory ntoskrnl and MERGE into the stored entry, so an image that
	// could read only part of the kernel completes the entry a fuller image
	// left behind (the store converges over time — §2).
	// A CreateTime offset already in the stored entry is provenance "store";
	// one this image contributes is "accessor" — decided before the merge.
	const ctFunc = "PsGetProcessCreateTimeQuadPart"
	ctWhence := "accessor"
	if stored != nil {
		if _, ok := stored.Offset(ctFunc); ok {
			ctWhence = "store"
		}
	}

	entry := stored
	dirty := false
	if stored == nil || !stored.Complete(symbols.ProcessAccessors) {
		offsets, diags := symbols.RecoverOffsets(kernelCode{e.vmm}, symbols.ProcessAccessors)
		var undecodable []string
		for _, d := range diags {
			if d.Kind == symbols.Unrecognised {
				undecodable = append(undecodable, d.Func)
			}
		}
		merged, improved := symbols.Merge(stored, key, offsets, undecodable, time.Now().UTC().Format(time.RFC3339))
		entry = merged
		dirty = improved
		switch {
		case stored == nil:
			fmt.Fprintf(os.Stderr, "[anamnesis] recovered %d/%d kernel offsets from in-memory ntoskrnl (guid=%s age=%d)\n",
				len(entry.Offsets), total, key.GUID, key.Age)
		case improved:
			fmt.Fprintf(os.Stderr, "[anamnesis] offset store hit but incomplete — converged to %d/%d offsets from this image (guid=%s age=%d)\n",
				len(entry.Offsets), total, key.GUID, key.Age)
		default:
			fmt.Fprintf(os.Stderr, "[anamnesis] offset store hit, %d/%d offsets (this image adds none more; guid=%s age=%d)\n",
				len(entry.Offsets), total, key.GUID, key.Age)
		}
		if entry == nil || len(entry.Offsets) == 0 {
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "[anamnesis] offset store hit (complete, %d/%d offsets) guid=%s age=%d\n",
			len(entry.Offsets), total, key.GUID, key.Age)
	}

	// _EPROCESS.Token has no clean accessor to disassemble, so its offset is
	// constraint-solved: the qword in the System process's _EPROCESS that,
	// read as an EX_FAST_REF, points to a token carrying S-1-5-18. A stored
	// offset is trusted only while it still passes that System-process gate;
	// a stale or poisoned one is re-solved and overwritten, so token recovery
	// self-heals rather than staying disabled until the store is deleted. The
	// resolve runs even on an accessor-complete hit, so an entry written
	// before token recovery existed gains it.
	tokenOff, haveToken := entry.Offset(tokenScanFunc)
	tokenOK := haveToken && tokenOff > 0 && e.systemTokenSID(uint32(tokenOff)) == "S-1-5-18"
	if !tokenOK {
		if off, found := e.scanTokenOffset(); found {
			entry.Offsets = upsertOffset(entry.Offsets, symbols.RecoveredOffset{
				Func: tokenScanFunc, Struct: "_EPROCESS", Field: "Token",
				Offset: int32(off), Confidence: symbols.BestEffort,
			})
			tokenOff, tokenOK, dirty = int32(off), true, true
			verb := "constraint-solved"
			if haveToken {
				verb = "re-solved poisoned"
			}
			fmt.Fprintf(os.Stderr, "[anamnesis] %s _EPROCESS.Token offset %#x (guid=%s age=%d)\n", verb, off, key.GUID, key.Age)
		} else if haveToken {
			fmt.Fprintf(os.Stderr, "[anamnesis] stored _EPROCESS.Token offset %#x failed the System-process SID gate and could not be re-solved — token SID recovery disabled for this image\n", tokenOff)
		}
	}
	if tokenOK {
		e.recTokenOffset, e.recTokenOK = uint32(tokenOff), true
	}

	// UniqueProcessId and ExitStatus: each offset is consumed only after
	// decoding the System process to its known value (pid 4, STILL_ACTIVE) —
	// the same self-quarantine as CreateTime and Token.
	if off, ok := entry.Offset("PsGetProcessId"); ok && off > 0 && e.systemQwordAt(uint32(off)) == uint64(systemPID) {
		e.recPIDOffset, e.recPIDOK = uint32(off), true
	}
	if off, ok := entry.Offset("PsGetProcessExitStatus"); ok && off > 0 && e.systemDwordAt(uint32(off)) == stillActiveStatus {
		e.recExitOffset, e.recExitOK = uint32(off), true
	}
	// ActiveProcessLinks directly follows UniqueProcessId on every known x64
	// build; the adjacency is accepted only when the LIST_ENTRY closure
	// invariant holds through the System process (§3: x->Flink->Blink == x
	// and x->Blink->Flink == x).
	if e.recPIDOK {
		if cand := e.recPIDOffset + 8; e.linksClosureHolds(cand) {
			e.recLinksOffset, e.recLinksOK = cand, true
			fmt.Fprintf(os.Stderr, "[anamnesis] ActiveProcessLinks at UniqueProcessId+8 (%#x) — closure holds, Hidden contrast enabled\n", cand)
		}
	}

	// ObHeaderCookie: keyless recovery of the _OBJECT_HEADER.TypeIndex key
	// (§7). The reference VA is build-stable (cached in the store, seedable);
	// the cookie value is per-boot random, so it is re-read and gated from
	// this image on every load. Enables correct object typing for future
	// pool/handle scanning — no user-visible field yet.
	cookieRef := symbols.KernelGlobals[0] // ObGetObjectType -> ObHeaderCookie
	cookieVA, haveCookieVA := entry.Global(cookieRef.Global)
	if !haveCookieVA {
		if va, found := symbols.RecoverGlobalVA(kernelCode{e.vmm}, cookieRef); found {
			cookieVA, haveCookieVA = va, true
			if symbols.MergeGlobal(entry, symbols.RecoveredGlobal{Name: cookieRef.Global, VA: va, Confidence: symbols.BestEffort}) {
				dirty = true
			}
			fmt.Fprintf(os.Stderr, "[anamnesis] recovered %s reference VA %#x (guid=%s age=%d)\n", cookieRef.Global, va, key.GUID, key.Age)
		}
	}

	if dirty && len(entry.Offsets) > 0 {
		if dir := e.writableStoreDir(); dir != "" {
			if werr := symbols.WriteStoredOffsets(dir, *entry); werr != nil {
				fmt.Fprintf(os.Stderr, "[anamnesis] offset store write failed: %v\n", werr)
			}
		}
	}

	if haveCookieVA {
		e.gateObCookie(cookieVA)
	}

	if off, ok := entry.Offset(ctFunc); ok && off > 0 {
		// Gate on EVERY load, store hits included: the offset must decode the
		// System process's CreateTime to a plausible FILETIME, so a wrong or
		// poisoned store entry self-quarantines instead of stamping garbage.
		if e.plausibleSystemCreateTime(uint32(off)) {
			e.recCTOffset, e.recCTOK, e.recSource = uint32(off), true, ctWhence
		} else {
			fmt.Fprintf(os.Stderr, "[anamnesis] recovered _EPROCESS.CreateTime offset %#x failed the System-process plausibility gate — discarded\n", off)
		}
	}
}

// upsertOffset replaces the entry for o.Func, or appends it if absent — so a
// re-solved offset overwrites a stale stored one rather than duplicating it.
func upsertOffset(offs []symbols.RecoveredOffset, o symbols.RecoveredOffset) []symbols.RecoveredOffset {
	for i := range offs {
		if offs[i].Func == o.Func {
			offs[i] = o
			return offs
		}
	}
	return append(offs, o)
}

// tokenScanFunc is the store key for the constraint-solved _EPROCESS.Token
// offset — a pseudo-accessor name so it persists and converges beside the
// disassembled offsets without being counted toward accessor completeness.
const tokenScanFunc = "TokenScan"

// fillProcess back-fills the fields the PDB-gated reads left empty, per
// process, tagging each recovered value in Recovery as field=method.
func (e *vmmEngine) fillProcess(p *Process, pi *mp.ProcessInfo) {
	var rec []string
	// The parameter block also carries cwd and the environment, which the
	// PDB-backed reads never fill — so the walk runs whenever ANY of the
	// three is missing, and each value only ever fills a blank.
	if p.CommandLine == "" || p.Cwd == "" || p.EnvVars == "" {
		r := vmmReader{e.vmm, pi.PID}
		var res symbols.ProcParamsResult
		var ok bool
		if pi.Win.PEB != 0 {
			res, ok = symbols.RecoverProcParams(r, pi.Win.PEB, p.Path)
		} else if pi.Win.PEB32 != 0 {
			res, ok = symbols.RecoverProcParams32(r, pi.Win.PEB32, p.Path)
		}
		if ok {
			if p.CommandLine == "" && res.CommandLine != "" {
				p.CommandLine = res.CommandLine
				rec = append(rec, "command_line="+res.Method)
			}
			if p.Path == "" {
				if ip := pathOnly(res.ImagePath); ip != "" {
					p.Path = ip
					rec = append(rec, "image_path="+res.Method)
				}
			}
			if p.Cwd == "" && res.Cwd != "" {
				p.Cwd = res.Cwd
				rec = append(rec, "cwd="+res.Method)
			}
			if p.EnvVars == "" && res.Env != "" {
				p.EnvVars = res.Env
				rec = append(rec, "env_vars="+res.Method)
			}
		}
	}
	if p.SID == "" {
		if s, ok := symbols.DecodeSID(pi.Win.SIDRaw[:]); ok {
			p.SID = s
			rec = append(rec, "sid=sidraw")
		}
	}
	if p.SID == "" && e.recTokenOK && pi.Win.EPROCESS != 0 {
		if sid, method := e.tokenSID(pi.Win.EPROCESS); sid != "" {
			p.SID = sid
			rec = append(rec, "sid="+method)
		}
	}
	// Exact SID→account match from the registry-derived table; well-known SIDs
	// are left for the enrich stage's own map.
	if p.User == "" && p.SID != "" {
		if u := e.userBySID[p.SID]; u != "" {
			p.User = u
			rec = append(rec, "user=userlist")
		}
	}
	if p.CreateTime != "" && e.ctSource != "" && e.ctSource != "pdb" {
		rec = append(rec, "create_time="+e.ctSource)
	}
	// Object-type check: with the cookie validated, this _EPROCESS's own
	// _OBJECT_HEADER must deobfuscate to the kernel's Process type. A mismatch
	// means the enumerated "process" is not a real process object — a spoofing
	// or DKOM signal on data the engine already holds.
	if e.recObCookieOK && pi.Win.EPROCESS != 0 {
		if idx, ok := e.objTypeIndex(pi.Win.EPROCESS, e.recObCookie); ok {
			p.ObjTypeChecked = true
			p.ObjTypeConfirmed = idx == e.recProcTypeIdx
			if !p.ObjTypeConfirmed {
				rec = append(rec, fmt.Sprintf("obj_type=mismatch(%d)", idx))
			}
		}
	}
	if len(rec) > 0 {
		p.Recovery = strings.Join(rec, ";")
	}
}

// kernelCodeView reads ntoskrnl's CodeView (GUID, age) out of the in-memory
// module map: the direct name lookup first, then a walk of the System
// process's module list for the kernel entry (the mapped name varies —
// ntoskrnl.exe here, ntkrnlmp.exe on some builds).
func (e *vmmEngine) kernelCodeView() (string, uint32, error) {
	if mod, err := e.vmm.GetModuleByName(systemPID, "ntoskrnl.exe", mp.ModuleFlagDebugInfo); err == nil &&
		mod != nil && mod.DebugInfo != nil && mod.DebugInfo.GuidString != "" {
		return mod.DebugInfo.GuidString, mod.DebugInfo.Age, nil
	}
	ml, err := e.vmm.GetModuleList(systemPID, mp.ModuleFlagDebugInfo)
	if err != nil {
		return "", 0, fmt.Errorf("module list: %w", err)
	}
	for i := range ml.Modules {
		m := &ml.Modules[i]
		name := strings.ToLower(m.Name)
		if !strings.Contains(name, "ntoskrnl") && !strings.Contains(name, "ntkrnl") {
			continue
		}
		if m.DebugInfo == nil || m.DebugInfo.GuidString == "" {
			return "", 0, fmt.Errorf("%s carries no CodeView debug info", m.Name)
		}
		return m.DebugInfo.GuidString, m.DebugInfo.Age, nil
	}
	return "", 0, fmt.Errorf("no kernel module among %d System modules", len(ml.Modules))
}

// storeDirs lists where offset-store entries may be READ, in priority order:
// the persistent symbol cache beside vmm.so (the read-write mount), the /tmp
// fallback, and the read-only seed dir baked into the image (build-time
// genstore output — ANAMNESIS_SEED_DIR, default /opt/anamnesis/seed-offsets).
// A seed hit is used as a base; a fuller image still writes the converged
// entry into the writable cache (writableStoreDir skips the read-only seed),
// so seeds stay pristine and the mount keeps self-teaching.
func (e *vmmEngine) storeDirs() []string {
	dirs := []string{
		filepath.Join(filepath.Dir(e.lib), "Symbols", symbols.StoreSubdir),
		filepath.Join("/tmp", symbols.StoreSubdir),
	}
	seed := os.Getenv("ANAMNESIS_SEED_DIR")
	if seed == "" {
		seed = "/opt/anamnesis/seed-offsets"
	}
	return append(dirs, seed)
}

// writableStoreCandidates is the subset of storeDirs the engine may write to —
// the baked seed dir is read-only and excluded.
func (e *vmmEngine) writableStoreCandidates() []string {
	return []string{
		filepath.Join(filepath.Dir(e.lib), "Symbols", symbols.StoreSubdir),
		filepath.Join("/tmp", symbols.StoreSubdir),
	}
}

// writableStoreDir picks the first store location that can actually be
// created and written — the store directory itself, not its parent, so a
// read-only Symbols mount (where the parent exists but the subdir cannot be
// made) correctly falls through to the /tmp store. "" when neither works.
func (e *vmmEngine) writableStoreDir() string {
	for _, dir := range e.writableStoreCandidates() {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		probe, err := os.CreateTemp(dir, ".anamnesis-probe-*")
		if err != nil {
			continue
		}
		probe.Close()
		os.Remove(probe.Name())
		return dir
	}
	return ""
}

// plausibleSystemCreateTime reads the System process's CreateTime through the
// candidate offset and demands a FILETIME between 1990 and a day from now.
func (e *vmmEngine) plausibleSystemCreateTime(off uint32) bool {
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return false
	}
	b, err := e.vmm.MemRead(systemPID, pi.Win.EPROCESS+uint64(off), 8)
	if err != nil || len(b) < 8 {
		return false
	}
	return plausibleFileTime(leU64(b))
}

// fileTimeFloor is 1990-01-01 as a FILETIME (100ns ticks since 1601-01-01).
var fileTimeFloor = uint64(time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC).Unix()+11644473600) * 10_000_000

func plausibleFileTime(ft uint64) bool {
	if ft < fileTimeFloor {
		return false
	}
	ceiling := uint64(time.Now().Add(24*time.Hour).Unix()+11644473600) * 10_000_000
	return ft <= ceiling
}

const (
	// exFastRefMask clears the EX_FAST_REF reference-count bits (low 4 on x64,
	// objects being 16-byte aligned) to leave the object pointer.
	exFastRefMask = ^uint64(0xf)
	// kernelVAFloor is the low bound of the x64 kernel-canonical range.
	kernelVAFloor = uint64(0xffff_8000_0000_0000)
	// tokenWindow is how much of a token allocation is swept for SIDs — the
	// user and group SIDs sit in the token's variable part, well within this.
	tokenWindow = 0x800
)

// stillActiveStatus is the NTSTATUS a live process's ExitStatus holds.
const stillActiveStatus = 0x103

const (
	// objHeaderBody is how far the object body sits past its _OBJECT_HEADER on
	// x64 (the common-header size); objHeaderTypeIndex is TypeIndex within the
	// header. Stable across Win10/11 x64; a wrong value simply fails the gate.
	objHeaderBody      = 0x30
	objHeaderTypeIndex = 0x18
	// maxObjectType bounds a plausible decoded TypeIndex (there are far fewer
	// than this many object types); index 0/1 are not real object types.
	maxObjectType = 80
)

// gateObCookie accepts the candidate ObHeaderCookie only if it deobfuscates
// two independent kernel objects — the System process and its primary token —
// to plausible, distinct TypeIndex values (§9: consensus, never one view). A
// wrong cookie XORs to a value that rarely lands both in range; a right one
// always does. On pass it enables object typing for this image.
func (e *vmmEngine) gateObCookie(cookieVA uint64) {
	cb, err := e.vmm.MemRead(systemPID, cookieVA, 1)
	if err != nil || len(cb) < 1 {
		return
	}
	cookie := cb[0]
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return
	}
	procIdx, ok := e.objTypeIndex(pi.Win.EPROCESS, cookie)
	if !ok || procIdx < 2 || procIdx > maxObjectType {
		fmt.Fprintf(os.Stderr, "[anamnesis] ObHeaderCookie %#x failed the object-type gate (System process index implausible) — deobfuscation disabled\n", cookie)
		return
	}
	// Second object, REQUIRED: the System process's primary token. Consensus
	// means two views or none — a cookie that cannot be cross-checked is not
	// accepted on the process index alone.
	if !e.recTokenOK {
		fmt.Fprintf(os.Stderr, "[anamnesis] ObHeaderCookie %#x has no second object to validate against (token offset unresolved) — deobfuscation disabled\n", cookie)
		return
	}
	tb, terr := e.vmm.MemRead(systemPID, pi.Win.EPROCESS+uint64(e.recTokenOffset), 8)
	if terr != nil || len(tb) < 8 {
		fmt.Fprintf(os.Stderr, "[anamnesis] ObHeaderCookie %#x: token pointer unreadable — deobfuscation disabled\n", cookie)
		return
	}
	token := leU64(tb) & exFastRefMask
	if token < kernelVAFloor {
		fmt.Fprintf(os.Stderr, "[anamnesis] ObHeaderCookie %#x: token pointer implausible — deobfuscation disabled\n", cookie)
		return
	}
	tokIdx, tok := e.objTypeIndex(token, cookie)
	if !tok || tokIdx < 2 || tokIdx > maxObjectType || tokIdx == procIdx {
		fmt.Fprintf(os.Stderr, "[anamnesis] ObHeaderCookie %#x failed the object-type gate (token index implausible or equal to process) — deobfuscation disabled\n", cookie)
		return
	}
	e.recObCookie, e.recObCookieOK, e.recProcTypeIdx = cookie, true, procIdx
	fmt.Fprintf(os.Stderr, "[anamnesis] ObHeaderCookie validated (System process TypeIndex=%d) — object typing enabled\n", procIdx)
}

// objTypeIndex deobfuscates the TypeIndex of the object at objVA using cookie.
func (e *vmmEngine) objTypeIndex(objVA uint64, cookie uint8) (uint8, bool) {
	headerVA := objVA - objHeaderBody
	b, err := e.vmm.MemRead(systemPID, headerVA+objHeaderTypeIndex, 1)
	if err != nil || len(b) < 1 {
		return 0, false
	}
	return symbols.DecodeTypeIndex(b[0], headerVA, cookie), true
}

// systemQwordAt reads one qword of the System process's _EPROCESS at the
// candidate offset; 0 on any failure.
func (e *vmmEngine) systemQwordAt(off uint32) uint64 {
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return 0
	}
	b, err := e.vmm.MemRead(systemPID, pi.Win.EPROCESS+uint64(off), 8)
	if err != nil || len(b) < 8 {
		return 0
	}
	return leU64(b)
}

// systemDwordAt reads one dword the same way — sized to the field, so a
// 4-byte NTSTATUS at a page edge is not lost to a wider read failing.
func (e *vmmEngine) systemDwordAt(off uint32) uint32 {
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return 0
	}
	b, err := e.vmm.MemRead(systemPID, pi.Win.EPROCESS+uint64(off), 4)
	if err != nil || len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// linksClosureHolds verifies the LIST_ENTRY at System's _EPROCESS+off closes
// in both directions: Flink's Blink and Blink's Flink both point back.
func (e *vmmEngine) linksClosureHolds(off uint32) bool {
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return false
	}
	entry := pi.Win.EPROCESS + uint64(off)
	b, err := e.vmm.MemRead(systemPID, entry, 16)
	if err != nil || len(b) < 16 {
		return false
	}
	flink, blink := leU64(b), leU64(b[8:])
	if flink < kernelVAFloor || blink < kernelVAFloor {
		return false
	}
	fb, err := e.vmm.MemRead(systemPID, flink+8, 8)
	if err != nil || len(fb) < 8 || leU64(fb) != entry {
		return false
	}
	bf, err := e.vmm.MemRead(systemPID, blink, 8)
	return err == nil && len(bf) >= 8 && leU64(bf) == entry
}

// linkedPIDs walks ActiveProcessLinks from the System process and returns the
// PIDs on the ring (cached — the walk is per image, not per collector). nil
// when the offsets are unavailable or the walk does not close plausibly. The
// list HEAD (PsActiveProcessHead, not inside an _EPROCESS) contributes one
// junk key; harmless, since the set is only queried for detected PIDs.
func (e *vmmEngine) linkedPIDs() map[uint32]bool {
	if e.linkedOnce {
		return e.linkedCache
	}
	e.linkedOnce = true
	if !e.recLinksOK || !e.recPIDOK {
		return nil
	}
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return nil
	}
	const maxRing = 8192
	out := make(map[uint32]bool)
	start := pi.Win.EPROCESS + uint64(e.recLinksOffset)
	entry := start
	for i := 0; i < maxRing; i++ {
		ep := entry - uint64(e.recLinksOffset)
		if b, rerr := e.vmm.MemRead(systemPID, ep+uint64(e.recPIDOffset), 8); rerr == nil && len(b) >= 8 {
			out[uint32(leU64(b))] = true
		}
		f, rerr := e.vmm.MemRead(systemPID, entry, 8)
		if rerr != nil || len(f) < 8 {
			return nil
		}
		next := leU64(f)
		if next == start {
			if len(out) < 4 {
				return nil // implausibly small ring
			}
			fmt.Fprintf(os.Stderr, "[anamnesis] active-list ring: %d linked processes\n", len(out))
			e.linkedCache = out
			return out
		}
		if next < kernelVAFloor {
			return nil
		}
		entry = next
	}
	return nil // never closed — corrupt or wrong offset
}

// stillActive reads a process's ExitStatus through the recovered offset;
// STILL_ACTIVE means it has not exited. Unknown reads report false, so an
// unreadable process is never promoted to hidden.
func (e *vmmEngine) stillActive(eprocess uint64) bool {
	if !e.recExitOK || eprocess == 0 {
		return false
	}
	b, err := e.vmm.MemRead(systemPID, eprocess+uint64(e.recExitOffset), 4)
	if err != nil || len(b) < 4 {
		return false
	}
	return uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24 == stillActiveStatus
}

// tokenScanLo/Hi bound the _EPROCESS window the Token EX_FAST_REF is
// constraint-solved in (x64 Token sits well inside the first ~0x800 bytes).
const (
	tokenScanLo = 0x200
	tokenScanHi = 0x800
)

// scanTokenOffset finds _EPROCESS.Token by brute force over the System
// process: the 8-aligned qword that, masked as an EX_FAST_REF, points to a
// kernel token allocation carrying S-1-5-18 is the Token field. The exact SID
// match makes a false hit vanishingly unlikely; the offset is then validated
// per load and per process anyway.
func (e *vmmEngine) scanTokenOffset() (uint32, bool) {
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return 0, false
	}
	buf, err := e.vmm.MemRead(systemPID, pi.Win.EPROCESS+tokenScanLo, tokenScanHi-tokenScanLo)
	if err != nil {
		return 0, false
	}
	for off := 0; off+8 <= len(buf); off += 8 {
		token := leU64(buf[off:]) & exFastRefMask
		if token < kernelVAFloor {
			continue
		}
		tb, terr := e.vmm.MemRead(systemPID, token, tokenWindow)
		if terr != nil || len(tb) == 0 {
			continue
		}
		for _, s := range symbols.ScanSIDs(tb) {
			if s == "S-1-5-18" {
				return uint32(tokenScanLo + off), true
			}
		}
	}
	return 0, false
}

// systemTokenSID resolves the System process's primary-token user SID through
// the candidate _EPROCESS.Token offset — the gate that proves the offset.
func (e *vmmEngine) systemTokenSID(off uint32) string {
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return ""
	}
	sid, _ := e.readTokenSID(pi.Win.EPROCESS, off)
	return sid
}

// tokenSID resolves a process's primary-token user SID using the validated
// offset, returning the SID and the selection method for provenance.
func (e *vmmEngine) tokenSID(eprocess uint64) (string, string) {
	return e.readTokenSID(eprocess, e.recTokenOffset)
}

// readTokenSID reads _EPROCESS.Token (an EX_FAST_REF), dereferences it, sweeps
// the token allocation for its SIDs and picks the user SID. The token is
// kernel memory, so every read is in the System process's context.
func (e *vmmEngine) readTokenSID(eprocess uint64, off uint32) (string, string) {
	if eprocess == 0 || off == 0 {
		return "", ""
	}
	b, err := e.vmm.MemRead(systemPID, eprocess+uint64(off), 8)
	if err != nil || len(b) < 8 {
		return "", ""
	}
	token := leU64(b) & exFastRefMask
	if token < kernelVAFloor {
		return "", ""
	}
	buf, err := e.vmm.MemRead(systemPID, token, tokenWindow)
	if err != nil || len(buf) == 0 {
		return "", ""
	}
	return symbols.PickUserSID(symbols.ScanSIDs(buf), func(s string) bool {
		return e.userBySID[s] != ""
	})
}
