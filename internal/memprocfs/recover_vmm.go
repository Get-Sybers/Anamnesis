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
	va, err := k.v.GetProcAddress(systemPID, "ntoskrnl.exe", name)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve %s: %w", name, err)
	}
	if va == 0 {
		return nil, 0, fmt.Errorf("resolve %s: export not found", name)
	}
	code, err := k.v.MemRead(systemPID, va, 64)
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
		if improved {
			if dir := e.writableStoreDir(); dir != "" {
				if werr := symbols.WriteStoredOffsets(dir, *entry); werr != nil {
					fmt.Fprintf(os.Stderr, "[anamnesis] offset store write failed: %v\n", werr)
				}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "[anamnesis] offset store hit (complete, %d/%d offsets) guid=%s age=%d\n",
			len(entry.Offsets), total, key.GUID, key.Age)
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
	if off, ok := entry.Offset("PsReferencePrimaryToken"); ok && off > 0 {
		// The System process's primary token must yield S-1-5-18 (Local
		// System); an offset that does not is wrong or poisoned — discarded.
		if e.systemTokenSID(uint32(off)) == "S-1-5-18" {
			e.recTokenOffset, e.recTokenOK = uint32(off), true
		} else {
			fmt.Fprintf(os.Stderr, "[anamnesis] recovered _EPROCESS.Token offset %#x failed the System-process SID gate — discarded\n", off)
		}
	}
}

// fillProcess back-fills the fields the PDB-gated reads left empty, per
// process, tagging each recovered value in Recovery as field=method.
func (e *vmmEngine) fillProcess(p *Process, pi *mp.ProcessInfo) {
	var rec []string
	if p.CommandLine == "" {
		r := vmmReader{e.vmm, pi.PID}
		var res symbols.CommandLineResult
		var ok bool
		if pi.Win.PEB != 0 {
			res, ok = symbols.RecoverCommandLine(r, pi.Win.PEB, p.Path)
		} else if pi.Win.PEB32 != 0 {
			res, ok = symbols.RecoverCommandLine32(r, pi.Win.PEB32, p.Path)
		}
		if ok {
			if res.CommandLine != "" {
				p.CommandLine = res.CommandLine
				rec = append(rec, "command_line="+res.Method)
			}
			if p.Path == "" {
				if ip := pathOnly(res.ImagePath); ip != "" {
					p.Path = ip
					rec = append(rec, "image_path="+res.Method)
				}
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

// storeDirs lists where offset-store entries may live: the persistent symbol
// cache beside vmm.so (when mounted read-write) and the /tmp fallback.
func (e *vmmEngine) storeDirs() []string {
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
	for _, dir := range e.storeDirs() {
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
