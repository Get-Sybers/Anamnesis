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
	"sort"
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
	// InheritedFromUniqueProcessId and ImageFileName back the pool-only rows
	// (a hidden process has no MemProcFS ProcessInfo, so every field is a
	// direct _EPROCESS read). Same self-quarantine: System's PPID is 0 and
	// its image name is the literal "System".
	if off, ok := entry.Offset("PsGetProcessInheritedFromUniqueProcessId"); ok && off > 0 && e.systemQwordAt(uint32(off)) == 0 {
		e.recPPIDOffset, e.recPPIDOK = uint32(off), true
	}
	if off, ok := entry.Offset("PsGetProcessImageFileName"); ok && off > 0 && e.imageNameAt(0, uint32(off)) == "System" {
		e.recImgOffset, e.recImgOK = uint32(off), true
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
	// (§7). Only the reference RVA is build-stable (cached in the store,
	// seedable) — under KASLR the VA moves every boot, so the store carries
	// module-relative addresses and the module base is added per image. The
	// cookie value is per-boot random, so it is re-read and gated from this
	// image on every load. Enables correct object typing for future
	// pool/handle scanning — no user-visible field yet.
	cookieRef := symbols.KernelGlobals[0] // ObGetObjectType -> ObHeaderCookie
	kBase, kSize, haveSpan := e.kernelSpan()
	var cookieVA uint64
	var haveCookieVA bool
	// An RVA is only meaningful inside the module span — enforced both when a
	// stored value is consumed and before a fresh recovery is persisted, so an
	// out-of-module address is never cached or read through.
	if rva, have := entry.Global(cookieRef.Global); have && haveSpan && rva < kSize {
		cookieVA, haveCookieVA = kBase+rva, true
	} else if va, found := symbols.RecoverGlobalVA(kernelCode{e.vmm}, cookieRef); found {
		cookieVA, haveCookieVA = va, true
		if haveSpan && va > kBase && va-kBase < kSize {
			if symbols.MergeGlobal(entry, symbols.RecoveredGlobal{Name: cookieRef.Global, RVA: va - kBase, Confidence: symbols.BestEffort}) {
				dirty = true
			}
			fmt.Fprintf(os.Stderr, "[anamnesis] recovered %s at RVA %#x (guid=%s age=%d)\n", cookieRef.Global, va-kBase, key.GUID, key.Age)
		}
	}

	// Function fingerprinting: prove the masked-pattern scan on THIS build's
	// real ntoskrnl image (self-test against exported ground truth), then
	// recover globals whose reading routines are not exported from the shipped
	// signatures. Only a passing self-test enables it; recovered RVAs cache in
	// the store like the cookie. The ground-truth cross-check confirms a
	// fingerprinted global equals its exported-path VA.
	e.fpOK = e.fingerprintSelfTest()
	if e.fpOK {
		e.fingerprintGroundTruth()
		if e.applyShippedSignatures(entry) {
			dirty = true
		}
	}

	// PsActiveProcessHead: in-image anchor recovery, and — first sighting of a
	// build — signature authoring, so later builds can locate it by pattern.
	if e.recoverProcessHead(entry) {
		dirty = true
	}

	// KdDebuggerDataBlock: locate the block and validate it against its own
	// "KDBG" tag and our independently-recovered process head. An unencoded
	// block is found by structural scan; the encoded case needs the wait keys
	// (a later slice's signature).
	if e.recoverKdbg(entry) {
		dirty = true
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

// kernelImageCap bounds the ntoskrnl span read for fingerprint scanning.
const kernelImageCap = 16 << 20

// kernelSpan resolves the ntoskrnl module's base and mapped size, cached per
// engine. Store RVAs resolve against the base; the size bounds in-module
// checks (a kernel global must lie inside the span).
func (e *vmmEngine) kernelSpan() (base, size uint64, ok bool) {
	if e.kBase != 0 {
		return e.kBase, e.kSize, true
	}
	if e.kSpanTried {
		return 0, 0, false
	}
	e.kSpanTried = true
	mod, err := e.vmm.GetModuleByName(systemPID, "ntoskrnl.exe", mp.ModuleFlag(0))
	if err != nil || mod == nil || mod.BaseAddress == 0 || mod.ImageSize == 0 {
		return 0, 0, false
	}
	e.kBase, e.kSize = mod.BaseAddress, uint64(mod.ImageSize)
	return e.kBase, e.kSize, true
}

// kernelImage reads the ntoskrnl module image span (base..base+ImageSize,
// capped) for masked-pattern scanning, cached per engine. It reads the whole
// mapped module, not an isolated .text section. baseVA is the module base — a
// matched offset resolves to base+off.
func (e *vmmEngine) kernelImage() (image []byte, baseVA uint64, ok bool) {
	if e.kImage != nil {
		return e.kImage, e.kImageVA, true
	}
	if e.kImageTried {
		return nil, 0, false
	}
	e.kImageTried = true
	base, modSize, ok := e.kernelSpan()
	if !ok {
		return nil, 0, false
	}
	size := int(modSize)
	if size <= 0 || size > kernelImageCap {
		size = kernelImageCap
	}
	// Read in chunks; a paged-out tail just shortens the scan window.
	const chunk = 1 << 20
	buf := make([]byte, 0, size)
	for off := 0; off < size; off += chunk {
		n := chunk
		if off+n > size {
			n = size - off
		}
		b, cb, rerr := e.vmm.MemReadEx(systemPID, base+uint64(off), uint32(n), mp.MemFlagNone)
		if rerr != nil || cb == 0 {
			break
		}
		buf = append(buf, b[:cb]...)
		if int(cb) < n {
			break
		}
	}
	if len(buf) == 0 {
		return nil, 0, false
	}
	e.kImage, e.kImageVA = buf, base
	return e.kImage, e.kImageVA, true
}

// fingerprintSelfTest proves the masked-pattern scanner on this build's real
// ntoskrnl image: it harvests a signature from an exported routine (bytes read
// via the export VA, the trailing displacement wildcarded) and requires the
// scan to relocate it — uniquely — to the export's own address. It reports the
// result; a later slice reads it to gate fingerprinted-global recovery.
func (e *vmmEngine) fingerprintSelfTest() bool {
	const probe = "PsGetProcessId" // an exported accessor: known VA = ground truth
	knownVA, err := e.vmm.GetProcAddress(systemPID, "ntoskrnl.exe", probe)
	if err != nil || knownVA == 0 {
		return false
	}
	code, err := e.vmm.MemRead(systemPID, knownVA, 24)
	if err != nil || len(code) < 16 {
		return false
	}
	image, baseVA, ok := e.kernelImage()
	if !ok {
		fmt.Fprintln(os.Stderr, "[anamnesis] fingerprint self-test: ntoskrnl image unreadable")
		return false
	}
	sig := harvestSignature(probe, code)
	matchVA, off, found := symbols.MatchSignature(image, baseVA, sig)
	if !found || matchVA != knownVA {
		fmt.Fprintf(os.Stderr, "[anamnesis] fingerprint self-test FAILED (found=%v at %#x, want %#x)\n", found, matchVA, knownVA)
		return false
	}
	// Uniqueness: no second match in the remainder.
	if _, _, dup := symbols.MatchSignature(image[off+1:], baseVA+uint64(off)+1, sig); dup {
		fmt.Fprintf(os.Stderr, "[anamnesis] fingerprint self-test: %s signature not unique\n", probe)
		return false
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] fingerprint self-test passed (%s relocated uniquely to %#x)\n", probe, knownVA)
	return true
}

// fingerprintGroundTruth cross-checks the whole harvest→apply path against a
// known answer: it harvests a signature from the EXPORTED ObGetObjectType at
// runtime, locates it by pattern in the image, RIPTargets ObHeaderCookie, and
// requires the result to equal the VA the exported path already recovers. It
// proves that locating a routine by pattern (what a non-exported target needs)
// yields the same global as resolving it by export.
func (e *vmmEngine) fingerprintGroundTruth() {
	va, err := e.vmm.GetProcAddress(systemPID, "ntoskrnl.exe", "ObGetObjectType")
	if err != nil || va == 0 {
		return
	}
	code, err := e.vmm.MemRead(systemPID, va, 96)
	if err != nil || len(code) < 32 {
		return
	}
	sig, ok := symbols.BuildSignature("ObGetObjectType", "ObHeaderCookie", code, true)
	if !ok {
		fmt.Fprintln(os.Stderr, "[anamnesis] fingerprint ground-truth: no RIP operand in ObGetObjectType")
		return
	}
	image, base, ok := e.kernelImage()
	if !ok {
		return
	}
	fpVA, fpOK := symbols.RecoverGlobalByFingerprint(image, base, sig)
	expVA, expOK := symbols.RecoverGlobalVA(kernelCode{e.vmm}, symbols.KernelGlobals[0])
	switch {
	case fpOK && expOK && fpVA == expVA:
		fmt.Fprintf(os.Stderr, "[anamnesis] fingerprint ground-truth OK: ObHeaderCookie via pattern == exported path (%#x)\n", fpVA)
	case fpOK && expOK:
		fmt.Fprintf(os.Stderr, "[anamnesis] fingerprint ground-truth MISMATCH (pattern=%#x exported=%#x)\n", fpVA, expVA)
	default:
		fmt.Fprintf(os.Stderr, "[anamnesis] fingerprint ground-truth inconclusive (pattern ok=%v, exported ok=%v)\n", fpOK, expOK)
	}
}

// sigDirs lists where fingerprint signatures are READ, in priority order: the
// persistent cache beside vmm.so, the /tmp fallback, and the read-only baked
// seed dir (ANAMNESIS_SIG_DIR, default /opt/anamnesis/seed-signatures).
// Signatures are not per-(GUID,age) — a masked pattern carries wherever the
// code shape does — and the cache self-teaches: an in-image anchor recovery
// AUTHORS a signature into the writable location, so a later image whose
// build shares that shape may locate the same global by pattern; one that
// does not match is skipped and recovered by its own anchor.
func (e *vmmEngine) sigDirs() []string {
	dirs := []string{
		filepath.Join(filepath.Dir(e.lib), "Symbols", symbols.SigSubdir),
		filepath.Join("/tmp", symbols.SigSubdir),
	}
	seed := os.Getenv("ANAMNESIS_SIG_DIR")
	if seed == "" {
		seed = "/opt/anamnesis/seed-signatures"
	}
	return append(dirs, seed)
}

// writableSigDir picks the first signature location that can actually be
// written (the baked seed dir is read-only and excluded), like
// writableStoreDir. "" when neither works.
func (e *vmmEngine) writableSigDir() string {
	return firstWritableDir([]string{
		filepath.Join(filepath.Dir(e.lib), "Symbols", symbols.SigSubdir),
		filepath.Join("/tmp", symbols.SigSubdir),
	})
}

// applyShippedSignatures locates each stored signature's global by pattern
// and caches its RVA in the store (per build, like the cookie). A global
// already in the entry is left alone (build-stable, seedable). The recovered
// address must lie inside the kernel module (an RVA is meaningless
// otherwise), and a global with a consume gate must pass it before it is
// trusted — PsActiveProcessHead's gate walks the ring from the candidate
// head. Returns whether the entry gained a global.
func (e *vmmEngine) applyShippedSignatures(entry *symbols.StoreEntry) bool {
	image, base, ok := e.kernelImage()
	if !ok {
		return false
	}
	_, size, _ := e.kernelSpan()
	var sigs []symbols.Signature
	for _, dir := range e.sigDirs() {
		s, err := symbols.ReadSignatures(dir, "ntoskrnl.exe")
		if err != nil {
			// A missing file is nil,nil — any error is a broken shipped file,
			// which must be visible, not a silent fingerprinting no-op.
			fmt.Fprintf(os.Stderr, "[anamnesis] signature store %s unreadable: %v\n", dir, err)
			continue
		}
		sigs = append(sigs, s...)
	}
	gates := map[string]func(uint64) bool{headGlobal: e.headRingGate}
	dirty := false
	for _, sig := range sigs {
		if _, have := entry.Global(sig.Global); have {
			continue
		}
		va, found := symbols.RecoverGlobalByFingerprint(image, base, sig)
		if !found || va <= base || va-base >= size {
			fmt.Fprintf(os.Stderr, "[anamnesis] signature %s (%s) did not locate an in-module global — skipped\n", sig.Name, sig.Global)
			continue
		}
		if gate := gates[sig.Global]; gate != nil && !gate(va) {
			fmt.Fprintf(os.Stderr, "[anamnesis] signature %s located %s at %#x but it failed the consume gate — skipped\n", sig.Name, sig.Global, va)
			continue
		}
		if symbols.MergeGlobal(entry, symbols.RecoveredGlobal{Name: sig.Global, RVA: va - base, Confidence: symbols.BestEffort}) {
			dirty = true
			fmt.Fprintf(os.Stderr, "[anamnesis] fingerprinted %s -> %s RVA %#x\n", sig.Name, sig.Global, va-base)
		}
		if sig.Global == headGlobal {
			e.recHeadVA, e.recHeadOK = va, true
		}
	}
	return dirty
}

// headGlobal is the kernel's active-process list head — a global LIST_ENTRY
// in ntoskrnl's data, not exported and not inside any _EPROCESS.
const headGlobal = "PsActiveProcessHead"

// systemLinksEntry is the System process's own ActiveProcessLinks entry VA —
// the anchor every ring walk and gate hangs off.
func (e *vmmEngine) systemLinksEntry() (uint64, bool) {
	if !e.recLinksOK {
		return 0, false
	}
	pi, err := e.vmm.GetProcessInfo(systemPID)
	if err != nil || pi == nil || pi.Win.EPROCESS == 0 {
		return 0, false
	}
	return pi.Win.EPROCESS + uint64(e.recLinksOffset), true
}

// walkRing follows Flink from start until the ring closes (entries, true) or
// the walk dies — a non-canonical pointer, a failed read, or no closure
// within the bound (nil, false).
func (e *vmmEngine) walkRing(start uint64) ([]uint64, bool) {
	const maxRing = 8192
	entries := make([]uint64, 0, 512)
	entry := start
	for i := 0; i < maxRing; i++ {
		entries = append(entries, entry)
		f, err := e.vmm.MemRead(systemPID, entry, 8)
		if err != nil || len(f) < 8 {
			return nil, false
		}
		next := leU64(f)
		if next == start {
			return entries, true
		}
		if next < kernelVAFloor {
			return nil, false
		}
		entry = next
	}
	return nil, false
}

// headRingGate is PsActiveProcessHead's consume gate: the ring walked FROM
// the candidate head must close, be plausibly populated, and pass through the
// System process's own links entry. A wrong head — a stale stored RVA, a
// mislocated signature — fails here and is never consumed.
func (e *vmmEngine) headRingGate(head uint64) bool {
	sysEntry, ok := e.systemLinksEntry()
	if !ok {
		return false
	}
	entries, closed := e.walkRing(head)
	if !closed || len(entries) < 5 {
		return false
	}
	for _, en := range entries {
		if en == sysEntry {
			return true
		}
	}
	return false
}

// recoverProcessHead resolves PsActiveProcessHead. A stored RVA is gated and
// consumed; otherwise the head is recovered from the ring itself — every
// ActiveProcessLinks entry lives inside an _EPROCESS except the list head,
// which is a global in the kernel image, so the single ring entry inside the
// ntoskrnl span IS the head (§6 structural anchor, no signature needed). On
// an anchor recovery the head's signature is authored from this image into
// the writable signature store, so a later image whose build shares the code
// shape may locate it by pattern before its own ring is walked. Returns
// whether entry gained the global.
func (e *vmmEngine) recoverProcessHead(entry *symbols.StoreEntry) bool {
	if e.recHeadOK {
		return false // a stored signature already located and gated it
	}
	base, size, ok := e.kernelSpan()
	if !ok {
		return false
	}
	if rva, have := entry.Global(headGlobal); have && rva < size {
		if va := base + rva; e.headRingGate(va) {
			e.recHeadVA, e.recHeadOK = va, true
			return false
		}
		// base wins in the store; this image simply does not consume it.
		fmt.Fprintf(os.Stderr, "[anamnesis] stored %s RVA failed the ring gate — ignored for this image\n", headGlobal)
		return false
	}
	sysEntry, ok := e.systemLinksEntry()
	if !ok {
		return false
	}
	entries, closed := e.walkRing(sysEntry)
	if !closed {
		return false
	}
	var head uint64
	inModule := 0
	for _, en := range entries {
		if en > base && en-base < size {
			head = en
			inModule++
		}
	}
	if inModule != 1 {
		fmt.Fprintf(os.Stderr, "[anamnesis] ring anchor: %d in-module entries, want exactly 1 — %s not recovered\n", inModule, headGlobal)
		return false
	}
	e.recHeadVA, e.recHeadOK = head, true
	fmt.Fprintf(os.Stderr, "[anamnesis] recovered %s %#x (RVA %#x) via ring anchor\n", headGlobal, head, head-base)
	if e.fpOK {
		e.authorHeadSignature(head)
	}
	return symbols.MergeGlobal(entry, symbols.RecoveredGlobal{Name: headGlobal, RVA: head - base, Confidence: symbols.BestEffort})
}

// authorHeadSignature writes a masked signature for a code site that
// references the recovered head into the writable signature store — in-image
// authoring, the bridge from anchor recovery to build-time-style shipping. A
// window is accepted only when it is unique in this image and the applier
// resolves it back to the same head; wider windows are tried until one is.
func (e *vmmEngine) authorHeadSignature(head uint64) {
	image, base, ok := e.kernelImage()
	if !ok {
		return
	}
	dir := e.writableSigDir()
	if dir == "" {
		return
	}
	// One signature per authoring build: variants accumulate in the store and
	// the applier tries each, so lineages the cache has seen stay locatable.
	sigName := headGlobal + ".ref"
	if guid, age, err := e.kernelCodeView(); err == nil {
		sigName = fmt.Sprintf("%s.ref@%s-%d", headGlobal, guid, age)
	}
	for _, h := range symbols.RIPTargetAll(image, base) {
		if h.Target != head {
			continue
		}
		for _, win := range []int{24, 32, 40} {
			start := h.At - win
			if start < 0 {
				continue
			}
			sig, built := symbols.BuildSignatureAround(sigName, headGlobal, image[start:h.At], false)
			if !built {
				continue
			}
			_, off, found := symbols.MatchSignature(image, base, sig)
			if !found {
				continue
			}
			if _, _, dup := symbols.MatchSignature(image[off+1:], base+uint64(off)+1, sig); dup {
				continue
			}
			if va, applied := symbols.RecoverGlobalByFingerprint(image, base, sig); !applied || va != head {
				continue
			}
			if err := symbols.WriteSignature(dir, "ntoskrnl.exe", sig); err != nil {
				fmt.Fprintf(os.Stderr, "[anamnesis] signature store write failed: %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "[anamnesis] authored %s signature from the in-image anchor (site RVA %#x, %d-byte window)\n", headGlobal, uint64(start), win)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] no authorable reference site for %s in this image\n", headGlobal)
}

// _KDDEBUGGER_DATA64 field offsets this engine reads — stable across x64
// builds (the header is 0x18, then KernBase and the two authoritative list
// heads). kdbgReadLen covers every field consumed here.
const (
	kdbgKernBaseOff   = 0x18
	kdbgModuleListOff = 0x48
	kdbgProcHeadOff   = 0x50
	kdbgReadLen       = symbols.KdbgReadLen
)

// KDBG decode inputs, as store-global names. Only the block's own location is
// build-stable and cached; the wait keys are per-boot values re-read live, and
// KdpDataBlockEncoded contributes its address (not value) to the transform.
const (
	kdbgBlockGlobal    = "KdDebuggerDataBlock"
	kiWaitNeverGlobal  = "KiWaitNever"
	kiWaitAlwaysGlobal = "KiWaitAlways"
	kdpEncodedGlobal   = "KdpDataBlockEncoded"
)

// recoverKdbg locates and validates KdDebuggerDataBlock. A stored block RVA is
// re-validated and consumed; otherwise the block is found by structural scan
// (the unencoded case) or decoded with the wait keys (the encoded case, when a
// signature has supplied them). Every path ends at the same gate — the "KDBG"
// OwnerTag plus agreement with the independently recovered process head — so a
// wrong location or a wrong decode is discarded, never trusted. Returns
// whether the store gained the block's RVA.
func (e *vmmEngine) recoverKdbg(entry *symbols.StoreEntry) bool {
	base, size, ok := e.kernelSpan()
	if !ok {
		return false
	}
	if rva, have := entry.Global(kdbgBlockGlobal); have && rva < size {
		if e.readAndAcceptKdbg(base + rva) {
			return false // already stored
		}
	}
	// Unencoded structural scan (keyless): the block sits in ntoskrnl's data
	// with a plaintext "KDBG" tag when kernel debugging is enabled.
	image, imgBase, imgOK := e.kernelImage()
	sawRejected := false
	if imgOK {
		for from := 0; ; {
			off, found := symbols.ScanKdbgTag(image, from)
			if !found {
				break
			}
			blockVA := imgBase + uint64(off)
			if e.readAndAcceptKdbg(blockVA) {
				return symbols.MergeGlobal(entry, symbols.RecoveredGlobal{Name: kdbgBlockGlobal, RVA: blockVA - base, Confidence: symbols.BestEffort})
			}
			sawRejected = true // a "KDBG" tag that failed the plausibility/head gate
			from = off + 4
		}
	}
	// Encoded case, stored inputs first: decode with the wait keys when an
	// earlier sighting cached all four (per-boot key VALUES are re-read live).
	if e.decodeStoredKdbg(entry, base, size) {
		return false // the four input RVAs were already stored
	}
	// Encoded case, first sighting: recover the inputs keyless from the
	// kernel's own decoder routine, decode, and cache them.
	if dirty := e.recoverKdbgKeys(entry, base, size); e.recKdbgOK {
		return dirty
	}
	switch {
	case !imgOK:
		fmt.Fprintln(os.Stderr, "[anamnesis] KdDebuggerDataBlock not recovered: ntoskrnl image unreadable")
	case sawRejected:
		fmt.Fprintln(os.Stderr, "[anamnesis] KdDebuggerDataBlock not recovered: a \"KDBG\" tag was found but failed the plausibility/head gate")
	default:
		fmt.Fprintln(os.Stderr, "[anamnesis] KdDebuggerDataBlock not recovered: no unencoded block, and no KdCopyDataBlock site yielded a decode that passed the tag gate")
	}
	return false
}

// recoverKdbgKeys recovers the encoded-KDBG inputs with no keys and no
// signature, from the kernel's own decoder: KdCopyDataBlock is found by its
// KdpDataBlockEncoded flag test plus the transform's BSWAP, and its
// RIP-relative operands name the flag, the block, and the two wait keys. The
// two keys arrive unordered and the transform is asymmetric, so both
// assignments are tried — only the one whose decode recovers the "KDBG" tag
// (and passes the head cross-check) is consumed, and all four inputs then
// cache in the store as RVAs. Returns whether the store gained globals.
func (e *vmmEngine) recoverKdbgKeys(entry *symbols.StoreEntry, base, size uint64) bool {
	image, imgBase, ok := e.kernelImage()
	if !ok {
		return false
	}
	inSpan := func(va uint64) bool { return va > base && va-base < size }
	for _, site := range symbols.FindKdbgCopySites(image, imgBase) {
		if !inSpan(site.FlagVA) {
			continue
		}
		// The kernel's own flag says whether the block is encoded at all; a
		// decoded-in-place block was already consumed by the scan above.
		if flag, ok := e.readByte(site.FlagVA); !ok || flag != 1 {
			continue
		}
		for _, blockVA := range site.Blocks {
			if !inSpan(blockVA) {
				continue
			}
			enc, err := e.vmm.MemRead(systemPID, blockVA, kdbgReadLen)
			if err != nil || symbols.KdbgTagOK(enc) {
				continue // unreadable, or plaintext (the scan path's case)
			}
			for i, kn := range site.Keys {
				for j, ka := range site.Keys {
					if i == j || !inSpan(kn) || !inSpan(ka) {
						continue
					}
					never, ok1 := e.readQword(kn)
					always, ok2 := e.readQword(ka)
					if !ok1 || !ok2 {
						continue
					}
					dec := symbols.DecodeKdbg(enc, never, always, site.FlagVA)
					if !symbols.KdbgTagOK(dec) || !e.acceptKdbg(blockVA, dec, true) {
						continue
					}
					fmt.Fprintf(os.Stderr, "[anamnesis] recovered the KDBG wait keys from KdCopyDataBlock (keyless, in-image): KiWaitNever RVA %#x, KiWaitAlways RVA %#x\n", kn-base, ka-base)
					dirty := false
					for _, g := range []struct {
						name string
						va   uint64
					}{
						{kdbgBlockGlobal, blockVA},
						{kiWaitNeverGlobal, kn},
						{kiWaitAlwaysGlobal, ka},
						{kdpEncodedGlobal, site.FlagVA},
					} {
						if symbols.MergeGlobal(entry, symbols.RecoveredGlobal{Name: g.name, RVA: g.va - base, Confidence: symbols.BestEffort}) {
							dirty = true
						}
					}
					return dirty
				}
			}
		}
	}
	return false
}

// readByte reads one byte from memory.
func (e *vmmEngine) readByte(va uint64) (byte, bool) {
	b, err := e.vmm.MemRead(systemPID, va, 1)
	if err != nil || len(b) < 1 {
		return 0, false
	}
	return b[0], true
}

// readAndAcceptKdbg reads the block at blockVA from memory and validates it.
func (e *vmmEngine) readAndAcceptKdbg(blockVA uint64) bool {
	b, err := e.vmm.MemRead(systemPID, blockVA, kdbgReadLen)
	if err != nil {
		return false
	}
	return e.acceptKdbg(blockVA, b, false)
}

// acceptKdbg gates a candidate block (bytes as they will be consumed —
// natively unencoded, or decoded by us) on its "KDBG" tag and agreement with
// the ring-anchored PsActiveProcessHead, then records it. decodedByUs marks
// the encoded path for the log.
func (e *vmmEngine) acceptKdbg(blockVA uint64, b []byte, decodedByUs bool) bool {
	if len(b) < kdbgProcHeadOff+8 || !symbols.KdbgTagOK(b) {
		return false
	}
	kern := leU64(b[kdbgKernBaseOff:])
	modList := leU64(b[kdbgModuleListOff:])
	proc := leU64(b[kdbgProcHeadOff:])
	// The three authoritative pointers must be canonical kernel VAs. This is
	// the plausibility floor that stands in for the head cross-check when no
	// head was independently recovered, and a cheap extra guard when one was.
	if kern < kernelVAFloor || modList < kernelVAFloor || proc < kernelVAFloor {
		return false
	}
	if e.recHeadOK && proc != e.recHeadVA {
		fmt.Fprintf(os.Stderr, "[anamnesis] KDBG at %#x: PsActiveProcessHead %#x disagrees with the ring-anchor head %#x — rejected\n", blockVA, proc, e.recHeadVA)
		return false
	}
	e.recKdbgVA, e.recKdbgOK, e.recKdbgEncoded = blockVA, true, decodedByUs
	how := "unencoded"
	if decodedByUs {
		how = "decoded"
	}
	agree := " (PsActiveProcessHead is canonical; no ring-anchor head to cross-check)"
	if e.recHeadOK {
		agree = " (agrees with the ring-anchor head)"
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] KdDebuggerDataBlock %#x (%s): KernBase %#x, PsLoadedModuleList %#x, PsActiveProcessHead %#x%s\n",
		blockVA, how, kern, modList, proc, agree)
	return true
}

// decodeStoredKdbg decodes the encoded block using the four store globals a
// wait-key signature supplies: the block RVA, the two per-boot key values
// (read live from their RVAs), and KdpDataBlockEncoded's address. The decoded
// bytes go through the same gate as an unencoded block.
func (e *vmmEngine) decodeStoredKdbg(entry *symbols.StoreEntry, base, size uint64) bool {
	blockRVA, ok1 := entry.Global(kdbgBlockGlobal)
	neverRVA, ok2 := entry.Global(kiWaitNeverGlobal)
	alwaysRVA, ok3 := entry.Global(kiWaitAlwaysGlobal)
	encRVA, ok4 := entry.Global(kdpEncodedGlobal)
	if !(ok1 && ok2 && ok3 && ok4) || blockRVA >= size {
		return false
	}
	never, ok := e.readQword(base + neverRVA)
	if !ok {
		return false
	}
	always, ok := e.readQword(base + alwaysRVA)
	if !ok {
		return false
	}
	enc, err := e.vmm.MemRead(systemPID, base+blockRVA, kdbgReadLen)
	if err != nil {
		return false
	}
	dec := symbols.DecodeKdbg(enc, never, always, base+encRVA)
	return e.acceptKdbg(base+blockRVA, dec, true)
}

// readQword reads one little-endian uint64 from memory.
func (e *vmmEngine) readQword(va uint64) (uint64, bool) {
	b, err := e.vmm.MemRead(systemPID, va, 8)
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return leU64(b), true
}

// procPoolTag is the kernel pool tag on an _EPROCESS allocation.
var procPoolTag = [4]byte{'P', 'r', 'o', 'c'}

// Bounded pool-sweep tuning. The sweep ranges are planned from the enumerated
// processes' own pool headers and swept in two passes, core first: the core
// pass tightly covers every calibrated header (poolCoreMargin/poolCoreMergeGap
// — the parity set the cross-check depends on), the outer pass widens by
// poolSweepMargin and merges across gaps up to poolSweepMergeGap — hidden
// processes are allocated by the same pool backend into the same segments as
// the visible ones, so the widened hull is where they live. poolSweepCap
// bounds the total bytes swept (the plan self-shrinks under it);
// poolBackScanWindow bounds the per-process header search (the header sits a
// few chunks before the body). Time is bounded separately by the scan budget
// (poolScanBudget), spent core-first, because byte-bounded reads are not
// time-bounded: the same sweep measured 42s warm-cache and 300s+ cold on one
// crash dump (LeechCore seeks per page on a bitmap dump), and a scan slower
// than the stall watchdog would cost the whole collector.
const (
	poolCoreMargin     = 1 << 20
	poolCoreMergeGap   = 8 << 20
	poolSweepMargin    = 64 << 20
	poolSweepMergeGap  = 256 << 20
	poolSweepCap       = 8 << 30
	poolSweepChunk     = 1 << 20
	poolBackScanWindow = 0x200
)

// poolScanProcesses independently discovers process objects by kernel pool tag
// ("Proc"), a DKOM-resistant view: a process unlinked from ActiveProcessLinks
// or otherwise hidden from the normal walk still owns its tagged allocation.
// The enumeration is the engine's own bounded sweep — chunked MemReadEx over
// planned ranges, a tag match at pool-chunk alignment — never the MemProcFS
// pool map (GetPoolList), which deadlocks on some crash-dump images. Every
// read is byte-bounded and the sweep as a whole is time-budgeted, so the scan
// can sit on the default lane: it degrades loudly, never stalls the
// collector. Each candidate is
// TYPED via the recovered ObHeaderCookie (its _OBJECT_HEADER.TypeIndex must
// decode to the Process type index) and gated on a plausible PID, so a false
// hit — text or stale data echoing the tag — is discarded rather than
// reported. The result is cross-checked against the enumerated set; any
// header that resolves to a valid Process object the enumeration missed is
// returned and logged. A no-op without cookie typing or the PID offset — the
// gates that make a candidate trustworthy. Internal for now: the cross-check
// is evidence, not yet a user-visible field.
func (e *vmmEngine) poolScanProcesses() []uint64 {
	if !e.recObCookieOK || !e.recPIDOK {
		fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan skipped: candidate typing unavailable (ObHeaderCookie ok=%v, PID offset ok=%v)\n", e.recObCookieOK, e.recPIDOK)
		return nil
	}
	if len(e.epToProc) == 0 {
		fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan skipped: no enumerated processes to calibrate against\n")
		return nil
	}
	// Calibrate the header -> _EPROCESS body delta(s) off ground truth: each
	// enumerated process's own header is a bounded back-scan away from its
	// body (the offset is build-stable, and reading it needs no symbols).
	// accounted maps each header already tied to a known process.
	deltas := map[uint64]int{}
	accounted := map[uint64]bool{}
	for ep := range e.epToProc {
		if ep < kernelVAFloor {
			continue
		}
		b, ok := e.readPadded(ep-poolBackScanWindow, poolBackScanWindow)
		if !ok {
			continue
		}
		if d, ok := symbols.PoolBackScanDelta(b, ep, procPoolTag); ok {
			deltas[d]++
			accounted[ep-d] = true
		}
	}
	if len(deltas) == 0 {
		fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: no Proc header behind any of the %d enumerated _EPROCESS bodies — delta uncalibrated, scan skipped\n", len(e.epToProc))
		return nil
	}
	uncalibrated := len(e.epToProc) - len(accounted)
	dlist := make([]uint64, 0, len(deltas))
	for d := range deltas {
		dlist = append(dlist, d)
	}
	sort.Slice(dlist, func(i, j int) bool { return deltas[dlist[i]] > deltas[dlist[j]] })

	// Plan the sweep: a core pass tightly covering every calibrated header,
	// then the widened discovery hull minus what the core already covers.
	// The budget is spent in that order, so a slow image degrades to reduced
	// discovery margins — never to a failed cross-check or a stalled collector.
	headerVAs := make([]uint64, 0, len(accounted))
	for hva := range accounted {
		headerVAs = append(headerVAs, hva)
	}
	core, coreTruncated := symbols.PlanPoolSweep(headerVAs, poolCoreMargin, poolCoreMergeGap, poolSweepCap)
	full, fullTruncated := symbols.PlanPoolSweep(headerVAs, poolSweepMargin, poolSweepMergeGap, poolSweepCap)
	if coreTruncated || fullTruncated {
		fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: sweep plan exceeded the %d MiB cap and was cut short (core capped: %v) — coverage is partial\n", poolSweepCap>>20, coreTruncated)
	}
	outer := symbols.SubtractRanges(full, core)
	rangeBytes := func(rs []symbols.VARange) (n uint64) {
		for _, r := range rs {
			n += r.End - r.Start
		}
		return n
	}
	budget := poolScanBudget()
	var deadline time.Time
	if budget > 0 {
		deadline = time.Now().Add(budget)
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: sweeping core %d MiB + discovery %d MiB, budget %v (calibrated from %d headers, deltas %#x)\n",
		rangeBytes(core)>>20, rangeBytes(outer)>>20, budget, len(accounted), dlist)
	hits, sweptCore, partialCore := e.sweepPoolTag(core, procPoolTag, deadline)
	hitsOuter, sweptOuter, partialOuter := e.sweepPoolTag(outer, procPoolTag, deadline)
	hits = append(hits, hitsOuter...)
	if partialCore || partialOuter {
		fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: time budget %v expired after %d/%d MiB — coverage is partial, pool-only results incomplete (raise ANAMNESIS_POOLSCAN_BUDGET to sweep fully)\n",
			budget, (sweptCore+sweptOuter)>>20, rangeBytes(core)>>20+rangeBytes(outer)>>20)
	}

	// Classify: headers the enumeration accounts for confirm parity; the rest
	// are candidates that must survive typing and the PID gate.
	matched := 0
	var poolOnly []uint64
	for _, hva := range hits {
		if accounted[hva] {
			matched++
			continue
		}
		for _, d := range dlist {
			ep := hva + d
			if ep < kernelVAFloor {
				continue
			}
			if _, known := e.epToProc[ep]; known {
				break // an enumerated body whose header the calibration mislocated — not pool-only
			}
			if idx, ok := e.objTypeIndex(ep, e.recObCookie); !ok || idx != e.recProcTypeIdx {
				continue // not a Process object at this delta
			}
			if !e.plausiblePoolPID(ep) {
				continue
			}
			poolOnly = append(poolOnly, ep)
			break
		}
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan (bounded sweep, %d MiB swept): %d tag hits, %d/%d enumerated headers confirmed + %d pool-only Process objects (ObHeaderCookie-typed)\n",
		(sweptCore+sweptOuter)>>20, len(hits), matched, len(accounted), len(poolOnly))
	if uncalibrated > 0 {
		fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: %d enumerated processes had no locatable Proc header (unreadable or unheadered allocation) — outside the sweep's calibration\n", uncalibrated)
	}
	if matched < len(accounted) {
		if partialCore || partialOuter || coreTruncated {
			fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: %d calibrated headers were left unswept by the expired budget or the capped plan\n", len(accounted)-matched)
		} else {
			fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: %d calibrated headers were NOT rediscovered by a full sweep — coverage defect, treat pool-only results as incomplete\n", len(accounted)-matched)
		}
	}
	for _, ep := range poolOnly {
		pid := e.readDword(ep + uint64(e.recPIDOffset))
		fmt.Fprintf(os.Stderr, "[anamnesis]   pool-only process _EPROCESS %#x pid=%d — present in pool, absent from the enumerated set\n", ep, pid)
	}
	return poolOnly
}

// sweepPoolTag reads the planned ranges in bounded chunks (holes zero-padded,
// never fatal) and returns the ascending VAs of every chunk-aligned pool
// header matching tag, plus the bytes swept. Chunks overlap by one header so
// a boundary-straddling header is still seen; the overlap's duplicate hit is
// dropped. A non-zero deadline stops the sweep between chunks (partial=true):
// the reads are byte-bounded but not time-bounded, and the collector must
// never wait on this scan longer than the caller budgeted.
func (e *vmmEngine) sweepPoolTag(ranges []symbols.VARange, tag [4]byte, deadline time.Time) (hits []uint64, swept uint64, partial bool) {
	nextReport := uint64(256 << 20)
	start := time.Now()
	for _, r := range ranges {
		va := r.Start &^ uint64(symbols.PoolChunkAlign-1)
		for va < r.End {
			if !deadline.IsZero() && time.Now().After(deadline) {
				return hits, swept, true
			}
			n := uint64(poolSweepChunk)
			if va+n > r.End {
				n = r.End - va
			}
			b, ok := e.readPadded(va, uint32(n))
			if ok {
				for _, off := range symbols.ScanPoolTag(b, tag) {
					hva := va + uint64(off)
					if len(hits) > 0 && hits[len(hits)-1] == hva {
						continue // overlap duplicate
					}
					hits = append(hits, hva)
				}
			}
			swept += n
			if swept >= nextReport {
				fmt.Fprintf(os.Stderr, "[anamnesis] pool-tag scan: swept %d MiB in %s (%d hits so far)\n", swept>>20, time.Since(start).Round(time.Second), len(hits))
				nextReport += 256 << 20
			}
			if n <= symbols.PoolHeaderSize {
				break
			}
			va += n - symbols.PoolHeaderSize
		}
	}
	return hits, swept, false
}

// plausiblePoolPID reads a candidate _EPROCESS's PID through the recovered
// offset and requires a sane, 4-aligned, non-zero value — PIDs are multiples
// of 4 and never span the full 32 bits.
func (e *vmmEngine) plausiblePoolPID(ep uint64) bool {
	pid := e.readDword(ep + uint64(e.recPIDOffset))
	return pid != 0 && pid%4 == 0 && pid < 0x4000_0000
}

// readPadded reads [va, va+n) with unreadable pages zero-padded in place, so
// byte positions always correspond to VAs. The binding truncates the returned
// slice to the bytes actually READ, which cuts position-correct data after a
// mid-buffer hole — re-extend to the request length (VMMDLL wrote the whole
// zero-padded buffer). Paged retrieval is skipped (NoPagingIO): the pool
// content this reads is nonpaged, so a pagefile/compressed-store round trip
// can only cost time, never add data. ok=false when nothing was readable.
func (e *vmmEngine) readPadded(va uint64, n uint32) ([]byte, bool) {
	b, cb, err := e.vmm.MemReadEx(systemPID, va, n, mp.MemFlagZeroPadOnFail|mp.MemFlagNoPagingIO)
	if err != nil || cb == 0 {
		return nil, false
	}
	if uint32(cap(b)) >= n {
		b = b[:n]
	}
	return b, true
}

// imageNameAt reads the 15-byte _EPROCESS.ImageFileName at off — NUL-trimmed
// and required printable, "" otherwise. ep 0 means the System process (the
// consume gate's ground truth).
func (e *vmmEngine) imageNameAt(ep uint64, off uint32) string {
	if ep == 0 {
		pi, err := e.vmm.GetProcessInfo(systemPID)
		if err != nil || pi == nil {
			return ""
		}
		ep = pi.Win.EPROCESS
	}
	b, err := e.vmm.MemRead(systemPID, ep+uint64(off), 15)
	if err != nil || len(b) < 15 {
		return "" // a short read could pass a truncated name through the gate
	}
	n := 0
	for n < len(b) && b[n] != 0 {
		if b[n] < 0x20 || b[n] > 0x7E {
			return ""
		}
		n++
	}
	return string(b[:n])
}

// poolOnlyProcess builds a Process row for a pool-scanned _EPROCESS the
// enumeration missed — a DKOM-hidden process. There is no ProcessInfo to draw
// from, so every field is a direct read through the recovered offsets, each
// already System-gated at consume time; what does not decode stays honestly
// empty. The typing gates (poolScanProcesses) already confirmed the object.
func (e *vmmEngine) poolOnlyProcess(ep uint64) Process {
	p := Process{
		EPROCESS: ep, PoolOnly: true,
		ObjTypeChecked: true, ObjTypeConfirmed: true,
	}
	rec := []string{"detection=pool_scan"}
	p.PID = e.readDword(ep + uint64(e.recPIDOffset)) // gated non-zero by the scan
	if e.recPPIDOK {
		p.PPID = e.readDword(ep + uint64(e.recPPIDOffset))
	}
	if e.recImgOK {
		if name := e.imageNameAt(ep, e.recImgOffset); name != "" {
			p.Name = name
			rec = append(rec, "exe=eprocess")
		}
	}
	p.CreateTime = e.createTime(0, ep)
	p.ExitTime = e.exitTimeISO(ep)
	p.Terminated = p.ExitTime != ""
	if e.recTokenOK {
		if sid, method := e.tokenSID(ep); sid != "" {
			p.SID = sid
			rec = append(rec, "sid="+method)
			if u := e.userBySID[sid]; u != "" {
				p.User = u
				rec = append(rec, "user=userlist")
			}
		}
	}
	p.Recovery = strings.Join(rec, ";")
	return p
}

// readDword reads a little-endian uint32 at an absolute VA (System
// context), 0 on failure.
func (e *vmmEngine) readDword(va uint64) uint32 {
	b, err := e.vmm.MemRead(systemPID, va, 4)
	if err != nil || len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// harvestSignature builds a masked signature from a routine's leading bytes:
// the whole window is pinned except a conservative wildcard over the tail,
// where a RIP disp32 or an immediate is most likely to vary. Enough to prove
// the scanner; real cross-build signatures are hand-authored per routine.
func harvestSignature(name string, code []byte) symbols.Signature {
	n := len(code)
	if n > 16 {
		n = 16
	}
	pat := append([]byte(nil), code[:n]...)
	mask := make([]byte, n)
	for i := range mask {
		mask[i] = 0xFF
	}
	// Wildcard the last 4 bytes of the window (a likely disp32/immediate).
	for i := n - 4; i < n && i >= 0; i++ {
		mask[i] = 0x00
	}
	return symbols.Signature{Name: name, Pattern: pat, Mask: mask}
}

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
	return firstWritableDir(e.writableStoreCandidates())
}

// firstWritableDir returns the first directory in dirs that can be created
// and written (proven with a probe file, not assumed from a stat).
func firstWritableDir(dirs []string) string {
	for _, dir := range dirs {
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

// linkedPIDs walks ActiveProcessLinks and returns the PIDs on the ring
// (cached — the walk is per image, not per collector). With the recovered
// PsActiveProcessHead the walk starts at the authoritative head and the head
// entry itself (a kernel global, not inside an _EPROCESS) is excluded;
// without it the walk anchors on the System process and the head contributes
// one junk key — harmless, since the set is only queried for detected PIDs.
// nil when the offsets are unavailable or the walk does not close plausibly.
func (e *vmmEngine) linkedPIDs() map[uint32]bool {
	if e.linkedOnce {
		return e.linkedCache
	}
	e.linkedOnce = true
	if !e.recLinksOK || !e.recPIDOK {
		return nil
	}
	start, ok := e.systemLinksEntry()
	if !ok {
		return nil
	}
	anchor := "System"
	fromHead := e.recHeadOK
	if fromHead {
		start, anchor = e.recHeadVA, headGlobal
	}
	entries, closed := e.walkRing(start)
	if !closed {
		return nil // never closed — corrupt or wrong offset
	}
	out := make(map[uint32]bool, len(entries))
	for _, entry := range entries {
		if fromHead && entry == start {
			continue // the head is not an _EPROCESS
		}
		ep := entry - uint64(e.recLinksOffset)
		if b, rerr := e.vmm.MemRead(systemPID, ep+uint64(e.recPIDOffset), 8); rerr == nil && len(b) >= 8 {
			out[uint32(leU64(b))] = true
		}
	}
	if len(out) < 4 {
		return nil // implausibly small ring
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] active-list ring: %d linked processes (walked from %s)\n", len(out), anchor)
	e.linkedCache = out
	return out
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
