//go:build memprocfs

// The bounded carves (docs/design/symbol-recovery.md §3 sync-word scans, on
// the #38 principles: byte-bounded reads, a wall-clock budget, loud
// degradation, never the MemProcFS forensic subsystem — the deadlock lane):
// windows.mftscan carves cached $MFT FILE records out of physical memory with
// the full NTFS file reference, and windows.filescan discovers FILE_OBJECTs
// by "File" pool tag, calibrated and gated against the handle-enumerated
// ground truth exactly the way the process pool scan is.
package memprocfs

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	mp "github.com/sergeyzav/gomemprocfs"

	"anamnesis/internal/symbols"
)

// physPID is MemProcFS's physical-memory address space.
const physPID = 0xFFFFFFFF

const (
	mftCarveChunk = 16 << 20
	// mftCarveCap bounds the carved record count — an 8 GiB image can cache
	// enormous $MFT spans, and past this point the carve reports the cut
	// rather than exhausting memory.
	mftCarveCap = 200000
)

// MFT carves FILE records from physical memory: chunked reads over the
// physical ranges, the "FILE" magic tested at 1 KiB alignment, every hit
// parsed and fail-closed validated (USA fixups, header sanity). Each record
// yields its $STANDARD_INFORMATION and $FILE_NAME rows carrying the record
// number, the sequence number and the combined NTFS file reference. Records
// are deduplicated by reference (the same record can be cached in more than
// one page).
func (e *vmmEngine) MFT() ([]MFTRecord, error) {
	pm, err := e.vmm.GetPhysMem()
	if err != nil || pm == nil || len(pm.Entries) == 0 {
		fmt.Fprintf(os.Stderr, "[anamnesis] mft carve: physical memory map unavailable (err=%v) — carve skipped\n", err)
		return nil, nil
	}
	budget := scanBudget("ANAMNESIS_MFTSCAN_BUDGET")
	var deadline time.Time
	if budget > 0 {
		deadline = time.Now().Add(budget)
	}
	var total uint64
	for _, r := range pm.Entries {
		total += r.Size
	}
	seen := map[uint64]bool{}
	var out []MFTRecord
	var scanned uint64
	partial, capped := false, false

scan:
	for _, r := range pm.Entries {
		for off := uint64(0); off < r.Size; off += mftCarveChunk {
			if !deadline.IsZero() && time.Now().After(deadline) {
				partial = true
				break scan
			}
			n := uint64(mftCarveChunk)
			if off+n > r.Size {
				n = r.Size - off
			}
			b, cb, rerr := e.vmm.MemReadEx(physPID, r.BaseAddress+off, uint32(n), mp.MemFlagZeroPadOnFail)
			scanned += n
			if rerr != nil || cb == 0 {
				continue
			}
			if uint32(cap(b)) >= uint32(n) {
				b = b[:n] // the binding truncates to bytes read; the buffer is position-correct
			}
			for p := 0; p+symbols.MFTRecordSize <= len(b); p += symbols.MFTRecordSize {
				if !symbols.MFTRecordMagic(b[p:]) {
					continue
				}
				ent, ok := symbols.ParseMFTRecord(b[p : p+symbols.MFTRecordSize])
				if !ok || seen[ent.FileReference] {
					continue
				}
				if len(seen) >= mftCarveCap {
					capped = true
					break scan
				}
				seen[ent.FileReference] = true
				out = append(out, mftRows(ent, r.BaseAddress+off+uint64(p))...)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] mft carve: %d records (%d rows) from %d/%d MiB of physical memory\n",
		len(seen), len(out), scanned>>20, total>>20)
	if partial {
		fmt.Fprintf(os.Stderr, "[anamnesis] mft carve: time budget %v expired — coverage is partial (raise ANAMNESIS_MFTSCAN_BUDGET to carve fully)\n", budget)
	}
	if capped {
		fmt.Fprintf(os.Stderr, "[anamnesis] mft carve: record cap %d reached — results truncated\n", mftCarveCap)
	}
	return out, nil
}

// mftRows renders one parsed record as attribute rows (the collector's
// one-row-per-attribute shape), the identity triplet on each.
func mftRows(ent symbols.MFTEntry, pa uint64) []MFTRecord {
	kind := "File"
	if ent.IsDir {
		kind = "Directory"
	}
	if !ent.InUse {
		kind += " (deleted)"
	}
	base := MFTRecord{
		RecordNumber: int(ent.RecordNumber), SequenceNumber: int(ent.Sequence),
		FileReference: ent.FileReference, MFTType: kind,
		Filename: ent.Name, Offset: pa,
	}
	var rows []MFTRecord
	if ent.SICreated != 0 {
		r := base
		r.AttributeType = "STANDARD_INFORMATION"
		r.Created = carveTimeISO(ent.SICreated)
		r.Modified = carveTimeISO(ent.SIModified)
		r.Updated = carveTimeISO(ent.SIMFTModified)
		r.Accessed = carveTimeISO(ent.SIAccessed)
		rows = append(rows, r)
	}
	if ent.Name != "" {
		r := base
		r.AttributeType = "FILE_NAME"
		r.Created = carveTimeISO(ent.FNCreated)
		r.Modified = carveTimeISO(ent.FNModified)
		r.Updated = carveTimeISO(ent.FNMFTModified)
		r.Accessed = carveTimeISO(ent.FNAccessed)
		rows = append(rows, r)
	}
	return rows
}

// carveTimeISO renders a carved FILETIME, "" for zero or implausible values —
// carved bytes are candidates, so the plausibility bound always applies.
func carveTimeISO(ft uint64) string {
	if ft == 0 || !plausibleFileTime(ft) {
		return ""
	}
	return fileTimeToISO(ft)
}

// filePoolTag is the kernel pool tag on a FILE_OBJECT allocation.
var filePoolTag = [4]byte{'F', 'i', 'l', 'e'}

// fileNameOffCandidates brackets _FILE_OBJECT.FileName across builds; the
// real offset is calibrated from ground truth, never assumed.
const (
	fileNameOffLo = 0x30
	fileNameOffHi = 0xd8
)

// FileScan discovers FILE_OBJECTs by "File" pool tag — the DKOM-resistant
// file view: an object unreferenced by any handle still owns its tagged
// allocation. Everything is calibrated from the handle-enumerated ground
// truth (windows.anamnesis.files' objects): the ObHeaderCookie-decoded File
// type index by consensus, the FileName UNICODE_STRING offset by
// read-back agreement with the handles' own names, and the allocation→object
// delta by header back-scan. Candidates must type as File objects AND carry a
// plausible name before they are reported; the result is the pool-only set —
// objects present in pool, absent from every handle table.
func (e *vmmEngine) FileScan() ([]FileObject, error) {
	if !e.recObCookieOK {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan skipped: candidate typing unavailable (ObHeaderCookie)\n")
		return nil, nil
	}
	procs, err := e.Processes()
	if err != nil {
		return nil, err
	}
	known := map[uint64]string{}
	for i := range procs {
		if procs[i].PoolOnly {
			continue // no handle table to walk
		}
		hs, herr := e.Handles(procs[i].PID)
		if herr != nil {
			continue
		}
		for _, h := range hs {
			if h.Type == "File" && h.ObjectVA >= kernelVAFloor {
				known[h.ObjectVA] = h.Name
			}
		}
	}
	if len(known) < 8 {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan skipped: only %d handle-enumerated FILE_OBJECTs — not enough ground truth to calibrate\n", len(known))
		return nil, nil
	}
	// File type index by consensus over the ground truth.
	votes := map[uint8]int{}
	for va := range known {
		if idx, ok := e.objTypeIndex(va, e.recObCookie); ok {
			votes[idx]++
		}
	}
	fileIdx, best, second := uint8(0), 0, 0
	for idx, n := range votes {
		if n > best {
			fileIdx, best, second = idx, n, best
		} else if n > second {
			second = n
		}
	}
	if best < 8 || second*4 > best {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan skipped: File type index has no consensus (votes %v)\n", votes)
		return nil, nil
	}
	// FileName offset: the candidate offset where reading the UNICODE_STRING
	// back agrees with the handles' own names (the handle text is
	// device-prefixed, so suffix agreement is the test).
	fnOff, ok := e.calibrateFileNameOffset(known)
	if !ok {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan skipped: FileName offset uncalibrated against the handle ground truth\n")
		return nil, nil
	}
	// Allocation→object delta off ground truth, then the budgeted sweep —
	// the same machinery as the process pool scan.
	deltas := map[uint64]int{}
	accounted := map[uint64]bool{}
	for va := range known {
		b, rok := e.readPadded(va-poolBackScanWindow, poolBackScanWindow)
		if !rok {
			continue
		}
		if d, dok := symbols.PoolBackScanDelta(b, va, filePoolTag); dok {
			deltas[d]++
			accounted[va-d] = true
		}
	}
	if len(deltas) == 0 {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan: no File header behind any of the %d known FILE_OBJECTs — delta uncalibrated, scan skipped\n", len(known))
		return nil, nil
	}
	dlist := make([]uint64, 0, len(deltas))
	for d := range deltas {
		dlist = append(dlist, d)
	}
	sort.Slice(dlist, func(i, j int) bool { return deltas[dlist[i]] > deltas[dlist[j]] })
	headerVAs := make([]uint64, 0, len(accounted))
	for hva := range accounted {
		headerVAs = append(headerVAs, hva)
	}
	core, coreTruncated := symbols.PlanPoolSweep(headerVAs, poolCoreMargin, poolCoreMergeGap, poolSweepCap)
	full, fullTruncated := symbols.PlanPoolSweep(headerVAs, poolSweepMargin, poolSweepMergeGap, poolSweepCap)
	if coreTruncated || fullTruncated {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan: sweep plan exceeded the %d MiB cap and was cut short (core capped: %v) — coverage is partial\n", poolSweepCap>>20, coreTruncated)
	}
	outer := symbols.SubtractRanges(full, core)
	budget := scanBudget("ANAMNESIS_FILESCAN_BUDGET")
	var deadline time.Time
	if budget > 0 {
		deadline = time.Now().Add(budget)
	}
	hits, sweptCore, partialCore := e.sweepPoolTag(core, filePoolTag, deadline)
	hitsOuter, sweptOuter, partialOuter := e.sweepPoolTag(outer, filePoolTag, deadline)
	hits = append(hits, hitsOuter...)
	if partialCore || partialOuter {
		fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan: time budget %v expired after %d MiB — coverage is partial (raise ANAMNESIS_FILESCAN_BUDGET to sweep fully)\n", budget, (sweptCore+sweptOuter)>>20)
	}
	var out []FileObject
	matched := 0
	for _, hva := range hits {
		if accounted[hva] {
			matched++
			continue
		}
		for _, d := range dlist {
			obj := hva + d
			if obj < kernelVAFloor {
				continue
			}
			if _, isKnown := known[obj]; isKnown {
				break // a known object whose header the calibration mislocated
			}
			if idx, tok := e.objTypeIndex(obj, e.recObCookie); !tok || idx != fileIdx {
				continue
			}
			name, nok := e.readUnicodeString(obj + uint64(fnOff))
			if !nok {
				continue
			}
			out = append(out, FileObject{Offset: obj, Name: name})
			break
		}
	}
	fmt.Fprintf(os.Stderr, "[anamnesis] file pool scan (bounded sweep, %d MiB swept): %d tag hits, %d/%d known headers confirmed + %d pool-only FILE_OBJECTs (type index %d, FileName at +%#x)\n",
		(sweptCore+sweptOuter)>>20, len(hits), matched, len(accounted), len(out), fileIdx, fnOff)
	return out, nil
}

// calibrateFileNameOffset finds _FILE_OBJECT.FileName by reading candidate
// offsets on the ground-truth objects and requiring the decoded string to be
// the tail of the handle's own name on a majority of readable samples.
func (e *vmmEngine) calibrateFileNameOffset(known map[uint64]string) (uint32, bool) {
	type stat struct{ agree, readable int }
	stats := map[uint32]*stat{}
	sampled := 0
	for va, handleName := range known {
		if sampled >= 64 { // plenty for a majority; keeps calibration cheap
			break
		}
		sampled++
		for off := uint32(fileNameOffLo); off <= fileNameOffHi; off += 8 {
			s := stats[off]
			if s == nil {
				s = &stat{}
				stats[off] = s
			}
			name, ok := e.readUnicodeString(va + uint64(off))
			if !ok {
				continue
			}
			s.readable++
			if handleName != "" && strings.HasSuffix(strings.ToLower(handleName), strings.ToLower(name)) {
				s.agree++
			}
		}
	}
	bestOff, bestAgree := uint32(0), 0
	for off, s := range stats {
		if s.agree > bestAgree {
			bestOff, bestAgree = off, s.agree
		}
	}
	// The winner must agree on a real majority of the sampled objects.
	if bestAgree*2 < sampled || bestAgree < 4 {
		return 0, false
	}
	return bestOff, true
}

// readUnicodeString reads a UNICODE_STRING (Length, MaximumLength, Buffer) and
// its buffer, fail-closed on any implausibility: length bounds, a canonical
// kernel buffer pointer, and printable UTF-16 content.
func (e *vmmEngine) readUnicodeString(va uint64) (string, bool) {
	h, err := e.vmm.MemRead(systemPID, va, 16)
	if err != nil || len(h) < 16 {
		return "", false
	}
	length := uint32(h[0]) | uint32(h[1])<<8
	maxLen := uint32(h[2]) | uint32(h[3])<<8
	buf := leU64(h[8:])
	if length == 0 || length%2 != 0 || length > 0x400 || maxLen < length || buf < kernelVAFloor {
		return "", false
	}
	b, err := e.vmm.MemRead(systemPID, buf, length)
	if err != nil || uint32(len(b)) < length {
		return "", false
	}
	u := make([]uint16, length/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	for _, c := range u {
		if c < 0x20 {
			return "", false
		}
	}
	return string(utf16.Decode(u)), true
}
