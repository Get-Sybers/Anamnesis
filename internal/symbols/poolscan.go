package symbols

// Deadlock-safe kernel-pool tag scanning (docs/design/symbol-recovery.md §3,
// the sync-word/magic scan): find pool-tagged allocations out of raw bytes
// with no pool subsystem, no type database and no unbounded native call. The
// engine reads memory in bounded chunks and these helpers do the byte-level
// work — matching a _POOL_HEADER tag at chunk alignment, locating the header
// behind a known allocation body (delta calibration off ground truth), and
// planning which virtual ranges to sweep from the addresses the enumeration
// already proved live. Every false hit is harmless by design: the engine
// gates each candidate on object-header typing and field plausibility.

import (
	"bytes"
	"sort"
)

// _POOL_HEADER geometry, stable across every 64-bit Windows build: the header
// is 0x10 bytes, pool chunks are 0x10-aligned, and the 4-byte PoolTag sits at
// header+0x04. The tag's top bit (byte 3 & 0x80) is the PROTECTED_POOL
// marker — set on process allocations on many builds — so it is masked, never
// matched. Later builds move small allocations into the segment heap's LFH
// (no per-allocation header), but every allocation the size of a process
// object keeps its _POOL_HEADER.
const (
	// PoolHeaderSize is sizeof(_POOL_HEADER) on x64.
	PoolHeaderSize = 0x10
	// PoolChunkAlign is the alignment of every pool chunk (and so of every
	// header and every allocation body) on x64.
	PoolChunkAlign = 0x10
	// poolTagOff is the PoolTag offset inside _POOL_HEADER.
	poolTagOff = 0x04
	// poolProtectedBit marks a protected allocation in the tag's last byte.
	poolProtectedBit = 0x80
)

// PoolTagMatch reports whether the four bytes at b hold tag, with the
// PROTECTED_POOL bit masked on both sides.
func PoolTagMatch(b []byte, tag [4]byte) bool {
	return len(b) >= 4 &&
		b[0] == tag[0] && b[1] == tag[1] && b[2] == tag[2] &&
		b[3]&^poolProtectedBit == tag[3]&^poolProtectedBit
}

// ScanPoolTag returns the buffer offset of every chunk-aligned _POOL_HEADER
// in buf whose PoolTag matches tag (protected bit masked). buf must start at
// a chunk-aligned address so buffer offsets are chunk offsets; the returned
// offsets ascend. A hit is a candidate, not a verdict — text and stale data
// can echo a tag, and the caller's typing gates decide.
func ScanPoolTag(buf []byte, tag [4]byte) []int {
	var hits []int
	needle := tag[:3]
	for i := 0; ; {
		j := bytes.Index(buf[i:], needle)
		if j < 0 {
			return hits
		}
		p := i + j
		if p%PoolChunkAlign == poolTagOff && p+4 <= len(buf) &&
			buf[p+3]&^poolProtectedBit == tag[3]&^poolProtectedBit {
			hits = append(hits, p-poolTagOff)
		}
		i = p + 1
	}
}

// PoolBackScanDelta locates the nearest matching pool header preceding an
// allocation body: window holds the bytes immediately before the body (its
// last byte is body-1, endVA is the body's address), and the result is the
// body's delta from its header — the calibration constant the sweep applies
// to turn a scanned header into a candidate object address. ok=false when no
// header is in the window.
func PoolBackScanDelta(window []byte, endVA uint64, tag [4]byte) (uint64, bool) {
	startVA := endVA - uint64(len(window))
	o := int((PoolChunkAlign - startVA%PoolChunkAlign) % PoolChunkAlign)
	best := -1
	for ; o+PoolHeaderSize <= len(window); o += PoolChunkAlign {
		if PoolTagMatch(window[o+poolTagOff:], tag) {
			best = o
		}
	}
	if best < 0 {
		return 0, false
	}
	return endVA - (startVA + uint64(best)), true
}

// VARange is a half-open virtual address range [Start, End).
type VARange struct{ Start, End uint64 }

// PlanPoolSweep turns a set of known-live allocation addresses into bounded,
// merged sweep ranges: each address is widened by margin on both sides,
// ranges closer than mergeGap coalesce, and the plan self-shrinks (halving
// margin, then mergeGap) until the total stays under totalCap. The ranges
// cover every input address whenever truncated is false; truncated=true means
// even the minimal plan exceeded the cap and was cut short — the caller must
// say so loudly. Returned ranges are sorted, disjoint and chunk-aligned.
func PlanPoolSweep(vas []uint64, margin, mergeGap, totalCap uint64) (ranges []VARange, truncated bool) {
	if len(vas) == 0 {
		return nil, false
	}
	sorted := append([]uint64(nil), vas...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	build := func(margin, mergeGap uint64) ([]VARange, uint64) {
		var out []VARange
		var total uint64
		for _, va := range sorted {
			start := (va - margin) &^ uint64(PoolChunkAlign-1)
			if start > va { // underflow
				start = 0
			}
			end := va + margin + PoolChunkAlign
			if end < va { // overflow
				end = ^uint64(0)
			}
			if n := len(out); n > 0 && start <= out[n-1].End+mergeGap {
				if end > out[n-1].End {
					total += end - out[n-1].End
					out[n-1].End = end
				}
				continue
			}
			out = append(out, VARange{start, end})
			total += end - start
		}
		return out, total
	}

	for {
		out, total := build(margin, mergeGap)
		if total <= totalCap {
			return out, false
		}
		switch {
		case margin > 0:
			margin /= 2
		case mergeGap > 0:
			mergeGap /= 2
		default:
			// Minimal plan still over the cap: keep ranges in order until the
			// budget runs out and report the cut.
			var kept []VARange
			var used uint64
			for _, r := range out {
				n := r.End - r.Start
				if used+n > totalCap {
					break
				}
				kept = append(kept, r)
				used += n
			}
			return kept, true
		}
	}
}

// SubtractRanges returns the parts of a not covered by b. Both inputs must be
// sorted and disjoint (as PlanPoolSweep returns them); so is the result. It
// lets a second sweep pass skip everything a first pass already covered.
func SubtractRanges(a, b []VARange) []VARange {
	var out []VARange
	j := 0
	for _, r := range a {
		start := r.Start
		for j < len(b) && b[j].End <= start {
			j++
		}
		k := j
		for k < len(b) && b[k].Start < r.End {
			if b[k].Start > start {
				out = append(out, VARange{start, b[k].Start})
			}
			if b[k].End > start {
				start = b[k].End
			}
			k++
		}
		if start < r.End {
			out = append(out, VARange{start, r.End})
		}
	}
	return out
}
