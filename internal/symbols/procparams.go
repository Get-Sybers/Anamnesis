package symbols

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// This file recovers a process's command line from its own user-space
// structures with no PDB (docs/design/symbol-recovery.md §6): the PEB's
// ProcessParameters pointer leads to _RTL_USER_PROCESS_PARAMETERS, where
// ImagePathName and CommandLine sit as adjacent _UNICODE_STRINGs. The image
// path the engine already knows anchors the read — the candidate
// ImagePathName must match it — so a build-shifted or tampered layout yields
// nothing rather than a wrong value.

// MemReader yields bytes from a process's virtual address space. ok is false
// when nothing useful could be read; a shorter-than-requested slice is allowed
// when only the tail is unavailable (paged out).
type MemReader interface {
	ReadVirtual(va uint64, n uint32) ([]byte, bool)
}

// CommandLineResult carries a recovered command line, the ImagePathName it was
// validated against, and how it was obtained. Every method here is anchored or
// structurally validated single-view evidence — heuristic per §10, never
// definitive.
type CommandLineResult struct {
	CommandLine string
	ImagePath   string
	Method      string
	Confidence  Confidence
}

const (
	pebProcessParams64  = 0x20 // _PEB.ProcessParameters (x64, stable since XP)
	paramsImagePath64   = 0x60 // _RTL_USER_PROCESS_PARAMETERS.ImagePathName
	paramsCommandLine64 = 0x70 // adjacent CommandLine
	pebProcessParams32  = 0x10 // _PEB32.ProcessParameters
	paramsImagePath32   = 0x38 // _RTL_USER_PROCESS_PARAMETERS32.ImagePathName
	paramsCommandLine32 = 0x40 // adjacent CommandLine
	paramsScanWindow    = 0x200
	maxUnicodeBytes     = 0x10000
)

// RecoverCommandLine walks the 64-bit PEB. anchorPath is the image path the
// engine already trusts ("" when unknown): with an anchor, ImagePathName must
// match it — first at the fixed +0x60/+0x70 offsets, then via a bounded scan
// of the parameter block; without one, the fixed offsets are accepted only
// when both strings validate structurally and the image path is path-shaped.
func RecoverCommandLine(r MemReader, peb uint64, anchorPath string) (CommandLineResult, bool) {
	if peb == 0 || !canonicalUser64(peb) {
		return CommandLineResult{}, false
	}
	raw, ok := readFull(r, peb+pebProcessParams64, 8)
	if !ok {
		return CommandLineResult{}, false
	}
	params := binary.LittleEndian.Uint64(raw)
	if !canonicalUser64(params) || params%8 != 0 {
		return CommandLineResult{}, false
	}
	block, ok := readWindow(r, params, paramsScanWindow, paramsCommandLine64+0x10)
	if !ok {
		return CommandLineResult{}, false
	}
	img, imgOK := unicodeString64(r, block, paramsImagePath64)
	if anchorPath == "" {
		// No anchor: structural validation only, lowest confidence.
		if !imgOK || !strings.ContainsAny(img, `\/`) {
			return CommandLineResult{}, false
		}
		cl, ok := unicodeString64(r, block, paramsCommandLine64)
		if !ok {
			return CommandLineResult{}, false
		}
		return CommandLineResult{cl, img, "peb_fixed_unanchored", BestEffort}, true
	}
	if imgOK && anchorMatch(img, anchorPath) {
		cl, ok := unicodeString64(r, block, paramsCommandLine64)
		if !ok {
			return CommandLineResult{}, false
		}
		return CommandLineResult{cl, img, "peb+0x60_anchor", BestEffort}, true
	}
	// Fixed offsets disagreed with the anchor (a shifted build layout): scan the
	// block for the _UNICODE_STRING whose buffer IS the anchor; CommandLine is
	// the next one (§6). A scan miss returns nothing — a failed anchor is a
	// tamper signal, never a license to guess.
	for off := 0; off+paramsCommandLine64-paramsImagePath64+0x10 <= len(block); off += 8 {
		cand, ok := unicodeString64(r, block, off)
		if !ok || cand == "" || !anchorMatch(cand, anchorPath) {
			continue
		}
		cl, ok := unicodeString64(r, block, off+0x10)
		if !ok {
			continue
		}
		return CommandLineResult{cl, cand, "peb_scan_anchor", BestEffort}, true
	}
	return CommandLineResult{}, false
}

// RecoverCommandLine32 is the 32-bit walk (an x86 image, or a WoW64 process
// whose 64-bit PEB is unavailable): same anchoring, _UNICODE_STRING32 layout
// {u16 Length; u16 MaximumLength; u32 Buffer}.
func RecoverCommandLine32(r MemReader, peb32 uint32, anchorPath string) (CommandLineResult, bool) {
	if peb32 == 0 || !canonicalUser32(uint64(peb32)) {
		return CommandLineResult{}, false
	}
	raw, ok := readFull(r, uint64(peb32)+pebProcessParams32, 4)
	if !ok {
		return CommandLineResult{}, false
	}
	params := uint64(binary.LittleEndian.Uint32(raw))
	if !canonicalUser32(params) || params%4 != 0 {
		return CommandLineResult{}, false
	}
	block, ok := readWindow(r, params, paramsScanWindow, paramsCommandLine32+0x8)
	if !ok {
		return CommandLineResult{}, false
	}
	img, imgOK := unicodeString32(r, block, paramsImagePath32)
	if anchorPath == "" {
		if !imgOK || !strings.ContainsAny(img, `\/`) {
			return CommandLineResult{}, false
		}
		cl, ok := unicodeString32(r, block, paramsCommandLine32)
		if !ok {
			return CommandLineResult{}, false
		}
		return CommandLineResult{cl, img, "peb32_fixed_unanchored", BestEffort}, true
	}
	if imgOK && anchorMatch(img, anchorPath) {
		cl, ok := unicodeString32(r, block, paramsCommandLine32)
		if !ok {
			return CommandLineResult{}, false
		}
		return CommandLineResult{cl, img, "peb32+0x38_anchor", BestEffort}, true
	}
	for off := 0; off+0x10 <= len(block); off += 4 {
		cand, ok := unicodeString32(r, block, off)
		if !ok || cand == "" || !anchorMatch(cand, anchorPath) {
			continue
		}
		cl, ok := unicodeString32(r, block, off+0x8)
		if !ok {
			continue
		}
		return CommandLineResult{cl, cand, "peb32_scan_anchor", BestEffort}, true
	}
	return CommandLineResult{}, false
}

// unicodeString64 parses the _UNICODE_STRING header at block[off:] and decodes
// its buffer. ok with "" is a structurally valid empty string (Length 0).
func unicodeString64(r MemReader, block []byte, off int) (string, bool) {
	if off < 0 || off+16 > len(block) {
		return "", false
	}
	length := binary.LittleEndian.Uint16(block[off:])
	maxLen := binary.LittleEndian.Uint16(block[off+2:])
	buffer := binary.LittleEndian.Uint64(block[off+8:])
	return decodeUnicodeBuffer(r, length, maxLen, buffer, canonicalUser64)
}

func unicodeString32(r MemReader, block []byte, off int) (string, bool) {
	if off < 0 || off+8 > len(block) {
		return "", false
	}
	length := binary.LittleEndian.Uint16(block[off:])
	maxLen := binary.LittleEndian.Uint16(block[off+2:])
	buffer := uint64(binary.LittleEndian.Uint32(block[off+4:]))
	return decodeUnicodeBuffer(r, length, maxLen, buffer, canonicalUser32)
}

func decodeUnicodeBuffer(r MemReader, length, maxLen uint16, buffer uint64, canonical func(uint64) bool) (string, bool) {
	if length%2 != 0 || length > maxLen || uint32(maxLen) > maxUnicodeBytes {
		return "", false
	}
	if length == 0 {
		return "", true
	}
	if !canonical(buffer) || buffer%2 != 0 {
		return "", false
	}
	raw, ok := readFull(r, buffer, uint32(length))
	if !ok {
		return "", false
	}
	words := make([]uint16, length/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	s := string(utf16.Decode(words))
	// Length counts no terminator; an interior NUL means the buffer page was
	// zero-filled by a failed page read — reject rather than emit a fragment.
	if strings.ContainsRune(s, 0) {
		return "", false
	}
	return s, true
}

// anchorMatch compares a candidate ImagePathName against the trusted image
// path: equal after normalization, or equal once each side's DOS drive or NT
// device prefix is stripped (the two views of the same file differ only there).
func anchorMatch(candidate, anchor string) bool {
	a, b := normPath(candidate), normPath(anchor)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	sa, sb := stripDevice(a), stripDevice(b)
	return sa != "" && sa == sb
}

func normPath(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "/", `\`))
	return strings.TrimPrefix(s, `\??\`)
}

// stripDevice removes a leading DOS drive ("c:") or NT device
// ("\device\harddiskvolume2") so the path tails compare.
func stripDevice(s string) string {
	if len(s) >= 2 && s[1] == ':' && s[0] >= 'a' && s[0] <= 'z' {
		return s[2:]
	}
	if rest, ok := strings.CutPrefix(s, `\device\`); ok {
		if i := strings.IndexByte(rest, '\\'); i >= 0 {
			return rest[i:]
		}
		return ""
	}
	return s
}

// canonicalUser64 accepts a plausible x64 user-space pointer.
func canonicalUser64(va uint64) bool {
	return va >= 0x10000 && va < 0x0000_7fff_ffff_0000
}

// canonicalUser32 accepts a plausible 32-bit user-space pointer.
func canonicalUser32(va uint64) bool {
	return va >= 0x10000 && va < 0x7fff_0000
}

// readFull reads exactly n bytes or reports failure.
func readFull(r MemReader, va uint64, n uint32) ([]byte, bool) {
	b, ok := r.ReadVirtual(va, n)
	if !ok || uint32(len(b)) < n {
		return nil, false
	}
	return b[:n], true
}

// readWindow reads up to want bytes, accepting a shorter block as long as the
// first need bytes are present (the tail of the scan window may be paged out).
func readWindow(r MemReader, va uint64, want, need uint32) ([]byte, bool) {
	b, ok := r.ReadVirtual(va, want)
	if !ok || uint32(len(b)) < need {
		return nil, false
	}
	return b, true
}
