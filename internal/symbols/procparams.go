package symbols

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// This file recovers a process's user-space parameter surface with no PDB
// (docs/design/symbol-recovery.md §6): the PEB's ProcessParameters pointer
// leads to _RTL_USER_PROCESS_PARAMETERS, where CurrentDirectory,
// ImagePathName, CommandLine and the Environment pointer sit at layout-stable
// offsets. The image path the engine already knows anchors the read — the
// candidate ImagePathName must match it — so a build-shifted or tampered
// layout yields nothing rather than a wrong value; the sibling fields are
// read relative to wherever the anchor was proven.

// MemReader yields bytes from a process's virtual address space. ok is false
// when nothing useful could be read; a shorter-than-requested slice is allowed
// when only the tail is unavailable (paged out).
type MemReader interface {
	ReadVirtual(va uint64, n uint32) ([]byte, bool)
}

// ProcParamsResult carries the recovered parameter-block fields, the
// ImagePathName they were validated against, and how they were obtained.
// CommandLine is the load-bearing field; Cwd and Env are best-effort
// siblings ("" when unreadable). Every method here is anchored or
// structurally validated single-view evidence — heuristic per §10, never
// definitive.
type ProcParamsResult struct {
	CommandLine string
	ImagePath   string
	Cwd         string
	Env         string // NUL-split environment block entries, newline-joined
	Method      string
	Confidence  Confidence
}

const (
	pebProcessParams64  = 0x20 // _PEB.ProcessParameters (x64, stable since XP)
	paramsCwd64         = 0x38 // _RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath
	paramsImagePath64   = 0x60 // .ImagePathName
	paramsCommandLine64 = 0x70 // adjacent CommandLine
	paramsEnv64         = 0x80 // .Environment (pointer)
	pebProcessParams32  = 0x10 // _PEB32.ProcessParameters
	paramsCwd32         = 0x24 // 32-bit CurrentDirectory.DosPath
	paramsImagePath32   = 0x38 // 32-bit ImagePathName
	paramsCommandLine32 = 0x40 // adjacent CommandLine
	paramsEnv32         = 0x48 // 32-bit Environment (pointer)
	paramsScanWindow    = 0x200
	maxUnicodeBytes     = 0x10000
	// envWindow caps how much of the environment block is read — typical
	// blocks are a few KB; the parse stops at the double-NUL terminator.
	envWindow = 0x8000
)

// RecoverProcParams walks the 64-bit PEB. anchorPath is the image path the
// engine already trusts ("" when unknown): with an anchor, ImagePathName must
// match it — first at the fixed +0x60/+0x70 offsets, then via a bounded scan
// of the parameter block; without one, the fixed offsets are accepted only
// when both strings validate structurally and the image path is path-shaped.
// Cwd and Env are then read relative to wherever the anchor was proven.
func RecoverProcParams(r MemReader, peb uint64, anchorPath string) (ProcParamsResult, bool) {
	if peb == 0 || !canonicalUser64(peb) {
		return ProcParamsResult{}, false
	}
	raw, ok := readFull(r, peb+pebProcessParams64, 8)
	if !ok {
		return ProcParamsResult{}, false
	}
	params := binary.LittleEndian.Uint64(raw)
	if !canonicalUser64(params) || params%8 != 0 {
		return ProcParamsResult{}, false
	}
	block, ok := readWindow(r, params, paramsScanWindow, paramsCommandLine64+0x10)
	if !ok {
		return ProcParamsResult{}, false
	}
	img, imgOK := unicodeString64(r, block, paramsImagePath64)
	if anchorPath == "" {
		// No anchor: structural validation only, lowest confidence.
		if !imgOK || !strings.ContainsAny(img, `\/`) {
			return ProcParamsResult{}, false
		}
		cl, ok := unicodeString64(r, block, paramsCommandLine64)
		if !ok {
			return ProcParamsResult{}, false
		}
		res := ProcParamsResult{CommandLine: cl, ImagePath: img, Method: "peb_fixed_unanchored", Confidence: BestEffort}
		fillSiblings64(r, block, paramsImagePath64, &res)
		return res, true
	}
	if imgOK && anchorMatch(img, anchorPath) {
		cl, ok := unicodeString64(r, block, paramsCommandLine64)
		if !ok {
			return ProcParamsResult{}, false
		}
		res := ProcParamsResult{CommandLine: cl, ImagePath: img, Method: "peb+0x60_anchor", Confidence: BestEffort}
		fillSiblings64(r, block, paramsImagePath64, &res)
		return res, true
	}
	// Fixed offsets disagreed with the anchor (a shifted build layout): scan the
	// block for the _UNICODE_STRING whose buffer IS the anchor; the siblings sit
	// at the same relative distances from it (§6). A scan miss returns nothing —
	// a failed anchor is a tamper signal, never a license to guess.
	for off := 0; off+paramsCommandLine64-paramsImagePath64+0x10 <= len(block); off += 8 {
		cand, ok := unicodeString64(r, block, off)
		if !ok || cand == "" || !anchorMatch(cand, anchorPath) {
			continue
		}
		cl, ok := unicodeString64(r, block, off+(paramsCommandLine64-paramsImagePath64))
		if !ok {
			continue
		}
		res := ProcParamsResult{CommandLine: cl, ImagePath: cand, Method: "peb_scan_anchor", Confidence: BestEffort}
		fillSiblings64(r, block, off, &res)
		return res, true
	}
	return ProcParamsResult{}, false
}

// fillSiblings64 best-effort reads CurrentDirectory and the environment block
// at their distances from the proven ImagePathName slot; a failure costs only
// that field.
func fillSiblings64(r MemReader, block []byte, imgOff int, res *ProcParamsResult) {
	if cwd, ok := unicodeString64(r, block, imgOff-(paramsImagePath64-paramsCwd64)); ok {
		res.Cwd = cwd
	}
	envOff := imgOff + (paramsEnv64 - paramsImagePath64)
	if envOff >= 0 && envOff+8 <= len(block) {
		if env := readEnvBlock(r, binary.LittleEndian.Uint64(block[envOff:]), canonicalUser64); env != "" {
			res.Env = env
		}
	}
}

// RecoverProcParams32 is the 32-bit walk (an x86 image, or a WoW64 process
// whose 64-bit PEB is unavailable): same anchoring, _UNICODE_STRING32 layout
// {u16 Length; u16 MaximumLength; u32 Buffer}.
func RecoverProcParams32(r MemReader, peb32 uint32, anchorPath string) (ProcParamsResult, bool) {
	if peb32 == 0 || !canonicalUser32(uint64(peb32)) {
		return ProcParamsResult{}, false
	}
	raw, ok := readFull(r, uint64(peb32)+pebProcessParams32, 4)
	if !ok {
		return ProcParamsResult{}, false
	}
	params := uint64(binary.LittleEndian.Uint32(raw))
	if !canonicalUser32(params) || params%4 != 0 {
		return ProcParamsResult{}, false
	}
	block, ok := readWindow(r, params, paramsScanWindow, paramsCommandLine32+0x8)
	if !ok {
		return ProcParamsResult{}, false
	}
	img, imgOK := unicodeString32(r, block, paramsImagePath32)
	if anchorPath == "" {
		if !imgOK || !strings.ContainsAny(img, `\/`) {
			return ProcParamsResult{}, false
		}
		cl, ok := unicodeString32(r, block, paramsCommandLine32)
		if !ok {
			return ProcParamsResult{}, false
		}
		res := ProcParamsResult{CommandLine: cl, ImagePath: img, Method: "peb32_fixed_unanchored", Confidence: BestEffort}
		fillSiblings32(r, block, paramsImagePath32, &res)
		return res, true
	}
	if imgOK && anchorMatch(img, anchorPath) {
		cl, ok := unicodeString32(r, block, paramsCommandLine32)
		if !ok {
			return ProcParamsResult{}, false
		}
		res := ProcParamsResult{CommandLine: cl, ImagePath: img, Method: "peb32+0x38_anchor", Confidence: BestEffort}
		fillSiblings32(r, block, paramsImagePath32, &res)
		return res, true
	}
	for off := 0; off+0x10 <= len(block); off += 4 {
		cand, ok := unicodeString32(r, block, off)
		if !ok || cand == "" || !anchorMatch(cand, anchorPath) {
			continue
		}
		cl, ok := unicodeString32(r, block, off+(paramsCommandLine32-paramsImagePath32))
		if !ok {
			continue
		}
		res := ProcParamsResult{CommandLine: cl, ImagePath: cand, Method: "peb32_scan_anchor", Confidence: BestEffort}
		fillSiblings32(r, block, off, &res)
		return res, true
	}
	return ProcParamsResult{}, false
}

func fillSiblings32(r MemReader, block []byte, imgOff int, res *ProcParamsResult) {
	if cwd, ok := unicodeString32(r, block, imgOff-(paramsImagePath32-paramsCwd32)); ok {
		res.Cwd = cwd
	}
	envOff := imgOff + (paramsEnv32 - paramsImagePath32)
	if envOff >= 0 && envOff+4 <= len(block) {
		if env := readEnvBlock(r, uint64(binary.LittleEndian.Uint32(block[envOff:])), canonicalUser32); env != "" {
			res.Env = env
		}
	}
}

// readEnvBlock reads the UTF-16 environment block at va (capped at envWindow)
// and joins its NUL-separated entries with newlines. The block ends at a
// double NUL; when the window ends first, only complete entries are kept.
func readEnvBlock(r MemReader, va uint64, canonical func(uint64) bool) string {
	if va == 0 || !canonical(va) || va%2 != 0 {
		return ""
	}
	raw, ok := r.ReadVirtual(va, envWindow)
	if !ok || len(raw) < 4 {
		return ""
	}
	return parseEnvBlock(raw)
}

// parseEnvBlock decodes a UTF-16LE environment block: entries separated by
// NUL, terminated by an empty entry. A truncated block (no terminator inside
// the window) yields its complete entries; a trailing fragment is dropped.
func parseEnvBlock(raw []byte) string {
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	var entries []string
	start := 0
	for i, w := range words {
		if w != 0 {
			continue
		}
		seg := words[start:i]
		if len(seg) == 0 {
			break // the double-NUL terminator
		}
		entries = append(entries, string(utf16.Decode(seg)))
		start = i + 1
	}
	// A fragment after the last NUL (window ended mid-entry) is never appended.
	return strings.Join(entries, "\n")
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
