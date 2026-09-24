package symbols

// Function fingerprinting locates a routine that has no export to resolve it
// by (docs/design/symbol-recovery.md §7/§8): a curated masked byte pattern of
// the routine's stable prologue/body is scanned across ntoskrnl's .text, and
// the RIP-relative operand at the match site names the global the routine
// reads. This is the same deterministic move as accessor disassembly and
// RecoverGlobalVA, with a pattern scan standing in for the export lookup.
//
// The signatures are hand-curated for the handful of globals the frontier
// transforms need, not a general FLIRT database: small, auditable, and each
// gated on consumption so a wrong match is discarded, never trusted.

// Signature is a masked byte pattern for one routine and the global its match
// site references. Mask marks which Pattern bytes must match exactly (0xFF)
// versus wildcards (0x00, for the RIP disp32, register nibbles, and any byte
// that varies across builds). Pattern and Mask are equal length; the RIP
// operand recovery starts at the match offset.
type Signature struct {
	Name        string `json:"name"`   // the routine, for logs (not resolvable by export)
	Global      string `json:"global"` // the global the match site references
	Pattern     []byte `json:"pattern"`
	Mask        []byte `json:"mask"`
	ByteOperand bool   `json:"byte_operand"` // prefer the byte-sized RIP reference (movzx/mov r8)
}

// BuildSignature derives a masked signature from a routine's leading bytes:
// it locates the routine's first RIP-relative operand (the reference to the
// named global), pins the whole window up to and including that instruction,
// and wildcards exactly the disp32 — the four bytes that move with the global
// across builds. This is what makes a harvested signature generalize: the code
// shape is pinned, the build-specific address is not. ok=false when no RIP
// operand is found in the window (nothing build-portable to key on).
func BuildSignature(name, global string, code []byte, byteOperand bool) (Signature, bool) {
	for _, h := range RIPTargetAll(code, 0) {
		if byteOperand && !h.Byte {
			continue
		}
		// h.At is the offset just past the instruction; the disp32 is the 4
		// bytes immediately before it.
		dispStart := h.At - 4
		if dispStart < 0 || h.At > len(code) {
			continue
		}
		pat := append([]byte(nil), code[:h.At]...)
		mask := make([]byte, h.At)
		for i := range mask {
			mask[i] = 0xFF
		}
		for i := dispStart; i < h.At; i++ {
			mask[i] = 0x00 // wildcard the RIP displacement
		}
		return Signature{Name: name, Global: global, Pattern: pat, Mask: mask, ByteOperand: byteOperand}, true
	}
	return Signature{}, false
}

// MatchSignature returns the VA and offset of the first place in text where
// sig's masked pattern matches. ok=false when the pattern is malformed or
// absent.
func MatchSignature(text []byte, textVA uint64, sig Signature) (matchVA uint64, off int, ok bool) {
	n := len(sig.Pattern)
	if n == 0 || n != len(sig.Mask) || n > len(text) {
		return 0, 0, false
	}
	for i := 0; i+n <= len(text); i++ {
		if matchAt(text[i:], sig.Pattern, sig.Mask) {
			return textVA + uint64(i), i, true
		}
	}
	return 0, 0, false
}

func matchAt(window, pattern, mask []byte) bool {
	for j := range pattern {
		if window[j]&mask[j] != pattern[j]&mask[j] {
			return false
		}
	}
	return true
}

// RecoverGlobalByFingerprint locates sig's routine in text and returns the
// virtual address of the global its match site references (the first
// RIP-relative operand at or after the match, byte-operand-preferring when
// sig.ByteOperand is set). ok=false when the routine is not found or carries
// no matching RIP reference — never a guessed address.
func RecoverGlobalByFingerprint(text []byte, textVA uint64, sig Signature) (globalVA uint64, ok bool) {
	matchVA, off, found := MatchSignature(text, textVA, sig)
	if !found {
		return 0, false
	}
	// Scan a bounded window from the match site — the RIP reference is within
	// the fingerprinted region, not the whole function.
	const window = 64
	end := off + window
	if end > len(text) {
		end = len(text)
	}
	for _, h := range RIPTargetAll(text[off:end], matchVA) {
		if sig.ByteOperand && !h.Byte {
			continue
		}
		return h.Target, true
	}
	return 0, false
}
