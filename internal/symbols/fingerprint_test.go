package symbols

import "testing"

func TestMatchSignatureMaskedHit(t *testing.T) {
	// A routine prologue with a wildcarded middle byte; the mask must let the
	// varying byte through while pinning the rest.
	text := []byte{
		0x00, 0x00, // leading noise
		0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0xC3, // mov rax,[rip+disp]; ret
	}
	sig := Signature{
		Name:    "R",
		Pattern: []byte{0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3},
		Mask:    []byte{0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF}, // disp32 wildcarded
	}
	va, off, ok := MatchSignature(text, 0x1000, sig)
	if !ok || off != 2 || va != 0x1002 {
		t.Fatalf("match = (va=%#x off=%d ok=%v), want (0x1002, 2, true)", va, off, ok)
	}
}

func TestMatchSignatureMaskRejectsNearMiss(t *testing.T) {
	text := []byte{0x48, 0x8B, 0x06, 0x11, 0x22, 0x33, 0x44, 0xC3} // 0x8B 0x06, not 0x05
	sig := Signature{
		Pattern: []byte{0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3},
		Mask:    []byte{0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF},
	}
	if _, _, ok := MatchSignature(text, 0x1000, sig); ok {
		t.Fatal("a pinned byte mismatch must not match")
	}
}

func TestRecoverGlobalByFingerprint(t *testing.T) {
	// mov rax,[rip+0x100]  (48 8B 05 00 01 00 00) — global at end-of-insn + disp.
	text := []byte{0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00, 0xC3}
	sig := Signature{
		Name: "R", Global: "SomeGlobal",
		Pattern: []byte{0x48, 0x8B, 0x05},
		Mask:    []byte{0xFF, 0xFF, 0xFF},
	}
	va, ok := RecoverGlobalByFingerprint(text, 0x40000, sig)
	if !ok || va != 0x40000+7+0x100 {
		t.Fatalf("global VA = %#x, want %#x", va, 0x40000+7+0x100)
	}
}

func TestRecoverGlobalByFingerprintNoMatch(t *testing.T) {
	text := []byte{0x90, 0x90, 0x90, 0x90}
	sig := Signature{Pattern: []byte{0x48, 0x8B, 0x05}, Mask: []byte{0xFF, 0xFF, 0xFF}}
	if _, ok := RecoverGlobalByFingerprint(text, 0x1000, sig); ok {
		t.Fatal("absent routine must not yield a global")
	}
}
