package symbols

import "testing"

func TestBuildSignatureMasksDisp(t *testing.T) {
	// movzx eax,byte [rip+0x1234] then ret: BuildSignature must pin the opcode
	// bytes and wildcard exactly the 4 disp bytes.
	code := []byte{0x0F, 0xB6, 0x05, 0x34, 0x12, 0x00, 0x00, 0xC3}
	sig, ok := BuildSignature("R", "G", code, true)
	if !ok {
		t.Fatal("expected a signature from a byte RIP operand")
	}
	// Pattern covers up to end-of-instruction (7 bytes), disp (offsets 3..6) masked.
	if len(sig.Pattern) != 7 || len(sig.Mask) != 7 {
		t.Fatalf("pattern/mask len = %d/%d, want 7", len(sig.Pattern), len(sig.Mask))
	}
	for i := 0; i < 3; i++ {
		if sig.Mask[i] != 0xFF {
			t.Errorf("opcode byte %d must be pinned", i)
		}
	}
	for i := 3; i < 7; i++ {
		if sig.Mask[i] != 0x00 {
			t.Errorf("disp byte %d must be wildcarded", i)
		}
	}
	// The harvested signature must still match the same bytes it came from, and
	// a build where only the disp differs.
	if !matchAt(code, sig.Pattern, sig.Mask) {
		t.Fatal("signature must match its own source bytes")
	}
	shifted := append([]byte(nil), code...)
	shifted[3], shifted[4] = 0xEF, 0xBE // different disp
	if !matchAt(shifted, sig.Pattern, sig.Mask) {
		t.Fatal("signature must match across a differing displacement")
	}
}

func TestBuildSignatureNoRIP(t *testing.T) {
	if _, ok := BuildSignature("R", "G", []byte{0x48, 0x8B, 0x01, 0xC3}, false); ok {
		t.Fatal("a routine with no RIP operand yields no signature")
	}
}

func TestSignatureStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sig := Signature{Name: "R", Global: "G", Pattern: []byte{1, 2, 3}, Mask: []byte{0xFF, 0, 0xFF}, ByteOperand: true}
	if err := WriteSignature(dir, "ntoskrnl.exe", sig); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSignatures(dir, "ntoskrnl.exe")
	if err != nil || len(got) != 1 || got[0].Global != "G" || got[0].ByteOperand != true {
		t.Fatalf("round trip = (%+v, %v)", got, err)
	}
	// Replace by Global, not duplicate.
	if err := WriteSignature(dir, "ntoskrnl.exe", Signature{Name: "R2", Global: "G", Pattern: []byte{9}, Mask: []byte{0xFF}}); err != nil {
		t.Fatal(err)
	}
	got, _ = ReadSignatures(dir, "ntoskrnl.exe")
	if len(got) != 1 || got[0].Name != "R2" {
		t.Fatalf("replace-by-global failed: %+v", got)
	}
}

func TestReadSignaturesAbsent(t *testing.T) {
	got, err := ReadSignatures(t.TempDir(), "ntoskrnl.exe")
	if err != nil || got != nil {
		t.Fatalf("absent sig file must be (nil, nil): (%+v, %v)", got, err)
	}
}

func TestBuildSignatureAround(t *testing.T) {
	// A scan-found site: leading context bytes, then lea rax,[rip+disp] whose
	// disp32 are the window's last four bytes.
	window := []byte{0x90, 0x90, 0x48, 0x8D, 0x05, 0x11, 0x22, 0x33, 0x44}
	sig, ok := BuildSignatureAround("R.ref", "G", window, false)
	if !ok || len(sig.Pattern) != len(window) {
		t.Fatalf("signature = (%+v, %v)", sig, ok)
	}
	for i := 0; i < len(window)-4; i++ {
		if sig.Mask[i] != 0xFF {
			t.Errorf("context byte %d must be pinned", i)
		}
	}
	for i := len(window) - 4; i < len(window); i++ {
		if sig.Mask[i] != 0x00 {
			t.Errorf("disp byte %d must be wildcarded", i)
		}
	}
	// Must match a build where only the displacement differs.
	other := append([]byte(nil), window...)
	other[len(other)-4], other[len(other)-1] = 0xAA, 0xBB
	if !matchAt(other, sig.Pattern, sig.Mask) {
		t.Fatal("signature must match across a differing displacement")
	}
	if _, ok := BuildSignatureAround("R", "G", window[:7], false); ok {
		t.Fatal("a window too short to carry context + disp32 yields no signature")
	}
}
