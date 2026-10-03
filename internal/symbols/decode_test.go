package symbols

import "testing"

func TestAccessorDisplacement(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want int32
		ok   bool
	}{
		// mov rax,[rcx+0x440]; ret   — the PsGetProcessId shape.
		{"mov disp32", []byte{0x48, 0x8B, 0x81, 0x40, 0x04, 0x00, 0x00, 0xC3}, 0x440, true},
		// mov rax,[rcx+0x28]; ret     — disp8 form.
		{"mov disp8", []byte{0x48, 0x8B, 0x41, 0x28, 0xC3}, 0x28, true},
		// lea rax,[rcx+0x5a8]; ret    — PsGetProcessImageFileName shape.
		{"lea disp32", []byte{0x48, 0x8D, 0x81, 0xA8, 0x05, 0x00, 0x00, 0xC3}, 0x5A8, true},
		// movzx eax,byte [rcx+0x87a]  — byte field, no REX.
		{"movzx disp32", []byte{0x0F, 0xB6, 0x81, 0x7A, 0x08, 0x00, 0x00, 0xC3}, 0x87A, true},
		// endbr64 then mov rax,[rcx+0x448].
		{"endbr64 prologue", []byte{0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x8B, 0x81, 0x48, 0x04, 0x00, 0x00, 0xC3}, 0x448, true},
		// mov edi,edi hot-patch pad then mov rax,[rcx+0x30].
		{"movedi pad", []byte{0x8B, 0xFF, 0x48, 0x8B, 0x41, 0x30, 0xC3}, 0x30, true},
		// mov rax,[rcx]  — field at offset 0 (mod==00).
		{"offset zero", []byte{0x48, 0x8B, 0x01, 0xC3}, 0, true},
		// [rdx+0x10] — second-argument base is accepted too.
		{"rdx base", []byte{0x48, 0x8B, 0x42, 0x10, 0xC3}, 0x10, true},
		// bare ret — not a memory op.
		{"ret only", []byte{0xC3}, 0, false},
		// xor eax,eax; ret — computed getter, not a field read.
		{"xor eax", []byte{0x33, 0xC0, 0xC3}, 0, false},
		// RIP-relative operand must not be read as a struct offset.
		{"rip relative rejected", []byte{0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3}, 0, false},
	}
	for _, c := range cases {
		got, ok := AccessorDisplacement(c.code)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: got (%#x, %v), want (%#x, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestRIPTarget(t *testing.T) {
	// lea rcx,[rip+0x1234] at VA 0xFFFFF80001000000.
	// 48 8D 0D 34 12 00 00  (length 7) => target = VA + 7 + 0x1234.
	code := []byte{0x48, 0x8D, 0x0D, 0x34, 0x12, 0x00, 0x00, 0xC3}
	va := uint64(0xFFFFF80001000000)

	target, at, ok := RIPTarget(code, va)
	if !ok {
		t.Fatal("expected a RIP-relative match")
	}
	if want := va + 7 + 0x1234; target != want {
		t.Errorf("target = %#x, want %#x", target, want)
	}
	if at != 7 {
		t.Errorf("at = %d, want 7", at)
	}
}

func TestRIPTargetNegativeDisplacement(t *testing.T) {
	// mov rax,[rip-0x20] at VA 0x140001000.
	// 48 8B 05 E0 FF FF FF (length 7) => target = VA + 7 - 0x20.
	code := []byte{0x48, 0x8B, 0x05, 0xE0, 0xFF, 0xFF, 0xFF, 0xC3}
	va := uint64(0x140001000)

	target, _, ok := RIPTarget(code, va)
	if !ok {
		t.Fatal("expected a RIP-relative match")
	}
	if want := va + 7 - 0x20; target != want {
		t.Errorf("target = %#x, want %#x", target, want)
	}
}

func TestRIPTargetNoMatch(t *testing.T) {
	// A plain [rcx+disp] read has no RIP-relative operand.
	if _, _, ok := RIPTarget([]byte{0x48, 0x8B, 0x81, 0x00, 0x01, 0x00, 0x00, 0xC3}, 0x1000); ok {
		t.Error("did not expect a RIP-relative match")
	}
}
