package symbols

import "testing"

func TestDecodeTypeIndex(t *testing.T) {
	// real = raw XOR (byte)(headerVA>>8) XOR cookie; must round-trip.
	const real = uint8(7)
	const cookie = uint8(0x9A)
	headerVA := uint64(0xffffd8_0b12_3400) // var: uint8() truncation is runtime, not a const conversion
	raw := real ^ uint8(headerVA>>8) ^ cookie
	if got := DecodeTypeIndex(raw, headerVA, cookie); got != real {
		t.Fatalf("DecodeTypeIndex = %d, want %d", got, real)
	}
}

// codeAt places a routine's bytes at a synthetic VA for RIP resolution.
type codeAt struct {
	code []byte
	va   uint64
}

func (c codeAt) FunctionCode(name string) ([]byte, uint64, error) { return c.code, c.va, nil }

func TestRIPTargetAllByteVsPointer(t *testing.T) {
	// lea rax,[rip+0x100]  (pointer-sized: 48 8D 05 00 01 00 00)
	// movzx eax,byte [rip+0x40] (byte-sized: 0F B6 05 40 00 00 00)
	code := []byte{
		0x48, 0x8D, 0x05, 0x00, 0x01, 0x00, 0x00,
		0x0F, 0xB6, 0x05, 0x40, 0x00, 0x00, 0x00,
	}
	hits := RIPTargetAll(code, 0x1000)
	if len(hits) != 2 {
		t.Fatalf("want 2 hits, got %d: %+v", len(hits), hits)
	}
	if hits[0].Byte {
		t.Errorf("lea hit must not be byte-sized")
	}
	if !hits[1].Byte {
		t.Errorf("movzx-byte hit must be byte-sized")
	}
	// end of first instruction (7) + disp 0x100
	if hits[0].Target != 0x1000+7+0x100 {
		t.Errorf("lea target = %#x", hits[0].Target)
	}
	// end of second instruction (14) + disp 0x40
	if hits[1].Target != 0x1000+14+0x40 {
		t.Errorf("movzx target = %#x", hits[1].Target)
	}
}

func TestRecoverGlobalVAPrefersByteOperand(t *testing.T) {
	// A routine that leas a table (pointer) then movzx-reads the byte cookie:
	// ByteOperand must skip the lea and return the cookie reference.
	code := []byte{
		0x48, 0x8D, 0x0D, 0x00, 0x20, 0x00, 0x00, // lea rcx,[rip+0x2000]  (table)
		0x0F, 0xB6, 0x05, 0x00, 0x10, 0x00, 0x00, // movzx eax,byte [rip+0x1000] (cookie)
	}
	src := codeAt{code: code, va: 0x40000}
	va, ok := RecoverGlobalVA(src, GlobalRef{Func: "ObGetObjectType", Global: "ObHeaderCookie", ByteOperand: true})
	if !ok {
		t.Fatal("expected a byte-operand hit")
	}
	if va != 0x40000+14+0x1000 {
		t.Fatalf("cookie VA = %#x, want %#x", va, 0x40000+14+0x1000)
	}
}
