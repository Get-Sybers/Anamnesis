package symbols

import (
	"encoding/binary"
	"testing"
)

func TestKdbgEntryRoundTrip(t *testing.T) {
	// Boot-random keys and a canonical KdpDataBlockEncoded address.
	const (
		never  = 0x8642097531FEDCBA
		always = 0x0F1E2D3C4B5A6978
		encVA  = 0xFFFFF80312345678
	)
	for _, plain := range []uint64{0, 1, 0x4742444B, 0xFFFFF8031861DF80, 0xDEADBEEFCAFEF00D} {
		enc := EncodeKdbgEntry(plain, never, always, encVA)
		if got := DecodeKdbgEntry(enc, never, always, encVA); got != plain {
			t.Fatalf("round trip %#x -> enc %#x -> %#x", plain, enc, got)
		}
	}
	// Encoding must actually transform (not identity) for a nonzero value.
	if EncodeKdbgEntry(0x1234, never, always, encVA) == 0x1234 {
		t.Fatal("encode produced identity")
	}
}

func TestDecodeKdbgRecoversTag(t *testing.T) {
	const (
		never  = 0x1122334455667788
		always = 0x99AABBCCDDEEFF00
		encVA  = 0xFFFFF80300ABCDE0
	)
	// A minimal block: 16-byte LIST_ENTRY, then OwnerTag "KDBG" + Size.
	plain := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(plain[kdbgOwnerTagOffset:], KdbgOwnerTag)
	binary.LittleEndian.PutUint32(plain[kdbgOwnerTagOffset+4:], 0x360)
	if !KdbgTagOK(plain) {
		t.Fatal("plaintext block must validate")
	}
	// Encode every entry, then a full decode must recover the tag.
	enc := make([]byte, len(plain))
	for i := 0; i+8 <= len(plain); i += 8 {
		v := binary.LittleEndian.Uint64(plain[i:])
		binary.LittleEndian.PutUint64(enc[i:], EncodeKdbgEntry(v, never, always, encVA))
	}
	if KdbgTagOK(enc) {
		t.Fatal("encoded block must NOT read as KDBG")
	}
	dec := DecodeKdbg(enc, never, always, encVA)
	if !KdbgTagOK(dec) {
		t.Fatalf("decoded block failed the tag gate: OwnerTag=%#x", binary.LittleEndian.Uint32(dec[kdbgOwnerTagOffset:]))
	}
}

func TestKdbgTagRejectsWrongKeys(t *testing.T) {
	const never, always, encVA = 0xAAAA, 0xBBBB, 0xFFFFF80300000000
	plain := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(plain[kdbgOwnerTagOffset:], KdbgOwnerTag)
	binary.LittleEndian.PutUint32(plain[kdbgOwnerTagOffset+4:], 0x360)
	enc := make([]byte, len(plain))
	for i := 0; i+8 <= len(plain); i += 8 {
		binary.LittleEndian.PutUint64(enc[i:], EncodeKdbgEntry(binary.LittleEndian.Uint64(plain[i:]), never, always, encVA))
	}
	// A single wrong key must leave the tag gate failing — the built-in proof.
	if KdbgTagOK(DecodeKdbg(enc, never+1, always, encVA)) {
		t.Fatal("wrong KiWaitNever must not decode to a valid tag")
	}
	if KdbgTagOK(DecodeKdbg(enc, never, always, encVA+8)) {
		t.Fatal("wrong KdpDataBlockEncoded address must not decode to a valid tag")
	}
}

func TestFindKdbgCopySites(t *testing.T) {
	// A synthetic KdCopyDataBlock: the flag test, the block LEA, the two key
	// loads (Win8-style MOV + Win8.1-style XOR), the transform's BSWAP, RET.
	code := []byte{
		0x80, 0x3D, 0x10, 0x00, 0x00, 0x00, 0x00, // cmp byte [rip+0x10], 0
		0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00, // lea rax, [rip+0x20]      -> block
		0x4C, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00, // mov r10, [rip+0x30]      -> key
		0x48, 0x33, 0x15, 0x40, 0x00, 0x00, 0x00, // xor rdx, [rip+0x40]      -> key
		0x48, 0x0F, 0xC8, // bswap rax
		0xC3, // ret
	}
	const base = 0x1000
	sites := FindKdbgCopySites(code, base)
	if len(sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(sites))
	}
	s := sites[0]
	if s.FlagVA != base+7+0x10 {
		t.Errorf("FlagVA = %#x, want %#x", s.FlagVA, base+7+0x10)
	}
	if len(s.Blocks) != 1 || s.Blocks[0] != base+14+0x20 {
		t.Errorf("Blocks = %#x, want [%#x]", s.Blocks, base+14+0x20)
	}
	if len(s.Keys) != 2 || s.Keys[0] != base+21+0x30 || s.Keys[1] != base+28+0x40 {
		t.Errorf("Keys = %#x, want [%#x %#x]", s.Keys, base+21+0x30, base+28+0x40)
	}
}

func TestFindKdbgCopySitesNeedsBswap(t *testing.T) {
	// The same shape minus the BSWAP must not qualify — the flag CMP alone is
	// far too common in the kernel.
	code := []byte{
		0x80, 0x3D, 0x10, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00,
		0x4C, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00,
		0x48, 0x33, 0x15, 0x40, 0x00, 0x00, 0x00,
		0xC3,
	}
	if sites := FindKdbgCopySites(code, 0x1000); len(sites) != 0 {
		t.Fatalf("a window without BSWAP must not qualify: %+v", sites)
	}
}
