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
