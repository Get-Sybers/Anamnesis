package symbols

import (
	"encoding/binary"
	"testing"
)

// buildDebugSection lays out, in one section based at baseRVA, an
// IMAGE_DEBUG_DIRECTORY entry (type 2, CODEVIEW) pointing at an RSDS record
// carrying the given raw GUID bytes and age. It returns a PEImage that reads
// from that section, exercising CodeView() without a full on-disk PE.
func buildDebugSection(t *testing.T, guid [16]byte, age uint32, rsdsMagic string) *PEImage {
	t.Helper()
	const baseRVA = 0x1000
	const dbgOff = 0x100 // debug dir within the section
	const rsdsOff = 0x200
	buf := make([]byte, 0x400)

	// IMAGE_DEBUG_DIRECTORY (28 bytes): Type at +12, SizeOfData at +16,
	// AddressOfRawData at +20.
	e := buf[dbgOff:]
	binary.LittleEndian.PutUint32(e[12:], 2) // CODEVIEW
	binary.LittleEndian.PutUint32(e[16:], 24)
	binary.LittleEndian.PutUint32(e[20:], baseRVA+rsdsOff)

	// RSDS record: magic, GUID[16], age[4].
	r := buf[rsdsOff:]
	copy(r[0:4], rsdsMagic)
	copy(r[4:20], guid[:])
	binary.LittleEndian.PutUint32(r[20:24], age)

	return &PEImage{
		sections:  []peSection{{va: baseRVA, size: uint32(len(buf)), data: buf}},
		debugRVA:  baseRVA + dbgOff,
		debugSize: 28,
	}
}

func TestCodeViewGUIDFormat(t *testing.T) {
	// Bytes chosen so the symbol-server string equals a value observed from a
	// real vmm run (FC57F1C8-41C2-C3F7 little-endian, 93D5… verbatim).
	guid := [16]byte{
		0xC8, 0xF1, 0x57, 0xFC, // Data1 LE -> FC57F1C8
		0xC2, 0x41, // Data2 LE -> 41C2
		0xF7, 0xC3, // Data3 LE -> C3F7
		0x93, 0xD5, 0x7A, 0xC1, 0x34, 0xDC, 0x0E, 0xFA, // Data4 verbatim
	}
	p := buildDebugSection(t, guid, 1, "RSDS")
	g, age, err := p.CodeView()
	if err != nil {
		t.Fatal(err)
	}
	if g != "FC57F1C841C2C3F793D57AC134DC0EFA" {
		t.Fatalf("guid = %q, want FC57F1C841C2C3F793D57AC134DC0EFA", g)
	}
	if age != 1 {
		t.Fatalf("age = %d, want 1", age)
	}
	// The formatted GUID must round-trip through the store filename unchanged
	// (the runtime key is exact-match on the lowered GUID).
	if fn := storeFileName(StoreKey{"ntoskrnl.exe", g, age}); fn != "ntoskrnl.exe-fc57f1c841c2c3f793d57ac134dc0efa-1.json" {
		t.Fatalf("store filename = %q", fn)
	}
}

func TestCodeViewRejectsNonRSDS(t *testing.T) {
	p := buildDebugSection(t, [16]byte{}, 1, "NB10")
	if _, _, err := p.CodeView(); err == nil {
		t.Fatal("a non-RSDS record must be rejected")
	}
	p2 := &PEImage{} // no debug directory
	if _, _, err := p2.CodeView(); err == nil {
		t.Fatal("absent debug directory must error")
	}
}
