package symbols

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildMFTRecord assembles a plausible 1 KiB FILE record: 48-byte header,
// USA fixups, resident $SI and $FN, terminator.
func buildMFTRecord(t *testing.T) []byte {
	t.Helper()
	rec := make([]byte, MFTRecordSize)
	copy(rec, "FILE")
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30) // UsaOffset
	binary.LittleEndian.PutUint16(rec[0x06:], 3)    // UsaCount (1 + 1024/512)
	binary.LittleEndian.PutUint16(rec[0x10:], 5)    // SequenceNumber
	binary.LittleEndian.PutUint16(rec[0x14:], 0x40) // AttrsOffset
	binary.LittleEndian.PutUint16(rec[0x16:], 0x1)  // Flags: in use
	binary.LittleEndian.PutUint32(rec[0x2C:], 843)  // RecordNumber

	// USA: USN 0xABCD, then the true words the sector tails carry.
	binary.LittleEndian.PutUint16(rec[0x30:], 0xABCD)
	binary.LittleEndian.PutUint16(rec[0x32:], 0x1111)
	binary.LittleEndian.PutUint16(rec[0x34:], 0x2222)

	off := 0x40
	// $STANDARD_INFORMATION: resident, content 0x30 at +0x18.
	binary.LittleEndian.PutUint32(rec[off:], 0x10)
	binary.LittleEndian.PutUint32(rec[off+4:], 0x48)
	binary.LittleEndian.PutUint32(rec[off+0x10:], 0x30)
	binary.LittleEndian.PutUint16(rec[off+0x14:], 0x18)
	c := off + 0x18
	binary.LittleEndian.PutUint64(rec[c:], 0x01D0000000000001)
	binary.LittleEndian.PutUint64(rec[c+8:], 0x01D0000000000002)
	binary.LittleEndian.PutUint64(rec[c+16:], 0x01D0000000000003)
	binary.LittleEndian.PutUint64(rec[c+24:], 0x01D0000000000004)
	off += 0x48

	// $FILE_NAME: resident, parent ref + times + name "a.txt" (Win32 ns).
	name := utf16.Encode([]rune("a.txt"))
	clen := 0x42 + 2*len(name)
	alen := (0x18 + clen + 7) &^ 7
	binary.LittleEndian.PutUint32(rec[off:], 0x30)
	binary.LittleEndian.PutUint32(rec[off+4:], uint32(alen))
	binary.LittleEndian.PutUint32(rec[off+0x10:], uint32(clen))
	binary.LittleEndian.PutUint16(rec[off+0x14:], 0x18)
	c = off + 0x18
	binary.LittleEndian.PutUint64(rec[c:], uint64(7)|uint64(2)<<48) // parent ref
	binary.LittleEndian.PutUint64(rec[c+8:], 0x01D0000000000005)
	rec[c+0x40] = byte(len(name))
	rec[c+0x41] = 1 // Win32 namespace
	for i, u := range name {
		binary.LittleEndian.PutUint16(rec[c+0x42+2*i:], u)
	}
	off += alen

	binary.LittleEndian.PutUint32(rec[off:], 0xFFFFFFFF)         // terminator
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(off+8))     // BytesInUse
	binary.LittleEndian.PutUint16(rec[mftSectorSize-2:], 0xABCD) // sector 1 tail = USN
	binary.LittleEndian.PutUint16(rec[MFTRecordSize-2:], 0xABCD) // sector 2 tail = USN
	_ = off
	return rec
}

func TestParseMFTRecord(t *testing.T) {
	rec := buildMFTRecord(t)
	e, ok := ParseMFTRecord(rec)
	if !ok {
		t.Fatal("valid record rejected")
	}
	if e.RecordNumber != 843 || e.Sequence != 5 {
		t.Fatalf("record/sequence = %d/%d, want 843/5", e.RecordNumber, e.Sequence)
	}
	if e.FileReference != uint64(843)|uint64(5)<<48 {
		t.Fatalf("file reference %#x, want entry|seq<<48", e.FileReference)
	}
	if !e.InUse || e.IsDir {
		t.Fatalf("flags: InUse=%v IsDir=%v", e.InUse, e.IsDir)
	}
	if e.Name != "a.txt" || e.ParentRef != uint64(7)|uint64(2)<<48 {
		t.Fatalf("name=%q parent=%#x", e.Name, e.ParentRef)
	}
	if e.SICreated != 0x01D0000000000001 || e.SIAccessed != 0x01D0000000000004 {
		t.Fatalf("$SI times: %#x %#x", e.SICreated, e.SIAccessed)
	}
	if e.FNCreated != 0x01D0000000000005 {
		t.Fatalf("$FN created: %#x", e.FNCreated)
	}
}

func TestParseMFTRecordFixedUpForm(t *testing.T) {
	// The cache manager's in-place form: no sector tail holds the USN — the
	// record must parse as-is, with no substitution.
	rec := buildMFTRecord(t)
	binary.LittleEndian.PutUint16(rec[mftSectorSize-2:], 0x1111)
	binary.LittleEndian.PutUint16(rec[MFTRecordSize-2:], 0x2222)
	e, ok := ParseMFTRecord(rec)
	if !ok || e.RecordNumber != 843 || e.Name != "a.txt" {
		t.Fatalf("fixed-up form must parse: ok=%v rec=%d name=%q", ok, e.RecordNumber, e.Name)
	}
}

func TestParseMFTRecordRejects(t *testing.T) {
	good := buildMFTRecord(t)

	torn := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(torn[mftSectorSize-2:], 0x9999) // one tail off, one == USN
	if _, ok := ParseMFTRecord(torn); ok {
		t.Error("torn record (mixed sector-tail forms) must be rejected")
	}

	zeroSeq := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(zeroSeq[0x10:], 0)
	if _, ok := ParseMFTRecord(zeroSeq); ok {
		t.Error("sequence 0 must be rejected")
	}

	badMagic := append([]byte(nil), good...)
	copy(badMagic, "BAAD")
	if _, ok := ParseMFTRecord(badMagic); ok {
		t.Error("wrong magic must be rejected")
	}

	if _, ok := ParseMFTRecord(good[:0x200]); ok {
		t.Error("short window must be rejected")
	}

	badUsa := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(badUsa[0x06:], 40) // implausible UsaCount
	if _, ok := ParseMFTRecord(badUsa); ok {
		t.Error("implausible USA count must be rejected")
	}
}
