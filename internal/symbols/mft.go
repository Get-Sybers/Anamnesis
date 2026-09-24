package symbols

// NTFS FILE-record parsing for the in-memory $MFT carve (the §3 sync-word
// scan applied to the "FILE" magic): cached $MFT pages sit in RAM, records
// are 1 KiB at 1 KiB alignment within a page, and every field the disk lane
// keys on — the record number, the SEQUENCE number (together the full NTFS
// file reference), the $STANDARD_INFORMATION and $FILE_NAME timestamps and
// the name — parses out of fixed layouts with no type database. Everything
// fails closed: a torn or repurposed page is rejected, never misparsed.

import (
	"encoding/binary"
	"unicode/utf16"
)

// MFTRecordSize is the classic FILE record size; records sit at this
// alignment inside cached $MFT pages (a 4 KiB page holds four).
const MFTRecordSize = 0x400

// mftSectorSize is the update-sequence stride: the last two bytes of every
// 512-byte sector are fixed up through the update sequence array.
const mftSectorSize = 512

// MFTEntry is one parsed FILE record — the identity fields plus both
// timestamp sets and the (non-DOS) name.
type MFTEntry struct {
	RecordNumber  uint32
	Sequence      uint16
	FileReference uint64 // RecordNumber | Sequence<<48 — the disk lane's key
	InUse         bool
	IsDir         bool
	Name          string
	ParentRef     uint64
	// $STANDARD_INFORMATION FILETIMEs (0 = absent).
	SICreated, SIModified, SIMFTModified, SIAccessed uint64
	// $FILE_NAME FILETIMEs (0 = absent).
	FNCreated, FNModified, FNMFTModified, FNAccessed uint64
}

// MFTRecordMagic reports whether b starts with the FILE record signature —
// the cheap pre-gate before a full parse.
func MFTRecordMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 'F' && b[1] == 'I' && b[2] == 'L' && b[3] == 'E'
}

// ParseMFTRecord parses one candidate FILE record (rec must be the full
// MFTRecordSize window). It validates the header, applies the update-sequence
// fixups (rejecting a torn record whose sector tails disagree with the USN),
// and walks the resident attributes for $STANDARD_INFORMATION and $FILE_NAME.
// ok=false on anything implausible — a carve hit is a candidate, not a verdict.
func ParseMFTRecord(rec []byte) (MFTEntry, bool) {
	var e MFTEntry
	if len(rec) < MFTRecordSize || !MFTRecordMagic(rec) {
		return e, false
	}
	usaOff := int(binary.LittleEndian.Uint16(rec[0x04:]))
	usaCount := int(binary.LittleEndian.Uint16(rec[0x06:]))
	// One USN plus one fixup word per sector of the record.
	if usaCount != MFTRecordSize/mftSectorSize+1 ||
		usaOff < 0x2A || usaOff+2*usaCount > mftSectorSize {
		return e, false
	}
	attrsOff := int(binary.LittleEndian.Uint16(rec[0x14:]))
	bytesInUse := int(binary.LittleEndian.Uint32(rec[0x18:]))
	if attrsOff < usaOff+2*usaCount || attrsOff >= MFTRecordSize ||
		attrsOff%8 != 0 || bytesInUse < attrsOff || bytesInUse > MFTRecordSize {
		return e, false
	}
	e.Sequence = binary.LittleEndian.Uint16(rec[0x10:])
	if e.Sequence == 0 {
		return e, false
	}
	flags := binary.LittleEndian.Uint16(rec[0x16:])
	e.InUse = flags&0x1 != 0
	e.IsDir = flags&0x2 != 0
	// The 48-byte header (usaOff >= 0x30) carries the record's own number;
	// the carve depends on it, so the pre-XP short header is rejected.
	if usaOff < 0x30 {
		return e, false
	}
	e.RecordNumber = binary.LittleEndian.Uint32(rec[0x2C:])
	e.FileReference = uint64(e.RecordNumber) | uint64(e.Sequence)<<48

	// Update-sequence handling. A record is cached in either form: PROTECTED
	// (on-disk shape — every sector's last word holds the USN and the real
	// words live in the USA) or FIXED-UP (the cache manager already restored
	// the real words in place). All tails == USN means protected: substitute
	// the USA words. No tail == USN means fixed-up: use the bytes as they
	// are. A mix means the record is torn across pages — reject.
	fixed := append([]byte(nil), rec...)
	usn := binary.LittleEndian.Uint16(rec[usaOff:])
	protected := 0
	for i := 0; i < usaCount-1; i++ {
		if binary.LittleEndian.Uint16(rec[(i+1)*mftSectorSize-2:]) == usn {
			protected++
		}
	}
	switch protected {
	case usaCount - 1:
		for i := 0; i < usaCount-1; i++ {
			tail := (i+1)*mftSectorSize - 2
			copy(fixed[tail:tail+2], rec[usaOff+2+2*i:])
		}
	case 0:
		// fixed-up in place — nothing to substitute
	default:
		return e, false // torn across cache pages
	}

	// Attribute walk: type, record-relative length, resident content.
	for off := attrsOff; off+8 <= bytesInUse; {
		typ := binary.LittleEndian.Uint32(fixed[off:])
		if typ == 0xFFFFFFFF {
			break
		}
		alen := int(binary.LittleEndian.Uint32(fixed[off+4:]))
		if alen <= 0 || alen%8 != 0 || off+alen > bytesInUse {
			return e, false
		}
		if fixed[off+8] == 0 && off+0x18 <= bytesInUse { // resident
			clen := int(binary.LittleEndian.Uint32(fixed[off+0x10:]))
			coff := int(binary.LittleEndian.Uint16(fixed[off+0x14:]))
			c := off + coff
			if coff >= 0x18 && clen >= 0 && c+clen <= off+alen {
				switch typ {
				case 0x10: // $STANDARD_INFORMATION
					if clen >= 0x20 {
						e.SICreated = binary.LittleEndian.Uint64(fixed[c:])
						e.SIModified = binary.LittleEndian.Uint64(fixed[c+8:])
						e.SIMFTModified = binary.LittleEndian.Uint64(fixed[c+16:])
						e.SIAccessed = binary.LittleEndian.Uint64(fixed[c+24:])
					}
				case 0x30: // $FILE_NAME — prefer a non-DOS namespace name
					if clen >= 0x42 {
						nameLen := int(fixed[c+0x40])
						ns := fixed[c+0x41]
						if c+0x42+2*nameLen <= off+alen && nameLen > 0 && (e.Name == "" || ns != 2) {
							u := make([]uint16, nameLen)
							for i := range u {
								u[i] = binary.LittleEndian.Uint16(fixed[c+0x42+2*i:])
							}
							e.Name = string(utf16.Decode(u))
							e.ParentRef = binary.LittleEndian.Uint64(fixed[c:])
							e.FNCreated = binary.LittleEndian.Uint64(fixed[c+8:])
							e.FNModified = binary.LittleEndian.Uint64(fixed[c+16:])
							e.FNMFTModified = binary.LittleEndian.Uint64(fixed[c+24:])
							e.FNAccessed = binary.LittleEndian.Uint64(fixed[c+32:])
						}
					}
				}
			}
		}
		off += alen
	}
	// A record with neither timestamps nor a name identifies nothing.
	if e.Name == "" && e.SICreated == 0 {
		return e, false
	}
	return e, true
}
