package symbols

import (
	"encoding/binary"
	"testing"
)

func binarySID(revision, count byte, authority uint64, subs ...uint32) []byte {
	b := []byte{revision, count, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 6; i++ {
		b[7-i] = byte(authority >> (8 * i))
	}
	for _, s := range subs {
		var w [4]byte
		binary.LittleEndian.PutUint32(w[:], s)
		b = append(b, w[:]...)
	}
	return b
}

func TestScanSIDs(t *testing.T) {
	// A token-shaped buffer: noise, the user SID (S-1-5-21-…-1001), a group
	// (S-1-5-32-544 Administrators), an integrity label (S-1-16-8192), and a
	// duplicate of the user SID — 4-aligned, with filler between.
	var buf []byte
	buf = append(buf, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33)
	buf = append(buf, binarySID(1, 5, 5, 21, 111, 222, 333, 1001)...)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, binarySID(1, 2, 5, 32, 544)...)
	buf = append(buf, binarySID(1, 1, 16, 8192)...)
	buf = append(buf, binarySID(1, 5, 5, 21, 111, 222, 333, 1001)...) // dup

	got := ScanSIDs(buf)
	want := []string{"S-1-5-21-111-222-333-1001", "S-1-5-32-544", "S-1-16-8192"}
	if len(got) != len(want) {
		t.Fatalf("ScanSIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ScanSIDs[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestScanSIDsRejectsHighAuthorityNoise(t *testing.T) {
	// Revision 1 + small count but an out-of-range authority: not a SID.
	noise := []byte{1, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00}
	if got := ScanSIDs(noise); len(got) != 0 {
		t.Fatalf("high-authority noise must not scan as a SID: %v", got)
	}
}

func TestPickUserSID(t *testing.T) {
	known := func(s string) bool { return s == "S-1-5-21-111-222-333-1001" }
	cases := []struct {
		name       string
		sids       []string
		known      func(string) bool
		wantSID    string
		wantMethod string
	}{
		{"profile account wins", []string{"S-1-16-8192", "S-1-5-21-111-222-333-1001", "S-1-5-32-544"}, known, "S-1-5-21-111-222-333-1001", "token+profile"},
		{"service identity", []string{"S-1-16-16384", "S-1-5-18", "S-1-1-0"}, known, "S-1-5-18", "token+wellknown"},
		{"account fallback", []string{"S-1-5-32-544", "S-1-5-21-9-8-7-1050"}, nil, "S-1-5-21-9-8-7-1050", "token+account"},
		{"domain group RID skipped", []string{"S-1-5-21-9-8-7-513", "S-1-5-21-9-8-7-1104"}, nil, "S-1-5-21-9-8-7-1104", "token+account"},
		{"only domain groups", []string{"S-1-5-21-9-8-7-512", "S-1-5-21-9-8-7-513"}, nil, "", ""},
		{"only groups", []string{"S-1-5-32-544", "S-1-1-0", "S-1-16-8192"}, nil, "", ""},
		{"empty", nil, known, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sid, method := PickUserSID(c.sids, c.known)
			if sid != c.wantSID || method != c.wantMethod {
				t.Fatalf("PickUserSID = (%q, %q), want (%q, %q)", sid, method, c.wantSID, c.wantMethod)
			}
		})
	}
}

func TestDecodeSID(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
		ok   bool
	}{
		{"ascii", append([]byte("S-1-5-21-1004336348-1177238915-682003330-1001"), 0, 'X'), "S-1-5-21-1004336348-1177238915-682003330-1001", true},
		{"ascii unterminated", []byte("S-1-5-18"), "S-1-5-18", true},
		{"ascii trailing dash", append([]byte("S-1-5-"), 0), "", false},
		{"ascii double dash", append([]byte("S-1-5--18"), 0), "", false},
		{"ascii bad char", append([]byte("S-1-5-1a"), 0), "", false},
		{"binary domain user", binarySID(1, 5, 5, 21, 1004336348, 1177238915, 682003330, 1001), "S-1-5-21-1004336348-1177238915-682003330-1001", true},
		{"binary local system", binarySID(1, 1, 5, 18), "S-1-5-18", true},
		{"binary wide authority", binarySID(1, 1, 1<<33, 7), "S-1-0x000200000000-7", true},
		{"binary zero count", binarySID(1, 0, 5), "", false},
		{"binary count too large", binarySID(1, 16, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), "", false},
		{"binary truncated", binarySID(1, 5, 5, 21, 1004336348), "", false},
		{"binary wrong revision", binarySID(2, 1, 5, 18), "", false},
		{"garbage", []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0}, "", false},
		{"empty", nil, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := DecodeSID(c.raw)
			if ok != c.ok || got != c.want {
				t.Fatalf("DecodeSID = (%q, %v), want (%q, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}
