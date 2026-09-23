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
