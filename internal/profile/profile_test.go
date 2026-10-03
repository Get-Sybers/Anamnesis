package profile

import (
	"math/rand"
	"testing"
)

const testStride = 48 // a plausible fixed-record size (e.g. an _MMPFN-like record)

// synthArray builds n contiguous testStride-byte records that mimic a real
// fixed-stride kernel array: a constant 4-byte tag, some zero-filled reserved
// bytes, a canonical-pointer field whose high bytes are constant, a low-entropy
// counter, and otherwise random payload. The constant fields are the "preamble"
// the profiler must find; the record size is what it must recover.
func synthArray(rng *rand.Rand, n int) []byte {
	buf := make([]byte, n*testStride)
	for r := 0; r < n; r++ {
		rec := buf[r*testStride : (r+1)*testStride]
		copy(rec[0:4], []byte("Pfn ")) // constant tag -> columns 0..3
		rec[4] = byte(r & 0x03)        // low-entropy counter (2 bits) -> not constant
		// rec[5:8] left zero            // reserved -> columns 5..7
		for i := 8; i < 14; i++ {
			rec[i] = byte(rng.Intn(256)) // pointer low bytes -> vary
		}
		rec[14] = 0xFF // canonical kernel-pointer prefix -> columns 14..15
		rec[15] = 0xFF
		for i := 16; i < testStride; i++ {
			rec[i] = byte(rng.Intn(256)) // random payload
		}
	}
	return buf
}

func synthNoise(rng *rand.Rand, rows int) []byte {
	buf := make([]byte, rows*testStride)
	for i := range buf {
		buf[i] = byte(rng.Intn(256))
	}
	return buf
}

func containsAll(got, want []int) bool {
	set := make(map[int]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestFundamentalStride(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	data := synthArray(rng, 256)

	results := Profile(data, Options{MinWidth: 8, MaxWidth: 128, Align: 8})
	fund, ok := Fundamental(results, 4)
	if !ok {
		t.Fatal("expected a fundamental stride, found none")
	}
	if fund.Width != testStride {
		t.Errorf("fundamental width = %d, want %d", fund.Width, testStride)
	}
	// The tag (0..3) and pointer prefix (14..15) must be among the preamble.
	if want := []int{0, 1, 2, 3, 14, 15}; !containsAll(fund.ConstColumns, want) {
		t.Errorf("const columns %v missing some of %v", fund.ConstColumns, want)
	}
	// Column 4 (the 2-bit counter) is not constant and must not be reported.
	for _, c := range fund.ConstColumns {
		if c == 4 {
			t.Errorf("column 4 (varying counter) wrongly reported constant")
		}
	}
}

func TestWrongWidthsHaveNoPreamble(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	data := synthArray(rng, 256)

	results := Profile(data, Options{MinWidth: 8, MaxWidth: 40, Align: 8})
	for _, r := range results {
		if len(r.ConstColumns) > 0 {
			t.Errorf("width %d (not a divisor giving row-aligned records) reported %d constant columns; want 0",
				r.Width, len(r.ConstColumns))
		}
	}
}

func TestColumnByteEntropy(t *testing.T) {
	// Two columns: col 0 constant (entropy 0), col 1 uniform over 4 values
	// (entropy 2 bits).
	data := make([]byte, 0, 256*2)
	for r := 0; r < 256; r++ {
		data = append(data, 0x41, byte(r&0x03))
	}
	ent := columnByteEntropy(data, 2)
	if len(ent) != 2 {
		t.Fatalf("got %d columns, want 2", len(ent))
	}
	if ent[0] != 0 {
		t.Errorf("constant column entropy = %v, want 0", ent[0])
	}
	if ent[1] < 1.99 || ent[1] > 2.01 {
		t.Errorf("4-value column entropy = %v, want ~2.0", ent[1])
	}
}
