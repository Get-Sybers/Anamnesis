package profile

import (
	"math/rand"
	"testing"
)

func TestAutocorrelationPeaksAtStride(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	data := synthArray(rng, 256)

	ac := Autocorrelation(data, 120)
	// The stride is a peak relative to non-harmonic neighbours.
	for _, lag := range []int{24, 40, 56} {
		if ac[testStride] <= ac[lag] {
			t.Errorf("autocorr[%d]=%.4f not greater than autocorr[%d]=%.4f",
				testStride, ac[testStride], lag, ac[lag])
		}
	}
	if ac[testStride] <= 0 {
		t.Errorf("autocorr at stride = %.4f, want positive", ac[testStride])
	}
}

func TestBitConstancy(t *testing.T) {
	// col 0: constant byte -> all 8 bits constant (1.0)
	// col 1: values with the top bit always set, low bits varying
	rng := rand.New(rand.NewSource(4))
	rows := 256
	data := make([]byte, rows*2)
	for r := 0; r < rows; r++ {
		data[r*2] = 0x5A
		data[r*2+1] = 0x80 | byte(rng.Intn(0x80)) // bit 7 always 1
	}
	bc := BitConstancy(data, 2)
	if bc[0] != 1.0 {
		t.Errorf("constant column bit-constancy = %v, want 1.0", bc[0])
	}
	if bc[1] < 1.0/8.0 {
		t.Errorf("top-bit-constant column bit-constancy = %v, want >= 0.125", bc[1])
	}
	if bc[1] >= 1.0 {
		t.Errorf("varying column bit-constancy = %v, want < 1.0", bc[1])
	}
}

func TestSegmentExtent(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	const lead, count, trail = 32, 256, 32
	var buf []byte
	buf = append(buf, synthNoise(rng, lead)...)
	buf = append(buf, synthArray(rng, count)...)
	buf = append(buf, synthNoise(rng, trail)...)

	start, end := Segment(buf, testStride, []int{0, 1, 2, 3, 14, 15})
	if start != lead || end != lead+count {
		t.Errorf("segment = [%d,%d), want [%d,%d)", start, end, lead, lead+count)
	}
}
