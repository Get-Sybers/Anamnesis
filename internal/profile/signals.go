package profile

import "math/bits"

// Autocorrelation returns the normalized autocorrelation of the byte stream for
// lags 0..maxLag (index 0 is unused and left at 0). A strong peak at lag k
// suggests a repeating period of k bytes; the smallest strong peak is the
// fundamental record stride. It is the cheap prefilter that proposes candidate
// widths before the per-column entropy confirm step.
func Autocorrelation(data []byte, maxLag int) []float64 {
	n := len(data)
	out := make([]float64, maxLag+1)
	if n == 0 || maxLag <= 0 {
		return out
	}
	var sum float64
	for _, b := range data {
		sum += float64(b)
	}
	mean := sum / float64(n)

	dev := make([]float64, n)
	var den float64
	for i, b := range data {
		d := float64(b) - mean
		dev[i] = d
		den += d * d
	}
	if den == 0 {
		return out // a constant stream has no meaningful autocorrelation
	}
	for k := 1; k <= maxLag && k < n; k++ {
		var num float64
		for i := 0; i+k < n; i++ {
			num += dev[i] * dev[i+k]
		}
		out[k] = num / den
	}
	return out
}

// BitConstancy reshapes data into rows of the given width and returns, per
// column, the fraction of the 8 bit-planes that are constant across all rows.
// This catches flag-heavy fields (e.g. page-table entries) whose byte varies
// while individual bits do not — the per-byte entropy score misses those.
func BitConstancy(data []byte, width int) []float64 {
	out := make([]float64, width)
	if width <= 0 {
		return out
	}
	rows := len(data) / width
	if rows == 0 {
		return out
	}
	for c := 0; c < width; c++ {
		andAll := byte(0xFF)
		orAll := byte(0x00)
		for r := 0; r < rows; r++ {
			b := data[r*width+c]
			andAll &= b
			orAll |= b
		}
		// A bit is constant across rows iff its AND and OR agree; the constant
		// bits are the complement of the bits that ever differ.
		constBits := ^(andAll ^ orAll)
		out[c] = float64(bits.OnesCount8(constBits)) / 8.0
	}
	return out
}

// Segment finds the maximal run of rows over which every column in cols holds
// its modal (most common) value, returning the row span [start, end). It bounds
// a fixed-stride array embedded in a larger region: the array's own rows all
// carry the preamble values, while surrounding data does not. end-start is the
// record count.
func Segment(data []byte, width int, cols []int) (start, end int) {
	if width <= 0 || len(cols) == 0 {
		return 0, 0
	}
	rows := len(data) / width
	if rows == 0 {
		return 0, 0
	}

	modal := make([]byte, len(cols))
	for j, c := range cols {
		var counts [256]int
		for r := 0; r < rows; r++ {
			counts[data[r*width+c]]++
		}
		bestVal, bestCnt := 0, -1
		for v := 0; v < 256; v++ {
			if counts[v] > bestCnt {
				bestCnt, bestVal = counts[v], v
			}
		}
		modal[j] = byte(bestVal)
	}

	bestStart, bestLen, curStart := 0, 0, -1
	for r := 0; r <= rows; r++ {
		match := r < rows
		if match {
			for j, c := range cols {
				if data[r*width+c] != modal[j] {
					match = false
					break
				}
			}
		}
		if match {
			if curStart < 0 {
				curStart = r
			}
			continue
		}
		if curStart >= 0 {
			if r-curStart > bestLen {
				bestStart, bestLen = curStart, r-curStart
			}
			curStart = -1
		}
	}
	return bestStart, bestStart + bestLen
}
