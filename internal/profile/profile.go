package profile

import "math"

// Options controls the frame-width sweep.
type Options struct {
	MinWidth int     // smallest frame width to try (bytes)
	MaxWidth int     // largest frame width to try (bytes)
	Align    int     // width step and alignment prior (kernel records are 8/16-aligned)
	Tau      float64 // entropy threshold (bits): a column below Tau is "near-constant"
	MinRows  int     // skip a width that does not yield at least this many rows
}

func (o Options) withDefaults() Options {
	if o.MinWidth <= 0 {
		o.MinWidth = 8
	}
	if o.MaxWidth <= 0 {
		o.MaxWidth = 256
	}
	if o.Align <= 0 {
		o.Align = 8
	}
	if o.Tau <= 0 {
		o.Tau = 0.5
	}
	if o.MinRows <= 0 {
		o.MinRows = 16
	}
	return o
}

// WidthResult is the score for one candidate frame width.
type WidthResult struct {
	Width        int     `json:"width"`
	ConstColumns []int   `json:"const_columns"` // byte columns with entropy < Tau
	MinEntropy   float64 `json:"min_entropy"`
	MeanEntropy  float64 `json:"mean_entropy"`
	Score        float64 `json:"score"` // ranking score (count of near-constant columns)
}

// Profile sweeps frame widths over data and returns one WidthResult per candidate
// width, in ascending width order. A width whose reshaped form has fewer than
// Options.MinRows rows is skipped.
func Profile(data []byte, opt Options) []WidthResult {
	opt = opt.withDefaults()
	var out []WidthResult
	for w := opt.MinWidth; w <= opt.MaxWidth; w += opt.Align {
		if len(data)/w < opt.MinRows {
			continue
		}
		out = append(out, scoreWidth(data, w, opt.Tau))
	}
	return out
}

// Fundamental returns the smallest-width result with at least minConst
// near-constant columns — the fundamental record stride, as opposed to its
// integer-multiple harmonics, which also score. ok is false if none qualifies.
func Fundamental(results []WidthResult, minConst int) (best WidthResult, ok bool) {
	for _, r := range results {
		if len(r.ConstColumns) < minConst {
			continue
		}
		if !ok || r.Width < best.Width {
			best, ok = r, true
		}
	}
	return best, ok
}

func scoreWidth(data []byte, width int, tau float64) WidthResult {
	ent := columnByteEntropy(data, width)
	res := WidthResult{Width: width, MinEntropy: math.Inf(1)}
	var sum float64
	for c, h := range ent {
		sum += h
		if h < res.MinEntropy {
			res.MinEntropy = h
		}
		if h < tau {
			res.ConstColumns = append(res.ConstColumns, c)
		}
	}
	if len(ent) > 0 {
		res.MeanEntropy = sum / float64(len(ent))
	}
	if math.IsInf(res.MinEntropy, 1) {
		res.MinEntropy = 0
	}
	res.Score = float64(len(res.ConstColumns))
	return res
}

// columnByteEntropy reshapes data into rows of the given width and returns the
// Shannon entropy (in bits) of each column across rows. A trailing partial row
// is ignored.
func columnByteEntropy(data []byte, width int) []float64 {
	if width <= 0 {
		return nil
	}
	rows := len(data) / width
	ent := make([]float64, width)
	if rows == 0 {
		return ent
	}
	var counts [256]int
	for c := 0; c < width; c++ {
		for i := range counts {
			counts[i] = 0
		}
		for r := 0; r < rows; r++ {
			counts[data[r*width+c]]++
		}
		ent[c] = entropyBits(counts[:], rows)
	}
	return ent
}

func entropyBits(counts []int, total int) float64 {
	if total <= 0 {
		return 0
	}
	inv := 1.0 / float64(total)
	var h float64
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) * inv
		h -= p * math.Log2(p)
	}
	return h
}
