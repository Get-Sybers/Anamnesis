// Command frameprofile is a development probe for structure discovery by frame
// profiling (docs/research/offline-structure-recovery.md, Section 7). Point it at
// a raw memory region — ideally a virtually-contiguous array already linearized
// through the page tables — and it reports the candidate record strides it finds
// by sweeping a frame width and scoring per-column byte entropy.
//
// It is a thin CLI over internal/profile; the engine will drive the same package
// against linearized kernel arrays. Not wired into the batch pipeline.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"anamnesis/internal/profile"
)

func main() {
	minW := flag.Int("min", 8, "smallest frame width (bytes)")
	maxW := flag.Int("max", 256, "largest frame width (bytes)")
	align := flag.Int("align", 8, "frame-width step / alignment prior")
	tau := flag.Float64("tau", 0.5, "entropy threshold (bits) for a near-constant column")
	minConst := flag.Int("min-const", 2, "min near-constant columns to call a stride")
	top := flag.Int("top", 5, "how many top-scoring widths to print")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: frameprofile [flags] <region.bin>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "frameprofile:", err)
		os.Exit(1)
	}

	results := profile.Profile(data, profile.Options{
		MinWidth: *minW, MaxWidth: *maxW, Align: *align, Tau: *tau,
	})
	ranked := append([]profile.WidthResult(nil), results...)
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Score > ranked[j].Score })
	if len(ranked) > *top {
		ranked = ranked[:*top]
	}
	fund, ok := profile.Fundamental(results, *minConst)

	out := struct {
		Bytes       int                   `json:"bytes"`
		Fundamental *profile.WidthResult  `json:"fundamental"`
		TopByScore  []profile.WidthResult `json:"top_by_score"`
	}{Bytes: len(data), TopByScore: ranked}
	if ok {
		out.Fundamental = &fund
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "frameprofile: encode:", err)
		os.Exit(1)
	}
}
