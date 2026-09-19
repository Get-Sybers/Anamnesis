// Command flashback turns a memory image into a MITRE CAR event store and timeline
// using a native (MemProcFS) engine — no Volatility, no Python.
//
//	flashback -f memory.raw -o out/                  # CAR store + wide JSONL timeline
//	flashback -f memory.raw -o out/ --format csv     # CAR store + one CSV per CAR object
//	flashback -f memory.raw -o out/ --no-timeline    # raw per-plugin JSONL + car.db only
//	flashback --list-plugins                         # the default collector set, as JSON
//
// With NO arguments it runs the env-driven batch orchestrator (the container
// ENTRYPOINT): it discovers every image under FLASHBACK_MEMORY_DIR and processes
// each. Pipeline (Plaso-shaped): extract -> normalize -> store -> output.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"flashback/internal/collect"
	"flashback/internal/memprocfs"
	"flashback/internal/pipeline"
	"flashback/internal/timeline"
)

// version is flashback's own line (a major bump from PIIAT-Mem 1.0.0: the engine
// is now native Go/MemProcFS rather than Volatility 3).
const version = "2.0.0"

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	// No args -> env-driven batch mode (the hardened container's ENTRYPOINT),
	// mirroring the old piiat_mem_batch contract. Any args -> the single-image CLI.
	if len(argv) == 0 {
		return runBatch()
	}
	return runSingle(argv)
}

func runSingle(argv []string) int {
	fs := flag.NewFlagSet("flashback", flag.ContinueOnError)
	var memory, out, format, plugins, symbols, lib string
	var noTimeline, symbolsOnline, listPlugins, showVersion bool
	// -f/--memory and -o/--out both bind the same var (short + long).
	fs.StringVar(&memory, "f", "", "memory image (raw/lime/dmp/vmem/...)")
	fs.StringVar(&memory, "memory", "", "memory image (raw/lime/dmp/vmem/...)")
	fs.StringVar(&out, "o", "", "output directory")
	fs.StringVar(&out, "out", "", "output directory")
	fs.StringVar(&format, "format", "json", "output: json (wide CAR timeline) | csv (one CSV per CAR object)")
	fs.StringVar(&plugins, "plugins", "", "comma-separated collector override (else the default set)")
	fs.StringVar(&symbols, "symbols", "", "PDB/symbol cache dir (default: a temp dir)")
	fs.StringVar(&lib, "lib", "", "path to the MemProcFS vmm library (else FLASHBACK_VMM_LIB / baked default)")
	fs.BoolVar(&noTimeline, "no-timeline", false, "skip rendered outputs; still write plugins/*.jsonl and car.db")
	fs.BoolVar(&symbolsOnline, "symbols-online", false, "allow the engine to fetch PDB symbols (network)")
	fs.BoolVar(&listPlugins, "list-plugins", false, "print the default collector set as JSON and exit")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	if showVersion {
		fmt.Printf("flashback %s\n", version)
		return 0
	}
	if listPlugins {
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(collect.Names())
		return 0
	}
	if memory == "" || out == "" {
		fmt.Fprintln(os.Stderr, "-f/--memory and -o/--out are required")
		return 2
	}
	if !isFile(memory) {
		fmt.Fprintf(os.Stderr, "memory image not found: %s\n", memory)
		return 2
	}
	os.MkdirAll(out, 0o755)
	if symbols == "" {
		symbols, _ = os.MkdirTemp("", "flashback-symbols-")
	}
	os.MkdirAll(symbols, 0o755)

	names := collect.Names()
	if plugins != "" {
		names = splitComma(plugins)
	}

	fmt.Fprintf(os.Stderr, "flashback %s: %s -> %s (%s)\n", version, memory, out, format)
	eng, err := memprocfs.Open(memory, memprocfs.OpenOptions{
		LibPath: libPath(lib), SymbolsDir: symbols, SymbolsOnline: symbolsOnline, Forensic: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	results := collect.Run(eng, out, names)
	eng.Close()

	ok := 0
	for _, r := range results {
		mark := "ok "
		if !r.OK {
			mark = "ERR"
		} else {
			ok++
		}
		line := fmt.Sprintf("  [%s] %s: %d rows", mark, r.Plugin, r.Rows)
		if !r.OK {
			line += "  (" + r.Error + ")"
		}
		fmt.Fprintln(os.Stderr, line)
	}

	st, err := pipeline.BuildStore(out, filepath.Base(memory))
	if err != nil {
		fmt.Fprintf(os.Stderr, "build store: %v\n", err)
		return 1
	}
	counts, _ := st.Counts()
	fmt.Fprintf(os.Stderr, "\nCAR store -> %s  (%s)\n", filepath.Join(out, "car.db"), countsStr(counts))

	switch {
	case noTimeline:
		fmt.Fprintf(os.Stderr, "raw per-plugin JSONL from %d/%d collectors -> %s\n",
			ok, len(results), filepath.Join(out, "plugins"))
	case format == "csv":
		written, _ := timeline.WriteObjectCSVs(st, filepath.Join(out, "car"))
		fmt.Fprintf(os.Stderr, "per-object CSVs -> %s  (%s)\n", filepath.Join(out, "car"), countsStr(written))
	default:
		n, _ := timeline.WriteTimelineJSON(st, filepath.Join(out, "timeline.json"), out)
		fmt.Fprintf(os.Stderr, "%d CAR timeline events -> %s\n", n, filepath.Join(out, "timeline.json"))
	}
	st.Close()

	if ok == 0 {
		fmt.Fprintln(os.Stderr, "no collector produced output — is the vmm library present and the image valid?")
		return 1
	}
	return 0
}

// --- shared helpers ----------------------------------------------------------

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func countsStr(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	// deterministic order
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%d", k, counts[k])
	}
	return strings.Join(parts, ", ")
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// libPath resolves the vmm library path: the --lib flag, else FLASHBACK_VMM_LIB,
// else empty (the implementation's baked default).
func libPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("FLASHBACK_VMM_LIB")
}
