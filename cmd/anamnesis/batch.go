package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"anamnesis/internal/collect"
	"anamnesis/internal/memprocfs"
	"anamnesis/internal/pipeline"
)

// The env-driven batch orchestrator — the container ENTRYPOINT. Faithful port of
// the original Python batch script, with the ANAMNESIS_* env contract.
//
//	ANAMNESIS_INPUT_DIR      memory image tree, recursed        (default /input)
//	ANAMNESIS_OUT_DIR        output root, one folder per image  (default /out)
//	ANAMNESIS_SYMBOLS_DIR    PDB/symbol cache (read-write)      (default /symbols)
//	ANAMNESIS_PLUGINS        comma-separated collectors; empty = the default CAR set
//	ANAMNESIS_FORCE          1/true/yes/on: rerun collectors with valid output
//	ANAMNESIS_SYMBOLS_ONLINE 1/true/yes/on: this container has network for PDB fetch
//	ANAMNESIS_VMM_LIB        path to the MemProcFS vmm library
//	ANAMNESIS_STALL_TIMEOUT  per-collector stall watchdog, a Go duration (default 5m; 0 disables)
//
// A collector blocked inside the native engine past ANAMNESIS_STALL_TIMEOUT is a
// stall: the call cannot be cancelled and the engine's native locks must be
// treated as poisoned, so the batch records it (plugins/<name>.stalled) and
// re-execs itself — completed collectors skip, the stalled one is retried, and
// after two stalls it is skipped as failed.
//
// Output per image: <out>/<clean name>/plugins/<plugin>.jsonl + car.db +
// anamnesis.log. stdout: one JSON summary line. Exit 0 normal, 1 nothing
// produced/nothing done, 2 config error.

const tool = "anamnesis"

var pluginRe = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9_.]*\z`)

var memoryExts = []string{".raw", ".mem", ".dmp", ".lime", ".vmem", ".bin", ".dump", ".vmsn", ".crash"}

var trueSet = map[string]bool{"1": true, "true": true, "yes": true, "on": true}

type perImage struct {
	Image    string   `json:"image"`
	Produced []string `json:"produced"`
	Empty    []string `json:"empty"`
}

type summary struct {
	Tool          string     `json:"tool"`
	InputDir      string     `json:"input_dir"`
	OutDir        string     `json:"out_dir"`
	SymbolsDir    string     `json:"symbols_dir"`
	SymbolsOnline bool       `json:"symbols_online"`
	Force         bool       `json:"force"`
	Images        int        `json:"images"`
	Plugins       int        `json:"plugins"`
	Processed     int        `json:"processed"`
	Skipped       int        `json:"skipped"`
	Failed        int        `json:"failed"`
	Results       []perImage `json:"results"`
	Diagnostics   string     `json:"diagnostics,omitempty"`
	Error         string     `json:"error,omitempty"`
}

func envStr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envBool(name string) bool { return trueSet[strings.ToLower(strings.TrimSpace(os.Getenv(name)))] }

// stallTimeout reads ANAMNESIS_STALL_TIMEOUT (a Go duration; 0 disables the
// watchdog). An unparseable value keeps the default.
func stallTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("ANAMNESIS_STALL_TIMEOUT"))
	if raw == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		fmt.Fprintf(os.Stderr, "[%s] ignoring invalid ANAMNESIS_STALL_TIMEOUT %q\n", tool, raw)
		return 5 * time.Minute
	}
	return d
}

// maxStalls is how many stalls a collector gets before it is skipped as failed.
const maxStalls = 2

func stallPath(dest, plugin string) string {
	return filepath.Join(dest, "plugins", plugin+".stalled")
}

func stallCount(dest, plugin string) int {
	b, err := os.ReadFile(stallPath(dest, plugin))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// bumpStall persists the stall marker the recovery depends on: an unwritable
// marker would re-exec forever, so its error is fatal to the caller.
func bumpStall(dest, plugin string) error {
	if err := os.MkdirAll(filepath.Join(dest, "plugins"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(stallPath(dest, plugin),
		[]byte(strconv.Itoa(stallCount(dest, plugin)+1)+"\n"), 0o644)
}

func inputDirFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("ANAMNESIS_INPUT_DIR")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("ANAMNESIS_MEMORY_DIR")); v != "" {
		fmt.Fprintf(os.Stderr, "[%s] ANAMNESIS_MEMORY_DIR is deprecated; use ANAMNESIS_INPUT_DIR (default /input)\n", tool)
		return v
	}
	return "/input"
}

func envPlugins() []string {
	raw := os.Getenv("ANAMNESIS_PLUGINS")
	var safe []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if pluginRe.MatchString(p) {
			safe = append(safe, p)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] ignoring invalid plugin name %q\n", tool, p)
		}
	}
	if len(safe) == 0 {
		return collect.Names()
	}
	return safe
}

func runBatch() int {
	sum := process(
		inputDirFromEnv(),
		envStr("ANAMNESIS_OUT_DIR", "/out"),
		envStr("ANAMNESIS_SYMBOLS_DIR", "/symbols"),
		envPlugins(),
		envBool("ANAMNESIS_FORCE"),
		envBool("ANAMNESIS_SYMBOLS_ONLINE"),
	)
	if sum.Error != "" {
		fmt.Fprintln(os.Stderr, sum.Error)
	}
	if sum.Diagnostics != "" {
		fmt.Fprintln(os.Stderr, sum.Diagnostics)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(sum)
	if sum.Error != "" {
		return 2
	}
	if sum.Failed > 0 && sum.Processed == 0 && sum.Skipped == 0 {
		return 1
	}
	return 0
}

func process(inputDir, outDir, symbolsDir string, plugins []string, force, symbolsOnline bool) summary {
	sum := summary{Tool: tool, InputDir: inputDir, OutDir: outDir, SymbolsDir: symbolsDir,
		SymbolsOnline: symbolsOnline, Force: force, Plugins: len(plugins), Results: []perImage{}}

	if fi, err := os.Stat(inputDir); err != nil || !fi.IsDir() {
		sum.Error = fmt.Sprintf("input dir not found or not a directory: %s (mount /input, or set ANAMNESIS_INPUT_DIR)", inputDir)
		return sum
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		sum.Error = fmt.Sprintf("output dir not writable: %s (%v)", outDir, err)
		return sum
	}
	probe := filepath.Join(outDir, ".anamnesis-write-probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		sum.Error = fmt.Sprintf("output dir not writable: %s (%v)", outDir, err)
		return sum
	}
	os.Remove(probe)
	os.MkdirAll(symbolsDir, 0o755)

	images := discover(inputDir)
	sum.Images = len(images)
	fmt.Fprintf(os.Stderr, "[%s] input_dir=%s out_dir=%s symbols_dir=%s symbols_online=%d force=%d plugins=%d images=%d\n",
		tool, inputDir, outDir, symbolsDir, b2i(symbolsOnline), b2i(force), len(plugins), len(images))

	var diagTails []string
	for idx, img := range images {
		rel, _ := filepath.Rel(inputDir, img)
		dest := filepath.Join(outDir, cleanName(rel))
		os.MkdirAll(dest, 0o755)
		pi := perImage{Image: rel, Produced: []string{}, Empty: []string{}}

		var todo []string
		for _, p := range plugins {
			switch {
			case !force && pluginDone(dest, p):
				sum.Skipped++
			case stallCount(dest, p) >= maxStalls:
				sum.Failed++
				pi.Empty = append(pi.Empty, p)
			default:
				todo = append(todo, p)
			}
		}

		if len(todo) > 0 {
			fmt.Fprintf(os.Stderr, "[%s] image %d/%d: %s — running %d collector(s) (%d already done)\n",
				tool, idx+1, len(images), rel, len(todo), len(plugins)-len(todo))
			logTail, stalled := runImage(img, dest, todo, symbolsDir, symbolsOnline)
			if stalled != "" {
				if err := bumpStall(dest, stalled); err != nil {
					// Without the marker the re-exec would retry forever — fail fast.
					fmt.Fprintf(os.Stderr, "[%s] cannot persist the stall marker for %s: %v\n", tool, stalled, err)
					os.Exit(2)
				}
				fmt.Fprintf(os.Stderr, "[%s] image %d/%d: %s — collector %s stalled (attempt %d/%d); re-executing to recover\n",
					tool, idx+1, len(images), rel, stalled, stallCount(dest, stalled), maxStalls)
				reexec()
			}
			for _, p := range todo {
				if validJSONL(outPath(dest, p)) {
					os.Remove(stallPath(dest, p))
					sum.Processed++
					pi.Produced = append(pi.Produced, p)
				} else {
					os.Remove(outPath(dest, p))
					sum.Failed++
					pi.Empty = append(pi.Empty, p)
				}
			}
			fmt.Fprintf(os.Stderr, "[%s] image %d/%d: %s — produced %d, empty %d\n",
				tool, idx+1, len(images), rel, len(pi.Produced), len(pi.Empty))
			if logTail != "" && len(pi.Produced) == 0 {
				diagTails = append(diagTails, fmt.Sprintf("--- %s (anamnesis.log) ---\n%s", rel, logTail))
			}
		} else {
			fmt.Fprintf(os.Stderr, "[%s] image %d/%d: %s — all %d collector(s) already done\n",
				tool, idx+1, len(images), rel, len(plugins))
		}
		sum.Results = append(sum.Results, pi)
	}

	if sum.Images > 0 && sum.Processed == 0 && sum.Failed > 0 && len(diagTails) > 0 {
		sum.Diagnostics = strings.Join(diagTails, "\n")
	}
	return sum
}

// runImage opens the engine, runs the todo collectors into dest/plugins, and
// rebuilds car.db from all raw JSONL on disk. Returns a short log tail for
// diagnostics when the run produced nothing, and the name of a collector that
// stalled inside the native engine ("" when none) — the stall is already
// recorded and the engine is deliberately NOT closed then, since Close would
// block on the same poisoned locks; the caller re-execs to recover.
func runImage(img, dest string, todo []string, symbolsDir string, symbolsOnline bool) (string, string) {
	logPath := filepath.Join(dest, "anamnesis.log")
	var log strings.Builder
	logln := func(s string) { log.WriteString(s + "\n") }
	logln(fmt.Sprintf("[%s] image=%s dest=%s plugins=%s", tool, img, dest, strings.Join(todo, ",")))

	eng, err := memprocfs.Open(img, memprocfs.OpenOptions{
		LibPath: os.Getenv("ANAMNESIS_VMM_LIB"), SymbolsDir: symbolsDir,
		SymbolsOnline: symbolsOnline})
	if err != nil {
		logln("engine open failed: " + err.Error())
		os.WriteFile(logPath, []byte(log.String()), 0o644)
		return tail(log.String(), 20), ""
	}

	results, stalled := collect.Run(eng, dest, todo, stallTimeout())
	for _, r := range results {
		if r.OK {
			logln(fmt.Sprintf("  [ok ] %s: %d rows", r.Plugin, r.Rows))
		} else {
			logln(fmt.Sprintf("  [ERR] %s: %s", r.Plugin, r.Error))
		}
	}
	if stalled != "" {
		os.WriteFile(logPath, []byte(log.String()), 0o644)
		return tail(log.String(), 20), stalled
	}
	eng.Close()

	if st, err := pipeline.BuildStore(dest, filepath.Base(img)); err != nil {
		logln("build store: " + err.Error())
	} else {
		st.Close()
	}
	os.WriteFile(logPath, []byte(log.String()), 0o644)
	return tail(log.String(), 20), ""
}

// --- discovery / validity ----------------------------------------------------

func isMemoryImage(name string) bool {
	low := strings.ToLower(name)
	for _, e := range memoryExts {
		if strings.HasSuffix(low, e) {
			return true
		}
	}
	return strings.HasSuffix(low, "dramimage")
}

func discover(memoryDir string) []string {
	var found []string
	filepath.WalkDir(memoryDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && isMemoryImage(d.Name()) {
			found = append(found, path)
		}
		return nil
	})
	sort.Strings(found)
	return found
}

func cleanName(rel string) string {
	return strings.ReplaceAll(strings.ReplaceAll(rel, string(os.PathSeparator), "_"), " ", "_")
}

func outPath(dest, plugin string) string { return filepath.Join(dest, "plugins", plugin+".jsonl") }

func pluginDone(dest, plugin string) bool {
	return validJSONL(outPath(dest, plugin)) || validJSONL(filepath.Join(dest, plugin+".jsonl"))
}

// validJSONL: non-empty and the first line parses as JSON.
func validJSONL(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() <= 0 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, rerr := f.Read(tmp)
		if idx := indexByte(tmp[:n], '\n'); idx >= 0 {
			buf = append(buf, tmp[:idx]...)
			break
		}
		buf = append(buf, tmp[:n]...)
		if rerr != nil || len(buf) > 1<<20 {
			break
		}
	}
	line := strings.TrimSpace(string(buf))
	if line == "" {
		return false
	}
	var v any
	return json.Unmarshal([]byte(line), &v) == nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
