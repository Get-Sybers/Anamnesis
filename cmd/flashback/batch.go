package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"flashback/internal/collect"
	"flashback/internal/memprocfs"
	"flashback/internal/pipeline"
)

// The env-driven batch orchestrator — the container ENTRYPOINT. Faithful port of
// GoDFIR-toolz/piiat-mem/piiat_mem_batch.py, with the FLASHBACK_* env contract.
//
//	FLASHBACK_MEMORY_DIR     memory image tree, recursed        (default /mem)
//	FLASHBACK_OUT_DIR        output root, one folder per image  (default /out)
//	FLASHBACK_SYMBOLS_DIR    PDB/symbol cache (read-write)      (default /symbols)
//	FLASHBACK_PLUGINS        comma-separated collectors; empty = the default CAR set
//	FLASHBACK_FORCE          1/true/yes/on: rerun collectors with valid output
//	FLASHBACK_SYMBOLS_ONLINE 1/true/yes/on: this container has network for PDB fetch
//	FLASHBACK_VMM_LIB        path to the MemProcFS vmm library
//
// Output per image: <out>/<clean name>/plugins/<plugin>.jsonl + car.db +
// flashback.log. stdout: one JSON summary line. Exit 0 normal, 1 nothing
// produced/nothing done, 2 config error.

const tool = "flashback"

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
	MemoryDir     string     `json:"memory_dir"`
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

func envPlugins() []string {
	raw := os.Getenv("FLASHBACK_PLUGINS")
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
		envStr("FLASHBACK_MEMORY_DIR", "/mem"),
		envStr("FLASHBACK_OUT_DIR", "/out"),
		envStr("FLASHBACK_SYMBOLS_DIR", "/symbols"),
		envPlugins(),
		envBool("FLASHBACK_FORCE"),
		envBool("FLASHBACK_SYMBOLS_ONLINE"),
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

func process(memoryDir, outDir, symbolsDir string, plugins []string, force, symbolsOnline bool) summary {
	sum := summary{Tool: tool, MemoryDir: memoryDir, OutDir: outDir, SymbolsDir: symbolsDir,
		SymbolsOnline: symbolsOnline, Force: force, Plugins: len(plugins), Results: []perImage{}}

	if fi, err := os.Stat(memoryDir); err != nil || !fi.IsDir() {
		sum.Error = fmt.Sprintf("memory dir not found or not a directory: %s (mount it, or set FLASHBACK_MEMORY_DIR)", memoryDir)
		return sum
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		sum.Error = fmt.Sprintf("output dir not writable: %s (%v)", outDir, err)
		return sum
	}
	probe := filepath.Join(outDir, ".flashback-write-probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		sum.Error = fmt.Sprintf("output dir not writable: %s (%v)", outDir, err)
		return sum
	}
	os.Remove(probe)
	os.MkdirAll(symbolsDir, 0o755)

	images := discover(memoryDir)
	sum.Images = len(images)
	fmt.Fprintf(os.Stderr, "[%s] memory_dir=%s out_dir=%s symbols_dir=%s symbols_online=%d force=%d plugins=%d images=%d\n",
		tool, memoryDir, outDir, symbolsDir, b2i(symbolsOnline), b2i(force), len(plugins), len(images))

	var diagTails []string
	for idx, img := range images {
		rel, _ := filepath.Rel(memoryDir, img)
		dest := filepath.Join(outDir, cleanName(rel))
		os.MkdirAll(dest, 0o755)
		pi := perImage{Image: rel, Produced: []string{}, Empty: []string{}}

		var todo []string
		for _, p := range plugins {
			if !force && pluginDone(dest, p) {
				sum.Skipped++
			} else {
				todo = append(todo, p)
			}
		}

		if len(todo) > 0 {
			fmt.Fprintf(os.Stderr, "[%s] image %d/%d: %s — running %d collector(s) (%d already done)\n",
				tool, idx+1, len(images), rel, len(todo), len(plugins)-len(todo))
			logTail := runImage(img, dest, todo, symbolsDir, symbolsOnline)
			for _, p := range todo {
				if validJSONL(outPath(dest, p)) {
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
				diagTails = append(diagTails, fmt.Sprintf("--- %s (flashback.log) ---\n%s", rel, logTail))
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
// diagnostics when the run produced nothing.
func runImage(img, dest string, todo []string, symbolsDir string, symbolsOnline bool) string {
	logPath := filepath.Join(dest, "flashback.log")
	var log strings.Builder
	logln := func(s string) { log.WriteString(s + "\n") }
	logln(fmt.Sprintf("[%s] image=%s dest=%s plugins=%s", tool, img, dest, strings.Join(todo, ",")))

	eng, err := memprocfs.Open(img, memprocfs.OpenOptions{
		LibPath: os.Getenv("FLASHBACK_VMM_LIB"), SymbolsDir: symbolsDir,
		SymbolsOnline: symbolsOnline, Forensic: true})
	if err != nil {
		logln("engine open failed: " + err.Error())
		os.WriteFile(logPath, []byte(log.String()), 0o644)
		return tail(log.String(), 20)
	}
	defer eng.Close()

	for _, r := range collect.Run(eng, dest, todo) {
		if r.OK {
			logln(fmt.Sprintf("  [ok ] %s: %d rows", r.Plugin, r.Rows))
		} else {
			logln(fmt.Sprintf("  [ERR] %s: %s", r.Plugin, r.Error))
		}
	}
	if st, err := pipeline.BuildStore(dest, filepath.Base(img)); err != nil {
		logln("build store: " + err.Error())
	} else {
		st.Close()
	}
	os.WriteFile(logPath, []byte(log.String()), 0o644)
	return tail(log.String(), 20)
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
