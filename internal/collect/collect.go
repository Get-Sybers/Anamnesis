// Package collect is the extraction stage: collectors turn the native Engine's
// enumerations into raw per-plugin records (the analogue of the earlier
// per-plugin JSONL), which the pipeline then normalizes into CAR. Each collector
// keeps its plugin NAME (the pipeline and idempotency key on it) and emits
// the field names normalize expects; only the native source changed.
package collect

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"anamnesis/internal/car"
	"anamnesis/internal/memprocfs"
)

type collectFn = func(memprocfs.Engine) ([]car.Record, error)

// Collector is one named extraction (its Name is the plugin id kept
// for the output/idempotency contract).
type Collector struct {
	Name    string
	Collect collectFn
}

// collectorFuncs binds each plugin name to its Go extraction function. The SET
// and ORDER of the default run — and the registry targets — are static data in
// collectors.yaml (below); only these bindings (the logic) stay in Go.
var collectorFuncs = map[string]collectFn{
	"banners.Banners":              collectBanners,
	"windows.info":                 collectInfo,
	"windows.anamnesis.processes":  collectProcesses,
	"windows.anamnesis.terminated": collectTerminated,
	"windows.pslist":               collectPslist,
	"windows.anamnesis.modules":    collectModules,
	"windows.modules":              collectDrivers,
	"windows.anamnesis.network":    collectNetwork,
	"windows.netstat":              collectNetstat,
	"windows.anamnesis.sessions":   collectSessions,
	"windows.filescan":             collectFilescan,
	"windows.anamnesis.files":      collectFiles,
	"windows.svcscan":              collectServices,
	"windows.anamnesis.threads":    collectThreads,
	"windows.anamnesis.registry":   collectRegistry,
	"windows.anamnesis.access":     collectAccess,
	"windows.mftscan.MFTScan":      collectMFT,
	"windows.malfind":              collectMalfind,
}

//go:embed collectors.yaml
var collectorsYAML []byte

// Default is the CAR collector set in run order; DefaultRegistryTargets is the
// curated key list — both loaded from collectors.yaml at init.
var (
	Default                []Collector
	DefaultRegistryTargets []string
)

func init() {
	var cfg struct {
		DefaultPlugins  []string `yaml:"default_plugins"`
		RegistryTargets []string `yaml:"registry_targets"`
	}
	if err := yaml.Unmarshal(collectorsYAML, &cfg); err != nil {
		panic("collect: parsing collectors.yaml: " + err.Error())
	}
	for _, name := range cfg.DefaultPlugins {
		fn, ok := collectorFuncs[name]
		if !ok {
			panic("collect: collectors.yaml lists unknown collector " + name)
		}
		Default = append(Default, Collector{Name: name, Collect: fn})
	}
	DefaultRegistryTargets = cfg.RegistryTargets
}

// Names returns the default collector names (for --list-plugins).
func Names() []string {
	out := make([]string, len(Default))
	for i, c := range Default {
		out[i] = c.Name
	}
	return out
}

// Get returns a collector by name.
func Get(name string) (Collector, bool) {
	for _, c := range Default {
		if c.Name == name {
			return c, true
		}
	}
	return Collector{}, false
}

// Result is one collector's outcome (the analogue of runner.run_plugin's dict).
type Result struct {
	Plugin string
	Output string
	Rows   int
	OK     bool
	Error  string
}

// Run executes the named collectors over one image, writing each one's records to
// <outDir>/plugins/<name>.jsonl. An unknown name is reported, not fatal.
// A collector that does not complete within timeout (0 disables the watchdog)
// has STALLED inside the native engine: its call cannot be cancelled and the
// engine's native locks must be treated as poisoned, so Run stops there and
// returns the stalled collector's name — the caller re-execs to recover.
func Run(eng memprocfs.Engine, outDir string, names []string, timeout time.Duration) ([]Result, string) {
	plugDir := filepath.Join(outDir, "plugins")
	os.MkdirAll(plugDir, 0o755)
	var results []Result
	for _, name := range names {
		out := filepath.Join(plugDir, name+".jsonl")
		c, ok := Get(name)
		if !ok {
			results = append(results, Result{Plugin: name, Output: out, OK: false,
				Error: "unknown collector"})
			continue
		}
		recs, stalled, err := runOne(eng, c, timeout)
		if stalled {
			results = append(results, Result{Plugin: name, Output: out, OK: false,
				Error: fmt.Sprintf("stalled: no completion within %s", timeout)})
			return results, name
		}
		writeErr := writeJSONL(out, recs)
		res := Result{Plugin: name, Output: out, Rows: len(recs), OK: err == nil && writeErr == nil}
		if err != nil {
			res.Error = err.Error()
		} else if writeErr != nil {
			res.Error = writeErr.Error()
		}
		results = append(results, res)
	}
	return results, ""
}

// runOne executes one collector under the stall watchdog. A stalled collector's
// goroutine stays blocked inside the native engine until the process is
// replaced; nothing here can cancel it.
func runOne(eng memprocfs.Engine, c Collector, timeout time.Duration) ([]car.Record, bool, error) {
	if timeout <= 0 {
		recs, err := c.Collect(eng)
		return recs, false, err
	}
	type outcome struct {
		recs []car.Record
		err  error
	}
	ch := make(chan outcome, 1)
	go func() {
		recs, err := c.Collect(eng)
		ch <- outcome{recs, err}
	}()
	watchdog := time.NewTimer(timeout)
	defer watchdog.Stop()
	select {
	case o := <-ch:
		return o.recs, false, o.err
	case <-watchdog.C:
		return nil, true, nil
	}
}

func writeJSONL(path string, recs []car.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// --- small record helpers ----------------------------------------------------

// nilIfEmpty maps "" to nil (an unavailable-value sentinel), so
// an unresolved field is null rather than an empty string.
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func pidOrNil(pid uint32) any {
	if pid == 0 {
		return nil
	}
	return int(pid)
}
