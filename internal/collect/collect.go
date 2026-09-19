// Package collect is the extraction stage: collectors turn the native Engine's
// enumerations into raw per-plugin records (the analogue of the Volatility
// per-plugin JSONL), which the pipeline then normalizes into CAR. Each collector
// keeps its PIIAT plugin NAME (the pipeline and idempotency key on it) and emits
// the field names normalize expects; only the native source changed.
package collect

import (
	"encoding/json"
	"os"
	"path/filepath"

	"flashback/internal/car"
	"flashback/internal/memprocfs"
)

// Collector is one named extraction (its Name is the Volatility plugin id kept
// for the output/idempotency contract).
type Collector struct {
	Name    string
	Collect func(memprocfs.Engine) ([]car.Record, error)
}

// Default is the CAR collector set, in run order (mirrors the batch DEFAULT_PLUGINS:
// banners first — it validates the image without symbols).
var Default = []Collector{
	{"banners.Banners", collectBanners},
	{"windows.info", collectInfo},
	{"windows.piiat.processes", collectProcesses},
	{"windows.pslist", collectPslist},
	{"windows.piiat.modules", collectModules},
	{"windows.modules", collectDrivers},
	{"windows.piiat.network", collectNetwork},
	{"windows.netstat", collectNetstat},
	{"windows.piiat.sessions", collectSessions},
	{"windows.filescan", collectFilescan},
	{"windows.piiat.files", collectFiles},
	{"windows.svcscan", collectServices},
	{"windows.piiat.threads", collectThreads},
	{"windows.piiat.registry", collectRegistry},
	{"windows.piiat.access", collectAccess},
	{"windows.mftscan.MFTScan", collectMFT},
	{"windows.malfind", collectMalfind},
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
func Run(eng memprocfs.Engine, outDir string, names []string) []Result {
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
		recs, err := c.Collect(eng)
		writeErr := writeJSONL(out, recs)
		res := Result{Plugin: name, Output: out, Rows: len(recs), OK: err == nil && writeErr == nil}
		if err != nil {
			res.Error = err.Error()
		} else if writeErr != nil {
			res.Error = writeErr.Error()
		}
		results = append(results, res)
	}
	return results
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

// nilIfEmpty maps "" to nil (the analogue of Volatility's NotAvailableValue), so
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

// DefaultRegistryTargets is the curated high-value key set the registry collector
// reads (host identity, autoruns, services, profiles). The Engine implementation
// resolves these against the in-memory hives.
var DefaultRegistryTargets = []string{
	`Microsoft\Windows\CurrentVersion\Run`,
	`Microsoft\Windows\CurrentVersion\RunOnce`,
	`Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`,
	`Microsoft\Windows NT\CurrentVersion\Winlogon`,
	`Microsoft\Windows NT\CurrentVersion\ProfileList`,
	`System\CurrentControlSet\Control\ComputerName\ComputerName`,
	`System\CurrentControlSet\Control\ComputerName\ActiveComputerName`,
	`System\CurrentControlSet\Services\Tcpip\Parameters`,
	`System\CurrentControlSet\Control\Session Manager\Environment`,
}
