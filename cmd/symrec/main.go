// Command symrec is a development probe and build-time seeder for offline
// symbol recovery. Point it at an ntoskrnl.exe (harvested at build time, or
// carved from a dump) and it prints the _EPROCESS / _ETHREAD field offsets it
// reads straight out of the kernel's exported accessor functions — no PDB, no
// symbol server.
//
//	symrec <ntoskrnl.exe>                  # print offsets + diagnostics as JSON
//	symrec -store <dir> <pe> [<pe>...]     # seed the (GUID,age) offset store
//
// In -store mode each PE's CodeView (GUID, age) keys one store file under dir,
// merged with any existing entry, so an unseen build is a Tier-1 store hit on
// its first real image instead of a runtime recovery. It is a thin CLI over
// internal/symbols; the engine drives the same package against the in-memory
// kernel.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"anamnesis/internal/symbols"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "-store" {
		if len(os.Args) < 4 { // -store needs a dir AND at least one PE
			fmt.Fprintln(os.Stderr, "usage: symrec <ntoskrnl.exe>  |  symrec -store <dir> <pe>...")
			os.Exit(2)
		}
		os.Exit(seed(os.Args[2], os.Args[3:]))
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: symrec <ntoskrnl.exe>  |  symrec -store <dir> <pe>...")
		os.Exit(2)
	}
	img, err := symbols.OpenPE(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "symrec: open:", err)
		os.Exit(1)
	}
	offsets, diags := symbols.RecoverOffsets(img, symbols.ProcessAccessors)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Offsets     []symbols.RecoveredOffset `json:"offsets"`
		Diagnostics []symbols.Diagnostic      `json:"diagnostics"`
	}{offsets, diags}); err != nil {
		fmt.Fprintln(os.Stderr, "symrec: encode:", err)
		os.Exit(1)
	}
}

// seed writes one offset-store file per input PE into dir. Per-file failures
// are reported and skipped; the exit code is non-zero only if every input
// failed (so a CI harvest of many builds is not sunk by one bad file).
func seed(dir string, paths []string) int {
	ok := 0
	for _, path := range paths {
		if err := seedOne(dir, path); err != nil {
			fmt.Fprintf(os.Stderr, "symrec: %s: %v\n", path, err)
			continue
		}
		ok++
	}
	if ok == 0 {
		return 1
	}
	return 0
}

func seedOne(dir, path string) error {
	img, err := symbols.OpenPE(path)
	if err != nil {
		return err
	}
	guid, age, err := img.CodeView()
	if err != nil {
		return fmt.Errorf("codeview: %w", err)
	}
	// v1 seeds only kernel offsets — the accessor battery is _EPROCESS/_ETHREAD.
	// ntdll layout is anchored per-process at consume time (procparams.go), so
	// there is nothing build-keyed to seed for it.
	if _, _, ferr := img.FunctionCode("PsGetProcessId"); ferr != nil {
		return fmt.Errorf("not a kernel image (no PsGetProcessId export): no store-backed offsets to seed")
	}
	offsets, diags := symbols.RecoverOffsets(img, symbols.ProcessAccessors)
	if len(offsets) == 0 {
		return fmt.Errorf("recovered no offsets (guid=%s age=%d)", guid, age)
	}
	var undecodable []string
	for _, d := range diags {
		if d.Kind == symbols.Unrecognised {
			undecodable = append(undecodable, d.Func)
		}
	}
	key := symbols.StoreKey{Module: "ntoskrnl.exe", GUID: guid, Age: age}
	base, _ := symbols.ReadStoredOffsets(dir, key)
	entry, improved := symbols.Merge(base, key, offsets, undecodable, time.Now().UTC().Format(time.RFC3339))
	if base == nil {
		entry.Source = "genstore" // a merge keeps the existing entry's provenance
	}
	if !improved {
		// Re-seeding an unchanged build must not rewrite the file: the store
		// stays deterministic and diffs stay quiet.
		fmt.Fprintf(os.Stderr, "symrec: %s already complete (guid=%s age=%d) — not rewritten\n",
			key.Module, guid, age)
		return nil
	}
	if err := symbols.WriteStoredOffsets(dir, *entry); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "symrec: seeded %d/%d offsets (guid=%s age=%d)\n",
		len(entry.Offsets), len(symbols.ProcessAccessors), guid, age)
	return nil
}
