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
	"path/filepath"
	"strings"
	"time"

	"anamnesis/internal/symbols"
)

const usage = "usage: symrec <ntoskrnl.exe>  |  symrec -store <dir> <pe>...  |  symrec -fingerprint <dir> <pe> <routine> <global> [byte]"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "-store" {
		if len(os.Args) < 4 { // -store needs a dir AND at least one PE
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(seed(os.Args[2], os.Args[3:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "-fingerprint" {
		// -fingerprint <dir> <pe> <routine> <global> [byte]
		if len(os.Args) < 6 {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(harvest(os.Args[2], os.Args[3], os.Args[4], os.Args[5], len(os.Args) > 6 && os.Args[6] == "byte"))
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
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

// harvest authors a fingerprint signature for a routine referencing a global
// from a reference kernel PE and writes it into the signature store. routine
// is resolved by export name; global is the name the routine's first RIP
// operand references. The signature masks the disp32, so it generalizes
// across builds. (Non-exported routines, addressed by RVA, come with the
// in-image anchor-recovery slice.)
func harvest(dir, pePath, routine, global string, byteOperand bool) int {
	img, err := symbols.OpenPE(pePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "symrec: open:", err)
		return 1
	}
	code, _, err := img.FunctionCodeN(routine, 96)
	if err != nil {
		fmt.Fprintf(os.Stderr, "symrec: %s: %v\n", routine, err)
		return 1
	}
	sig, ok := symbols.BuildSignature(routine, global, code, byteOperand)
	if !ok {
		fmt.Fprintf(os.Stderr, "symrec: %s: no RIP-relative operand to key a signature on\n", routine)
		return 1
	}
	// The store file is named for the module the bytes came from, so a
	// signature harvested from a non-kernel PE lands in that module's file.
	module := strings.ToLower(filepath.Base(pePath))
	if err := symbols.WriteSignature(dir, module, sig); err != nil {
		fmt.Fprintln(os.Stderr, "symrec: write:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "symrec: harvested %s -> %s signature into %s (%d bytes, disp32 wildcarded)\n",
		routine, global, module, len(sig.Pattern))
	return 0
}
