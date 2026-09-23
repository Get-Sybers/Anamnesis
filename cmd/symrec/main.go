// Command symrec is a development probe for offline symbol recovery: point it at
// an ntoskrnl.exe (harvested at build time, or carved from a dump) and it prints
// the _EPROCESS / _ETHREAD field offsets it can read straight out of the kernel's
// exported accessor functions — no PDB, no symbol server.
//
// It is a thin CLI over internal/symbols; the real engine will drive the same
// package against the in-memory kernel. Not wired into the batch pipeline.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"anamnesis/internal/symbols"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: symrec <ntoskrnl.exe>")
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
