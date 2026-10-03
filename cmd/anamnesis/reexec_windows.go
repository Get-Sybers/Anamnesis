//go:build windows

package main

import (
	"fmt"
	"os"
)

// reexec (windows): exec-style process replacement does not exist. The stall
// marker is already persisted, so exit partial — a rerun resumes idempotently.
func reexec() {
	fmt.Fprintf(os.Stderr, "[%s] stall recovery needs a rerun (no process replacement on windows); exiting\n", tool)
	os.Exit(3)
}
