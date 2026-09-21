//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// reexec replaces this process with a fresh copy of itself: the only way to
// shed a thread blocked inside the native engine. The new process resumes
// idempotently over the same output tree.
func reexec() {
	exe, err := os.Executable()
	if err == nil {
		err = syscall.Exec(exe, os.Args, os.Environ())
	}
	fmt.Fprintf(os.Stderr, "[%s] re-exec failed: %v\n", tool, err)
	os.Exit(2)
}
