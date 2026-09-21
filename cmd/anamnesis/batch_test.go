package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestInputDirFromEnvPrimary(t *testing.T) {
	t.Setenv("ANAMNESIS_INPUT_DIR", "/custom-input")
	t.Setenv("ANAMNESIS_MEMORY_DIR", "/legacy-memory")
	if got := inputDirFromEnv(); got != "/custom-input" {
		t.Fatalf("inputDirFromEnv() = %q, want %q", got, "/custom-input")
	}
}

func TestInputDirFromEnvFallbackWarns(t *testing.T) {
	t.Setenv("ANAMNESIS_INPUT_DIR", "")
	t.Setenv("ANAMNESIS_MEMORY_DIR", "/legacy-memory")

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	got := inputDirFromEnv()

	_ = w.Close()
	os.Stderr = oldStderr
	out, _ := io.ReadAll(r)
	_ = r.Close()

	if got != "/legacy-memory" {
		t.Fatalf("inputDirFromEnv() = %q, want %q", got, "/legacy-memory")
	}
	if !strings.Contains(string(out), "ANAMNESIS_MEMORY_DIR is deprecated; use ANAMNESIS_INPUT_DIR") {
		t.Fatalf("missing deprecation warning, got: %q", string(out))
	}
}

func TestSummaryJSONUsesInputDirKey(t *testing.T) {
	b, err := json.Marshal(summary{Tool: tool, InputDir: "/input"})
	if err != nil {
		t.Fatalf("json.Marshal(summary): %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"input_dir":"/input"`) {
		t.Fatalf("summary JSON missing input_dir: %s", s)
	}
	if strings.Contains(s, `"memory_dir"`) {
		t.Fatalf("summary JSON still contains memory_dir: %s", s)
	}
}
