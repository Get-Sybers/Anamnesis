package symbols

import (
	"fmt"
	"testing"
)

// fakeSource is a CodeSource backed by hand-assembled bytes, so the recovery
// logic is testable with no PE and no memory image.
type fakeSource map[string][]byte

func (f fakeSource) FunctionCode(name string) ([]byte, uint64, error) {
	b, ok := f[name]
	if !ok {
		return nil, 0, fmt.Errorf("export %q not found", name)
	}
	return b, 0xFFFFF80000000000, nil
}

func TestRecoverOffsets(t *testing.T) {
	src := fakeSource{
		"PsGetProcessId":            {0x48, 0x8B, 0x81, 0x40, 0x04, 0x00, 0x00, 0xC3}, // mov rax,[rcx+0x440]
		"PsGetProcessImageFileName": {0x48, 0x8D, 0x81, 0xA8, 0x05, 0x00, 0x00, 0xC3}, // lea rax,[rcx+0x5a8]
		"PsGetProcessDebugPort":     {0x33, 0xC0, 0xC3},                               // xor eax,eax; ret (undecodable)
		// "PsGetProcessMissing" absent on purpose.
	}
	accessors := []Accessor{
		{Func: "PsGetProcessId", Struct: "_EPROCESS", Field: "UniqueProcessId", Confidence: Definitive},
		{Func: "PsGetProcessImageFileName", Struct: "_EPROCESS", Field: "ImageFileName", Confidence: Definitive},
		{Func: "PsGetProcessDebugPort", Struct: "_EPROCESS", Field: "DebugPort", Confidence: Definitive},
		{Func: "PsGetProcessMissing", Struct: "_EPROCESS", Field: "X", Confidence: Definitive},
	}

	offs, diags := RecoverOffsets(src, accessors)

	if len(offs) != 2 {
		t.Fatalf("want 2 recovered offsets, got %d: %+v", len(offs), offs)
	}
	byField := map[string]int32{}
	for _, o := range offs {
		byField[o.Field] = o.Offset
		if o.Confidence != Definitive {
			t.Errorf("%s: confidence = %q, want definitive", o.Field, o.Confidence)
		}
	}
	if byField["UniqueProcessId"] != 0x440 {
		t.Errorf("UniqueProcessId = %#x, want 0x440", byField["UniqueProcessId"])
	}
	if byField["ImageFileName"] != 0x5A8 {
		t.Errorf("ImageFileName = %#x, want 0x5a8", byField["ImageFileName"])
	}

	// One undecodable shape + one missing export = two honest diagnostics.
	if len(diags) != 2 {
		t.Fatalf("want 2 diagnostics, got %d: %+v", len(diags), diags)
	}
}

func TestProcessAccessorsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range ProcessAccessors {
		if a.Func == "" || a.Struct == "" || a.Field == "" {
			t.Errorf("incomplete accessor: %+v", a)
		}
		if a.Confidence != Definitive && a.Confidence != BestEffort {
			t.Errorf("%s: bad confidence %q", a.Func, a.Confidence)
		}
		if seen[a.Func] {
			t.Errorf("duplicate accessor func %q", a.Func)
		}
		seen[a.Func] = true
	}
}
