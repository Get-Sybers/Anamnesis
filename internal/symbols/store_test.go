package symbols

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func battery() []Accessor {
	return []Accessor{
		{Func: "PsGetProcessId"},
		{Func: "PsGetProcessCreateTimeQuadPart"},
		{Func: "PsIsProtectedProcess"},
	}
}

func TestMergeFirstRecovery(t *testing.T) {
	offs := []RecoveredOffset{{Func: "PsGetProcessId", Offset: 0x440, Confidence: Definitive}}
	got, improved := Merge(nil, StoreKey{"ntoskrnl.exe", "G", 1}, offs, []string{"PsIsProtectedProcess"}, "2026-09-23T00:00:00Z")
	if !improved {
		t.Fatal("a first recovery must count as improved")
	}
	if got.Source != "accessor" || got.Created != "2026-09-23T00:00:00Z" || got.Updated != "2026-09-23T00:00:00Z" {
		t.Fatalf("bad provenance: %+v", got)
	}
	if len(got.Offsets) != 1 || len(got.Undecodable) != 1 {
		t.Fatalf("merge shape: %+v", got)
	}
}

func TestMergeConvergesPartialToComplete(t *testing.T) {
	// A first image read only PsGetProcessId and found PsIsProtectedProcess
	// undecodable; CreateTime's page was not resident (neither offset nor
	// undecodable) — the entry is incomplete.
	base := &StoreEntry{
		Module: "ntoskrnl.exe", GUID: "G", Age: 1,
		Offsets:     []RecoveredOffset{{Func: "PsGetProcessId", Offset: 0x440, Confidence: Definitive}},
		Undecodable: []string{"PsIsProtectedProcess"},
		Source:      "accessor", Created: "2026-09-23T00:00:00Z", Updated: "2026-09-23T00:00:00Z",
	}
	if base.Complete(battery()) {
		t.Fatal("base must be incomplete (CreateTime missing)")
	}
	// A later, fuller image reads CreateTime too.
	fresh := []RecoveredOffset{
		{Func: "PsGetProcessId", Offset: 0x440, Confidence: Definitive},
		{Func: "PsGetProcessCreateTimeQuadPart", Offset: 0x468, Confidence: Definitive},
	}
	got, improved := Merge(base, StoreKey{"ntoskrnl.exe", "G", 1}, fresh, nil, "2026-09-24T00:00:00Z")
	if !improved {
		t.Fatal("adding CreateTime must improve the entry")
	}
	if !got.Complete(battery()) {
		t.Fatalf("merged entry must now be complete: %+v", got)
	}
	if got.Created != "2026-09-23T00:00:00Z" || got.Updated != "2026-09-24T00:00:00Z" {
		t.Fatalf("Created must be preserved and Updated advanced: %+v", got)
	}
	if _, ok := got.Offset("PsGetProcessCreateTimeQuadPart"); !ok {
		t.Fatal("CreateTime offset must be present after convergence")
	}
}

func TestMergeNoImprovementOnComplete(t *testing.T) {
	base := &StoreEntry{
		Module: "ntoskrnl.exe", GUID: "G", Age: 1,
		Offsets: []RecoveredOffset{
			{Func: "PsGetProcessId", Offset: 0x440},
			{Func: "PsGetProcessCreateTimeQuadPart", Offset: 0x468},
		},
		Undecodable: []string{"PsIsProtectedProcess"},
		Created:     "2026-09-23T00:00:00Z",
	}
	if !base.Complete(battery()) {
		t.Fatal("base should be complete")
	}
	_, improved := Merge(base, StoreKey{"ntoskrnl.exe", "G", 1},
		[]RecoveredOffset{{Func: "PsGetProcessId", Offset: 0x440}}, nil, "2026-09-25T00:00:00Z")
	if improved {
		t.Fatal("re-recovering offsets already stored must not count as improvement")
	}
}

func TestMergeBaseWinsConflict(t *testing.T) {
	base := &StoreEntry{
		Module: "ntoskrnl.exe", GUID: "G", Age: 1,
		Offsets: []RecoveredOffset{{Func: "PsGetProcessId", Offset: 0x440}},
		Created: "2026-09-23T00:00:00Z",
	}
	// A fresh read disagrees (a corrupt page): base's value stays authoritative.
	got, _ := Merge(base, StoreKey{"ntoskrnl.exe", "G", 1},
		[]RecoveredOffset{{Func: "PsGetProcessId", Offset: 0x999}}, nil, "2026-09-24T00:00:00Z")
	if o, _ := got.Offset("PsGetProcessId"); o != 0x440 {
		t.Fatalf("base must win an offset conflict, got %#x", o)
	}
}

func testEntry() StoreEntry {
	return StoreEntry{
		Module: "ntoskrnl.exe",
		GUID:   "3EB2B7C0-9A1D-4C55-8F13-2AD01D1B29D1",
		Age:    1,
		Offsets: []RecoveredOffset{
			{Func: "PsGetProcessCreateTimeQuadPart", Struct: "_EPROCESS", Field: "CreateTime", Offset: 0x468, Confidence: Definitive},
		},
		Source:  "accessor",
		Created: "2026-09-23T00:00:00Z",
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	e := testEntry()
	if err := WriteStoredOffsets(dir, e); err != nil {
		t.Fatal(err)
	}
	key := StoreKey{e.Module, e.GUID, e.Age}
	got, err := ReadStoredOffsets(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Offsets) != 1 || got.Offsets[0].Offset != 0x468 || got.Source != "accessor" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	// Key lookups fold case on both module and GUID.
	if _, err := ReadStoredOffsets(dir, StoreKey{"NTOSKRNL.EXE", strings.ToLower(e.GUID), e.Age}); err != nil {
		t.Fatalf("case-insensitive key lookup must resolve the entry: %v", err)
	}
}

func TestStoreMissAndCorruption(t *testing.T) {
	dir := t.TempDir()
	e := testEntry()
	key := StoreKey{e.Module, e.GUID, e.Age}
	if _, err := ReadStoredOffsets(dir, key); err == nil {
		t.Fatal("absent file must be a miss")
	}
	if err := os.WriteFile(filepath.Join(dir, storeFileName(key)), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStoredOffsets(dir, key); err == nil {
		t.Fatal("corrupt JSON must be a miss")
	}
	// Overwrite heals the corrupt file atomically.
	if err := WriteStoredOffsets(dir, e); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadStoredOffsets(dir, key); err != nil || len(got.Offsets) != 1 {
		t.Fatalf("healed read = (%+v, %v)", got, err)
	}
}

func TestStoreKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	e := testEntry()
	if err := WriteStoredOffsets(dir, e); err != nil {
		t.Fatal(err)
	}
	// A file renamed onto another build's key is rejected by the restated key.
	other := StoreKey{e.Module, "00000000-0000-0000-0000-000000000000", 2}
	if err := os.Rename(
		filepath.Join(dir, storeFileName(StoreKey{e.Module, e.GUID, e.Age})),
		filepath.Join(dir, storeFileName(other)),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStoredOffsets(dir, other); err == nil {
		t.Fatal("key mismatch must be a miss")
	}
}

func TestStoreEmptyOffsetsIsMiss(t *testing.T) {
	dir := t.TempDir()
	e := testEntry()
	e.Offsets = nil
	if err := WriteStoredOffsets(dir, e); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStoredOffsets(dir, StoreKey{e.Module, e.GUID, e.Age}); err == nil {
		t.Fatal("entry with no offsets must be a miss")
	}
}

func TestStoreFileNameSanitized(t *testing.T) {
	name := storeFileName(StoreKey{`..\..\evil`, "A/B", 3})
	if filepath.Base(name) != name {
		t.Fatalf("file name %q escapes the store directory", name)
	}
}

func TestGlobalsAreRVAKeyed(t *testing.T) {
	e := &StoreEntry{}
	if !MergeGlobal(e, RecoveredGlobal{Name: "G", RVA: 0x1234, Confidence: BestEffort}) {
		t.Fatal("first merge must add")
	}
	if MergeGlobal(e, RecoveredGlobal{Name: "G", RVA: 0x9999, Confidence: BestEffort}) {
		t.Fatal("an existing RVA is authoritative — base wins")
	}
	if rva, ok := e.Global("G"); !ok || rva != 0x1234 {
		t.Fatalf("Global = (%#x, %v), want (0x1234, true)", rva, ok)
	}
	// A legacy entry (written before globals were module-relative) unmarshals
	// with RVA 0: reported absent, and upgraded in place by a fresh recovery.
	legacy := &StoreEntry{Globals: []RecoveredGlobal{{Name: "G", RVA: 0, Confidence: BestEffort}}}
	if _, ok := legacy.Global("G"); ok {
		t.Fatal("a zero-RVA entry must read as absent, never as address zero")
	}
	if !MergeGlobal(legacy, RecoveredGlobal{Name: "G", RVA: 0x4321, Confidence: BestEffort}) {
		t.Fatal("a zero-RVA entry must be upgraded in place")
	}
	if rva, _ := legacy.Global("G"); rva != 0x4321 || len(legacy.Globals) != 1 {
		t.Fatalf("upgrade produced (%#x, %d entries), want (0x4321, 1)", rva, len(legacy.Globals))
	}
}
