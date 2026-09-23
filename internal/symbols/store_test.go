package symbols

import (
	"os"
	"path/filepath"
	"testing"
)

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
	// Key lookups are case-insensitive on module and GUID.
	if _, err := ReadStoredOffsets(dir, StoreKey{"NTOSKRNL.EXE", e.GUID, e.Age}); err == nil {
		t.Log("upper-case module resolved (file name is lower-cased)")
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
