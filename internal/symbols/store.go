package symbols

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The Tier-1 offset store (docs/design/symbol-recovery.md §2): recovered
// offsets keyed by a module's CodeView (GUID, age), one small JSON file per
// build, kept in an `anamnesis-offsets/` directory inside the persistent
// symbol cache. A Tier-2 recovery writes its result back, so the second
// occurrence of a build is a store hit — the cache teaches itself. Files are
// plain RecoveredOffset JSON: diffable, auditable, and seedable by hand.

// StoreKey identifies one module build.
type StoreKey struct {
	Module string // module file name, e.g. "ntoskrnl.exe"
	GUID   string // CodeView GUID string
	Age    uint32
}

// StoreEntry is the persisted form: the key restated (so a file is
// self-describing and a mismatched or renamed file is detected), the offsets,
// how they were obtained, and when.
type StoreEntry struct {
	Module  string            `json:"module"`
	GUID    string            `json:"guid"`
	Age     uint32            `json:"age"`
	Offsets []RecoveredOffset `json:"offsets"`
	Source  string            `json:"source"`  // "accessor" today; other tiers later
	Created string            `json:"created"` // RFC3339 UTC
}

// StoreSubdir is the directory the store lives in, under the symbol cache.
const StoreSubdir = "anamnesis-offsets"

// ReadStoredOffsets loads the entry for key from dir. Any failure — absent
// file, unparseable JSON, a key mismatch, no offsets — is an error the caller
// treats as a store miss; the file is never deleted here.
func ReadStoredOffsets(dir string, key StoreKey) (*StoreEntry, error) {
	raw, err := os.ReadFile(filepath.Join(dir, storeFileName(key)))
	if err != nil {
		return nil, err
	}
	var e StoreEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	if !strings.EqualFold(e.Module, key.Module) || !strings.EqualFold(e.GUID, key.GUID) || e.Age != key.Age {
		return nil, fmt.Errorf("offset store entry keyed (%s, %s, %d), want (%s, %s, %d)",
			e.Module, e.GUID, e.Age, key.Module, key.GUID, key.Age)
	}
	if len(e.Offsets) == 0 {
		return nil, fmt.Errorf("offset store entry for (%s, %s, %d) holds no offsets", key.Module, key.GUID, key.Age)
	}
	return &e, nil
}

// WriteStoredOffsets persists entry into dir atomically (temp file + rename,
// so a concurrent reader only ever sees a complete file; last writer wins,
// which is safe because content is deterministic per (GUID, age)).
func WriteStoredOffsets(dir string, entry StoreEntry) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".offsets-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(raw, '\n'))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, storeFileName(StoreKey{entry.Module, entry.GUID, entry.Age})))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// storeFileName is "<module>-<guid>-<age>.json", lower-cased, with anything
// outside [a-z0-9._-] folded to '_' so a hostile module name cannot escape
// the store directory.
func storeFileName(key StoreKey) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
				return r
			default:
				return '_'
			}
		}, strings.ToLower(s))
	}
	return fmt.Sprintf("%s-%s-%d.json", clean(key.Module), clean(key.GUID), key.Age)
}
