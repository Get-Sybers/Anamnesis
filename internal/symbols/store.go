package symbols

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
// the accessors found permanently undecodable for this build, how they were
// obtained, and when. Undecodable lets a hit know a partial entry is as
// complete as the build allows, so an image that could only read part of the
// kernel does not force every later image to re-attempt the rest — the store
// converges (docs/design/symbol-recovery.md §2).
type StoreEntry struct {
	Module      string            `json:"module"`
	GUID        string            `json:"guid"`
	Age         uint32            `json:"age"`
	Offsets     []RecoveredOffset `json:"offsets"`
	Undecodable []string          `json:"undecodable,omitempty"` // accessor funcs whose shape carries no offset — permanent for this build
	Source      string            `json:"source"`                // "accessor" today; other tiers later
	Created     string            `json:"created"`               // RFC3339 UTC, first write
	Updated     string            `json:"updated,omitempty"`     // RFC3339 UTC, last convergence write
}

// Offset returns the recovered offset for an accessor func.
func (e *StoreEntry) Offset(fn string) (int32, bool) {
	for _, o := range e.Offsets {
		if o.Func == fn {
			return o.Offset, true
		}
	}
	return 0, false
}

// Complete reports whether every accessor is accounted for — each either
// recovered or known permanently undecodable — so no later image can add to
// this entry and recovery can be skipped on a hit.
func (e *StoreEntry) Complete(accessors []Accessor) bool {
	covered := make(map[string]bool, len(e.Offsets)+len(e.Undecodable))
	for _, o := range e.Offsets {
		covered[o.Func] = true
	}
	for _, u := range e.Undecodable {
		covered[u] = true
	}
	for _, a := range accessors {
		if !covered[a.Func] {
			return false
		}
	}
	return true
}

// Merge folds a fresh recovery — the offsets read this run and the funcs found
// permanently undecodable — into base, returning the converged entry and
// whether it improved on base (a new offset or a newly-known-undecodable
// func). base wins every offset conflict: a hand-seeded or already-persisted
// value stays authoritative (a wrong one is caught downstream by the
// consume-time plausibility gate), and a fresh recovery only fills gaps.
// base may be nil for a first recovery. Offsets are ordered by func so the
// file is stable across writes.
func Merge(base *StoreEntry, key StoreKey, offsets []RecoveredOffset, undecodable []string, now string) (*StoreEntry, bool) {
	byFunc := map[string]RecoveredOffset{}
	created, source := now, "accessor"
	if base != nil {
		created, source = base.Created, base.Source
		for _, o := range base.Offsets {
			byFunc[o.Func] = o
		}
	}
	improved := base == nil
	for _, o := range offsets {
		if _, ok := byFunc[o.Func]; !ok {
			byFunc[o.Func] = o
			improved = true
		}
	}
	undec := map[string]bool{}
	if base != nil {
		for _, u := range base.Undecodable {
			undec[u] = true
		}
	}
	for _, u := range undecodable {
		if !undec[u] {
			undec[u] = true
			improved = true
		}
	}
	out := &StoreEntry{
		Module: key.Module, GUID: key.GUID, Age: key.Age,
		Offsets: sortedOffsets(byFunc), Undecodable: sortedKeys(undec),
		Source: source, Created: created, Updated: now,
	}
	return out, improved
}

func sortedOffsets(m map[string]RecoveredOffset) []RecoveredOffset {
	out := make([]RecoveredOffset, 0, len(m))
	for _, o := range m {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Func < out[j].Func })
	return out
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
