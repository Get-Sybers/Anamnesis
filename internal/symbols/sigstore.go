package symbols

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// Signatures are build-time harvested from a reference kernel (symrec's
// fingerprint mode) and shipped read-only so the engine can locate a
// non-exported routine on a build it has never seen. Unlike the offset store,
// a signature is NOT keyed by (GUID, age): a masked pattern is authored to
// generalize across builds, so one file per module holds them all.

// SigSubdir is the directory signatures live in, under the seed root.
const SigSubdir = "anamnesis-signatures"

// ReadSignatures loads every signature authored for module from dir. A missing
// file is not an error (no signatures shipped yet) — it returns nil.
func ReadSignatures(dir, module string) ([]Signature, error) {
	raw, err := os.ReadFile(filepath.Join(dir, sigFileName(module)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sigs []Signature
	if err := json.Unmarshal(raw, &sigs); err != nil {
		return nil, err
	}
	return sigs, nil
}

// WriteSignature adds or replaces (by Global) a signature for module in dir,
// keeping the file sorted by Global for stable diffs, written atomically.
func WriteSignature(dir, module string, sig Signature) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sigs, err := ReadSignatures(dir, module)
	if err != nil {
		return err
	}
	replaced := false
	for i := range sigs {
		if sigs[i].Global == sig.Global {
			sigs[i], replaced = sig, true
			break
		}
	}
	if !replaced {
		sigs = append(sigs, sig)
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].Global < sigs[j].Global })

	raw, err := json.MarshalIndent(sigs, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sigs-*")
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
		err = os.Rename(tmp.Name(), filepath.Join(dir, sigFileName(module)))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// sigFileName is "<module>.json", lower-cased and path-safe.
func sigFileName(module string) string {
	return cleanStoreName(module) + ".json"
}
