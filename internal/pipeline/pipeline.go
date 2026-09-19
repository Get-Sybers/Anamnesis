// Package pipeline wires extract-output together: it (re)builds the CAR store from
// the raw per-plugin JSONL on disk. Faithful port of the original Python cli.build_store.
//
// Scanning the disk (not one invocation's plugin list) makes the store safe under
// subset/incremental runs — earlier plugins' raw output is re-normalized, never
// destroyed. Plugins with no CAR map land in the image_context side table.
package pipeline

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"anamnesis/internal/car"
	"anamnesis/internal/enrich"
	"anamnesis/internal/normalize"
	"anamnesis/internal/store"
	"anamnesis/internal/timeline"
)

const jsonlExt = ".jsonl"

// BuildStore normalizes + enriches every raw per-plugin JSONL under <out>/plugins/
// into a fresh <out>/car.db and returns the open store. Stale rendered views
// (timeline.json, car/*.csv) are removed so they can never disagree with the store.
func BuildStore(outDir, sourceImage string) (*store.Store, error) {
	plugDir := filepath.Join(outDir, "plugins")
	var events []car.Event
	type ctx struct {
		plugin  string
		records []car.Record
	}
	var context []ctx

	if entries, err := os.ReadDir(plugDir); err == nil {
		present := map[string]bool{}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), jsonlExt) {
				present[strings.TrimSuffix(e.Name(), jsonlExt)] = true
			}
		}
		// a superseded built-in is skipped when its piiat.* successor is present
		superseded := map[string]bool{}
		for new, old := range normalize.SUPERSEDES {
			if present[new] {
				superseded[old] = true
			}
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), jsonlExt) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			plugin := strings.TrimSuffix(name, jsonlExt)
			if superseded[plugin] {
				continue
			}
			// malfind is a trigger, not a record — joined at output time.
			if contains(timeline.MalfindPlugins, plugin) {
				continue
			}
			records := timeline.LoadJSONL(filepath.Join(plugDir, name))
			if len(records) == 0 {
				continue
			}
			var evs []car.Event
			for _, rec := range records {
				if ev := normalize.Normalize(plugin, rec); ev != nil {
					evs = append(evs, ev)
				}
			}
			if len(evs) > 0 {
				for _, ev := range evs {
					ev["source_image"] = sourceImage
				}
				events = append(events, evs...)
			} else {
				context = append(context, ctx{plugin, records})
			}
		}
	}
	events = enrich.Enrich(events)

	dbPath := filepath.Join(outDir, "car.db")
	os.Remove(dbPath) // the store is rebuilt from the raw JSONL each run
	os.Remove(filepath.Join(outDir, "timeline.json"))
	if csvDir := filepath.Join(outDir, "car"); dirExists(csvDir) {
		if des, err := os.ReadDir(csvDir); err == nil {
			for _, d := range des {
				if strings.HasSuffix(d.Name(), ".csv") {
					os.Remove(filepath.Join(csvDir, d.Name()))
				}
			}
		}
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := st.InsertEvents(events); err != nil {
		st.Close()
		return nil, err
	}
	for _, c := range context {
		if err := st.InsertContext(sourceImage, c.plugin, c.records); err != nil {
			st.Close()
			return nil, err
		}
	}
	return st, nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
