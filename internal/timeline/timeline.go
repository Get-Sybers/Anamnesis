// Package timeline is the output stage — it derives the deliverables from the
// CAR-event store (the psort analogue). Faithful port of the original Python timeline.py.
//
//   - wide JSONL timeline (timeline.json): one line per TIMESTAMPED CAR event —
//     the meta columns + every CAR property across every object (the model
//     superset), null where the object doesn't carry it.
//   - per-object CSVs (car/<object>.csv): the event header + that object's own
//     properties.
//
// Store-only events (no timestamp) appear in the CSVs but not the timeline.
package timeline

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"anamnesis/internal/car"
	"anamnesis/internal/carmodel"
	"anamnesis/internal/store"
	"anamnesis/internal/value"
)

var meta = []string{"timestamp", "car_object", "car_action", "guid", "owning_guid",
	"parent_guid", "link_confidence", "source_plugin", "source_image"}

// MalfindPlugins: malfind is a TRIGGER, not a stored record — its regions are
// joined against the stored processes here, at output time.
var MalfindPlugins = []string{"windows.malfind", "windows.malware.malfind"}

// LoadJSONL reads a JSONL file into records, preserving integer precision (json.Number).
func LoadJSONL(path string) []car.Record {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []car.Record
	dec := json.NewDecoder(f)
	dec.UseNumber()
	for {
		var r car.Record
		if err := dec.Decode(&r); err != nil {
			break
		}
		out = append(out, r)
	}
	return out
}

// MalfindOverlay retrieves the process already extracted (by PID) and populates a
// CAR module timeline entry from THAT stored record plus the region detail malfind
// uniquely provides. Nothing is written to the store.
func MalfindOverlay(st *store.Store, outDir string) []car.Event {
	procsList, _ := st.IterObject("process")
	procs := map[int64]car.Event{}
	for _, p := range procsList {
		if p["car_action"] != "create" {
			continue
		}
		if pid, ok := value.Int(p["pid"]); ok {
			procs[pid] = p
		}
	}
	plugDir := filepath.Join(outDir, "plugins")
	var regions []car.Record
	for _, name := range MalfindPlugins {
		regions = append(regions, LoadJSONL(filepath.Join(plugDir, name+".jsonl"))...)
	}
	var entries []car.Event
	for _, r := range regions {
		pid, ok := value.Int(r["PID"])
		if !ok {
			continue
		}
		proc, ok := procs[pid]
		if !ok {
			continue
		}
		start := r["Start VPN"]
		entries = append(entries, car.Event{
			"timestamp": proc["timestamp"],
			"car_object": "module", "car_action": "load",
			"guid":            "module-" + value.Str(r["PID"]) + "-" + value.Str(start),
			"owning_guid":     proc["guid"],
			"link_confidence": "heuristic",
			"source_plugin":   "windows.malfind", "source_image": proc["source_image"],
			"pid": r["PID"], "exe": proc["exe"], "image_path": proc["image_path"],
			"hostname": proc["hostname"], "fqdn": proc["fqdn"],
			"base_address": start,
			"_native": map[string]any{"malfind": true, "Protection": r["Protection"],
				"Tag": r["Tag"], "StartVPN": start, "EndVPN": r["End VPN"],
				"CommitCharge": r["CommitCharge"], "PrivateMemory": r["PrivateMemory"],
				"Disasm": r["Disasm"], "Hexdump": r["Hexdump"]},
		})
	}
	return entries
}

// WriteTimelineJSON writes the wide CAR timeline: every property of every object,
// null or not, plus the malfind overlay when outDir is given.
func WriteTimelineJSON(st *store.Store, path, outDir string) (int, error) {
	cols := append([]string(nil), meta...)
	for _, f := range carmodel.AllFields() {
		if !contains(meta, f) {
			cols = append(cols, f)
		}
	}
	rows, err := st.IterTimeline()
	if err != nil {
		return 0, err
	}
	if outDir != "" {
		for _, e := range MalfindOverlay(st, outDir) {
			if !value.IsBlank(e["timestamp"]) {
				rows = append(rows, e)
			}
		}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		return value.Str(rows[a]["timestamp"]) < value.Str(rows[b]["timestamp"])
	})
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	for _, ev := range rows {
		if err := writeOrderedJSON(f, cols, ev); err != nil {
			return n, err
		}
		if _, err := f.WriteString("\n"); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// writeOrderedJSON writes {col: ev[col], ...} preserving column order (Python's
// sort_keys=False), absent columns rendered as null.
func writeOrderedJSON(f *os.File, cols []string, ev car.Event) error {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, c := range cols {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(c)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(ev[c])
		if err != nil {
			vb = []byte("null")
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	_, err := f.Write(buf.Bytes())
	return err
}

// WriteObjectCSVs writes one CSV per CAR object that has rows: the header plus the
// object's properties. Returns per-object row counts.
func WriteObjectCSVs(st *store.Store, outDir string) (map[string]int, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	counts, err := st.Counts()
	if err != nil {
		return nil, err
	}
	written := map[string]int{}
	for obj, count := range counts {
		cols := make([]string, 0)
		for _, c := range meta {
			if c != "car_object" {
				cols = append(cols, c)
			}
		}
		for _, f := range carmodel.Fields(obj) {
			if !contains(meta, f) {
				cols = append(cols, f)
			}
		}
		path := filepath.Join(outDir, obj+".csv")
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		w := csv.NewWriter(f)
		if err := w.Write(cols); err != nil {
			f.Close()
			return nil, err
		}
		evs, err := st.IterObject(obj)
		if err != nil {
			f.Close()
			return nil, err
		}
		for _, ev := range evs {
			rec := make([]string, len(cols))
			for i, c := range cols {
				rec[i] = csvCell(ev[c])
			}
			if err := w.Write(rec); err != nil {
				f.Close()
				return nil, err
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		written[obj] = count
	}
	return written, nil
}

func csvCell(v any) string {
	if v == nil {
		return ""
	}
	return value.Str(v)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
