// Package store is the CAR-event store — SQLite, the .plaso analogue. One table
// per CAR object (all 13 from the model, empty where memory has nothing), each
// with a common event header plus that object's canonical properties as nullable
// columns. Faithful port of piiat_mem/store.py.
//
// SQLite is modernc.org/sqlite — a pure-Go, cgo-free driver — so flashback builds
// with CGO_ENABLED=0.
package store

import (
	"database/sql"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"

	"flashback/internal/car"
	"flashback/internal/carmodel"

	_ "modernc.org/sqlite"
)

// header is the common event header on every object table.
var header = []string{"timestamp", "car_action", "guid", "owning_pid", "owning_offset",
	"owning_guid", "parent_pid", "parent_guid", "link_confidence",
	"source_plugin", "source_image", "native"}

var headerSet = func() map[string]bool {
	m := map[string]bool{}
	for _, h := range header {
		m[h] = true
	}
	return m
}()

func q(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

// Store creates/opens a car.db and reads/writes CAR events.
type Store struct {
	db    *sql.DB
	model *carmodel.Model
}

// cols returns an object's columns: the header first, then its CAR properties
// (minus any that collide with a header name, e.g. process.guid/parent_guid).
func cols(obj string) []string {
	out := append([]string(nil), header...)
	for _, f := range carmodel.Fields(obj) {
		if !headerSet[f] {
			out = append(out, f)
		}
	}
	return out
}

// Open creates or opens the store at path and ensures the schema exists.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, model: carmodel.Load()}
	if err := s.create(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) create() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, obj := range s.model.Names {
		colDefs := make([]string, 0)
		for _, c := range cols(obj) {
			colDefs = append(colDefs, q(c))
		}
		if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS " + q(obj) +
			" (event_id INTEGER PRIMARY KEY, " + strings.Join(colDefs, ", ") + ")"); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS " + q("ix_"+obj+"_guid") +
			" ON " + q(obj) + " (guid)"); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS " + q("ix_"+obj+"_ts") +
			" ON " + q(obj) + " (timestamp)"); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS image_context " +
		"(source_image TEXT, source_plugin TEXT, record TEXT)"); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// InsertEvents writes every event into its object's table. Returns the count.
func (s *Store) InsertEvents(events []car.Event) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	stmts := map[string]*sql.Stmt{}
	n := 0
	for _, ev := range events {
		obj, _ := ev["car_object"].(string)
		st, ok := stmts[obj]
		if !ok {
			cs := cols(obj)
			ph := strings.TrimSuffix(strings.Repeat("?, ", len(cs)), ", ")
			names := make([]string, len(cs))
			for i, c := range cs {
				names[i] = q(c)
			}
			st, err = tx.Prepare("INSERT INTO " + q(obj) + " (" + strings.Join(names, ", ") +
				") VALUES (" + ph + ")")
			if err != nil {
				tx.Rollback()
				return 0, err
			}
			stmts[obj] = st
		}
		row := make([]any, 0, len(cols(obj)))
		for _, c := range cols(obj) {
			if c == "native" {
				row = append(row, marshalNative(ev["_native"]))
				continue
			}
			row = append(row, bind(ev[c]))
		}
		if _, err := st.Exec(row...); err != nil {
			tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// InsertContext stores the raw output of a plugin with no CAR map.
func (s *Store) InsertContext(image, plugin string, records []car.Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare("INSERT INTO image_context (source_image, source_plugin, record) VALUES (?,?,?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range records {
		b, _ := json.Marshal(r)
		if _, err := st.Exec(image, plugin, string(b)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// IterObject returns every event row of one object, as events (native JSON
// decoded, car_object set).
func (s *Store) IterObject(obj string) ([]car.Event, error) {
	rows, err := s.db.Query("SELECT * FROM " + q(obj) + " ORDER BY event_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []car.Event
	for rows.Next() {
		vals := make([]any, len(colNames))
		ptrs := make([]any, len(colNames))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		ev := car.Event{"car_object": obj}
		for i, name := range colNames {
			if name == "event_id" {
				continue
			}
			ev[name] = normalizeScan(vals[i])
		}
		if raw, ok := ev["native"].(string); ok {
			var m map[string]any
			dec := json.NewDecoder(strings.NewReader(raw))
			dec.UseNumber()
			if dec.Decode(&m) == nil {
				ev["native"] = m
			}
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// IterTimeline returns every TIMESTAMPED event across all objects, ascending.
func (s *Store) IterTimeline() ([]car.Event, error) {
	var rows []car.Event
	for _, obj := range s.model.Names {
		evs, err := s.IterObject(obj)
		if err != nil {
			return nil, err
		}
		for _, e := range evs {
			if ts, _ := e["timestamp"].(string); ts != "" {
				rows = append(rows, e)
			}
		}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		return tsStr(rows[a]) < tsStr(rows[b])
	})
	return rows, nil
}

func tsStr(ev car.Event) string {
	s, _ := ev["timestamp"].(string)
	return s
}

// Counts returns non-empty object row counts.
func (s *Store) Counts() (map[string]int, error) {
	out := map[string]int{}
	for _, obj := range s.model.Names {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + q(obj)).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			out[obj] = n
		}
	}
	return out, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- value helpers -----------------------------------------------------------

func marshalNative(v any) string {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// bind converts an event value to something the SQLite driver accepts, mirroring
// Python sqlite3's adaptation (bool -> int, list/dict -> JSON text) and keeping
// 64-bit offsets exact (values above int64 max are stored as decimal text).
func bind(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case bool:
		if t {
			return int64(1)
		}
		return int64(0)
	case int:
		return int64(t)
	case int64:
		return t
	case uint64:
		if t <= math.MaxInt64 {
			return int64(t)
		}
		return strconv.FormatUint(t, 10)
	case float64:
		return t
	case json.Number:
		if u, err := strconv.ParseUint(t.String(), 10, 64); err == nil {
			if u <= math.MaxInt64 {
				return int64(u)
			}
			return t.String()
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case string:
		return t
	case []any, map[string]any:
		b, _ := json.Marshal(t)
		return string(b)
	default:
		return v
	}
}

// normalizeScan turns a driver-returned value into the event representation
// (BLOB/[]byte -> string; everything else as-is).
func normalizeScan(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}
