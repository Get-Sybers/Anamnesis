// Package carmodel is the MITRE CAR data model — the single source of truth for
// which objects exist and which actions/properties each object has. It embeds the
// vendored car_data_model.json (13 objects, regenerated from mitre-attack/car), so
// the store's table schemas and the wide timeline's property superset both derive
// from here: a model refresh is a data change, not a code change.
//
// Faithful port of piiat_mem/carmodel.py. Object order is preserved from the JSON
// (insertion order in the Python dict) so table creation and CSV/timeline object
// iteration stay deterministic.
package carmodel

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"
)

//go:embed car_data_model.json
var modelJSON []byte

// Object is one CAR object's canonical property and action names.
type Object struct {
	Fields  []string
	Actions []string
}

// Model is the parsed CAR data model, keeping object order.
type Model struct {
	Names []string          // objects in file order
	Objs  map[string]Object // name -> object
}

type rawObject struct {
	Name    []string `json:"name"`
	Fields  []string `json:"fields"`
	Actions []string `json:"actions"`
}

type rawDoc struct {
	Objects []rawObject `json:"objects"`
}

var (
	once   sync.Once
	cached *Model
)

// Load parses (once) and returns the embedded CAR data model.
func Load() *Model {
	once.Do(func() {
		var doc rawDoc
		if err := json.Unmarshal(modelJSON, &doc); err != nil {
			panic("carmodel: cannot parse embedded car_data_model.json: " + err.Error())
		}
		m := &Model{Objs: make(map[string]Object, len(doc.Objects))}
		for _, o := range doc.Objects {
			name := ""
			if len(o.Name) > 0 {
				name = o.Name[0]
			}
			m.Names = append(m.Names, name)
			m.Objs[name] = Object{Fields: append([]string(nil), o.Fields...),
				Actions: append([]string(nil), o.Actions...)}
		}
		cached = m
	})
	return cached
}

// Fields returns the canonical property names of one CAR object.
func Fields(obj string) []string { return Load().Objs[obj].Fields }

// Actions returns the canonical actions of one CAR object.
func Actions(obj string) []string { return Load().Objs[obj].Actions }

// FieldSet returns the object's fields as a set for membership tests.
func FieldSet(obj string) map[string]bool {
	fs := Load().Objs[obj].Fields
	s := make(map[string]bool, len(fs))
	for _, f := range fs {
		s[f] = true
	}
	return s
}

// AllFields returns the sorted union of every object's properties — the wide
// timeline's property superset.
func AllFields() []string {
	seen := map[string]bool{}
	for _, spec := range Load().Objs {
		for _, f := range spec.Fields {
			seen[f] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Objects returns the object names in model (file) order.
func Objects() []string { return Load().Names }
