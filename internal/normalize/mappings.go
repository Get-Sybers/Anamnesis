package normalize

import (
	_ "embed"

	"gopkg.in/yaml.v3"

	"anamnesis/internal/car"
	"anamnesis/internal/value"
)

// The static delegation table lives in mappings.yaml (embedded), NOT in Go — Go
// only interprets it. The marker resolvers (first/basename/…) and the variant
// predicates are named Go functions this loader binds by name.

//go:embed mappings.yaml
var mappingsYAML []byte

// mappings: plugin name -> its CAR map. SUPERSEDES: a piiat.* plugin -> the
// built-in it supersedes. Both are loaded from mappings.yaml at package init.
var (
	mappings   map[string]*carMap
	SUPERSEDES map[string]string
)

// predicates are the named variant predicates mappings.yaml may reference.
var predicates = map[string]func(car.Record) bool{
	"is_bound_socket": isBoundSocket,
}

// isBoundSocket: a netscan/netstat/piiat.network row that is a bound/listening
// socket, not a connection (LISTENING, or no real foreign endpoint).
func isBoundSocket(rec car.Record) bool {
	if value.Str(rec["State"]) == "LISTENING" {
		return true
	}
	fa := rec["ForeignAddr"]
	if fa == nil {
		return true
	}
	switch value.Str(fa) {
	case "", "*", "0.0.0.0", "::":
		return true
	}
	return false
}

// --- YAML shapes -------------------------------------------------------------

type rawFile struct {
	Supersedes map[string]string   `yaml:"supersedes"`
	Mappings   map[string]rawEntry `yaml:"mappings"`
}

type rawEntry struct {
	Object       string         `yaml:"object"`
	Action       *string        `yaml:"action"`
	Ts           *string        `yaml:"ts"`
	OwningPID    string         `yaml:"owning_pid"`
	OwningOffset string         `yaml:"owning_offset"`
	ParentPID    string         `yaml:"parent_pid"`
	Guid         map[string]any `yaml:"guid"`
	Props        map[string]any `yaml:"props"`
	Keep         []string       `yaml:"keep"`
	Variants     []rawVariant   `yaml:"variants"`
	Default      *rawEntry      `yaml:"default"`
}

type rawVariant struct {
	Predicate string   `yaml:"predicate"`
	Map       rawEntry `yaml:"map"`
}

func init() {
	var rf rawFile
	if err := yaml.Unmarshal(mappingsYAML, &rf); err != nil {
		panic("normalize: parsing mappings.yaml: " + err.Error())
	}
	SUPERSEDES = rf.Supersedes
	mappings = make(map[string]*carMap, len(rf.Mappings))
	for name, re := range rf.Mappings {
		mappings[name] = parseEntry(re)
	}
}

func parseEntry(re rawEntry) *carMap {
	if len(re.Variants) > 0 {
		m := &carMap{}
		for _, v := range re.Variants {
			pred, ok := predicates[v.Predicate]
			if !ok {
				panic("normalize: unknown variant predicate " + v.Predicate)
			}
			m.variants = append(m.variants, variant{pred: pred, m: parseEntry(v.Map)})
		}
		if re.Default != nil {
			m.def = parseEntry(*re.Default)
		}
		return m
	}
	cm := &carMap{
		object:       re.Object,
		ts:           strOr(re.Ts),
		owningPID:    re.OwningPID,
		owningOffset: re.OwningOffset,
		parentPID:    re.ParentPID,
		guid:         parseGUID(re.Guid),
		props:        parseProps(re.Props),
		keep:         re.Keep,
	}
	if re.Action != nil {
		cm.action = *re.Action
	}
	return cm
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseProps(m map[string]any) map[string]src {
	out := make(map[string]src, len(m))
	for k, v := range m {
		out[k] = parseSource(v)
	}
	return out
}

func parseGUID(m map[string]any) guidSpec {
	if v, ok := m["none"]; ok {
		if b, _ := v.(bool); b {
			return guidSpec{kind: guidNone}
		}
	}
	if v, ok := m["marker"]; ok {
		return guidSpec{kind: guidMarker, marker: parseSource(v)}
	}
	if v, ok := m["field"]; ok {
		return guidSpec{kind: guidField, field: v.(string)}
	}
	if v, ok := m["fields"]; ok {
		return guidSpec{kind: guidFields, fields: strList(v)}
	}
	panic("normalize: bad guid spec in mappings.yaml")
}

func strList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		panic("normalize: expected a list in mappings.yaml")
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.(string)
	}
	return out
}

// parseSource turns a YAML source node (string = field; single-key map = marker)
// into the src tree, recursing through nested markers.
func parseSource(node any) src {
	switch v := node.(type) {
	case string:
		return field(v)
	case map[string]any:
		if len(v) != 1 {
			panic("normalize: a source marker must be a single-key map")
		}
		for key, val := range v {
			switch key {
			case "first":
				items, ok := val.([]any)
				if !ok {
					panic("normalize: first: expects a list")
				}
				srcs := make([]src, len(items))
				for i, it := range items {
					srcs[i] = parseSource(it)
				}
				return first(srcs...)
			case "basename":
				return basename(parseSource(val))
			case "user_from_hive":
				return userFromHive(parseSource(val))
			case "transport":
				return transport(parseSource(val))
			case "family":
				return family(parseSource(val))
			case "ext":
				return ext(parseSource(val))
			case "exe_path":
				return exePath(parseSource(val))
			case "proc_guid":
				return procGUID(parseSource(val))
			case "const":
				return constS(val)
			default:
				panic("normalize: unknown source marker " + key)
			}
		}
	}
	panic("normalize: bad source node in mappings.yaml")
}
