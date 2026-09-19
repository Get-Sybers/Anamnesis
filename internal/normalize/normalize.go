// Package normalize turns one raw collector record into one MITRE CAR event.
//
// Faithful port of the original Python normalize.py + mappings.py. Normalize
// applies the plugin's map (picking the matching variant where the plugin splits
// across objects) and returns one CAR event: car_object, car_action, timestamp,
// the synthesized guid (the object's reuse-proof identity), owning_pid/parent_pid
// (resolved to owning_guid/parent_guid during enrichment, with link_confidence),
// the canonical CAR properties, and _native (kept fields with no CAR home).
package normalize

import (
	"regexp"
	"strconv"
	"strings"

	"anamnesis/internal/car"
	"anamnesis/internal/value"
)

// The profile owner from a user-hive FILE path. Covers real renderings:
// \??\C:\Users\<name>\NTUSER.DAT, \Device\HarddiskVolumeN\Users\<name>\...,
// Documents and Settings\<name>\ (XP), and Windows service profiles.
var reHiveUser = regexp.MustCompile(`(?i)(?:Documents and Settings|Users|ServiceProfiles)\\([^\\]+)\\`)

// Volatility's "no time" sentinels (epoch-zero renderings) — treated as no timestamp.
var reEpochZero = regexp.MustCompile(`^(1601-01-01|1970-01-01|0001-01-01|1600-12-)`)

// Layer-4 protocol / address family from Volatility's Proto ("TCPv4").
var reProto = regexp.MustCompile(`(?i)^([a-z]+?)(v(4|6))?$`)

// winBasename is ntpath.basename: the part after the last \ or / (whole string
// when neither is present).
func winBasename(s string) string {
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		return s[i+1:]
	}
	return s
}

// cleanTS returns a usable timestamp string, or nil (blank / epoch-zero sentinel).
func cleanTS(v any) any {
	if value.IsBlank(v) {
		return nil
	}
	s := value.Str(v)
	if reEpochZero.MatchString(s) {
		return nil
	}
	return s
}

// --- source markers (resolved against a record; markers nest) ----------------

type src interface{ resolve(rec car.Record) any }

type fieldSrc string

func (f fieldSrc) resolve(rec car.Record) any { return rec[string(f)] }

func field(name string) src { return fieldSrc(name) }

type firstSrc []src

func (fs firstSrc) resolve(rec car.Record) any {
	for _, s := range fs {
		if v := s.resolve(rec); !value.IsBlank(v) {
			return v
		}
	}
	return nil
}

func first(ss ...src) src { return firstSrc(ss) }

type basenameSrc struct{ s src }

func (b basenameSrc) resolve(rec car.Record) any {
	v := b.s.resolve(rec)
	if value.IsBlank(v) {
		return nil
	}
	return winBasename(value.Str(v))
}

func basename(s src) src { return basenameSrc{s} }

type userFromHiveSrc struct{ s src }

func (u userFromHiveSrc) resolve(rec car.Record) any {
	v := u.s.resolve(rec)
	if m := reHiveUser.FindStringSubmatch(value.Str(v)); m != nil {
		return m[1]
	}
	return nil
}

func userFromHive(s src) src { return userFromHiveSrc{s} }

type transportSrc struct{ s src }

func (t transportSrc) resolve(rec car.Record) any {
	v := t.s.resolve(rec)
	if value.IsBlank(v) {
		return nil
	}
	if m := reProto.FindStringSubmatch(value.Str(v)); m != nil {
		return strings.ToUpper(m[1])
	}
	return nil
}

func transport(s src) src { return transportSrc{s} }

type familySrc struct{ s src }

func (f familySrc) resolve(rec car.Record) any {
	v := f.s.resolve(rec)
	if value.IsBlank(v) {
		return nil
	}
	if m := reProto.FindStringSubmatch(value.Str(v)); m != nil && m[3] != "" {
		return "ipv" + m[3]
	}
	return nil
}

func family(s src) src { return familySrc{s} }

type constSrc struct{ v any }

func (c constSrc) resolve(rec car.Record) any { return c.v }

func constS(v any) src { return constSrc{v} }

type extSrc struct{ s src }

func (e extSrc) resolve(rec car.Record) any {
	v := e.s.resolve(rec)
	if value.IsBlank(v) {
		return nil
	}
	base := winBasename(value.Str(v))
	dot := strings.LastIndex(base, ".")
	if dot <= 0 { // no dot, or a leading-dot name (ntpath.splitext -> "")
		return nil
	}
	ext := strings.ToLower(base[dot+1:])
	if ext == "" {
		return nil
	}
	return ext
}

func ext(s src) src { return extSrc{s} }

type exePathSrc struct{ s src }

func (e exePathSrc) resolve(rec car.Record) any {
	v := e.s.resolve(rec)
	if value.IsBlank(v) {
		return nil
	}
	s := strings.TrimSpace(value.Str(v))
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return s[1 : 1+end]
		}
		return strings.Trim(s, `"`)
	}
	if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		return s[:i+4]
	}
	return strings.SplitN(s, " ", 2)[0]
}

func exePath(s src) src { return exePathSrc{s} }

type procGUIDSrc struct{ s src }

func (p procGUIDSrc) resolve(rec car.Record) any {
	v := p.s.resolve(rec)
	if v == nil {
		return nil
	}
	if u, ok := value.Uint(v); ok {
		return "proc-" + strconv.FormatUint(u, 16)
	}
	return nil
}

func procGUID(s src) src { return procGUIDSrc{s} }

// --- guid spec ---------------------------------------------------------------

type guidKind int

const (
	guidFields guidKind = iota // {"fields": [...]} -> "<obj>-<v1>-<v2>..."
	guidField                  // {"field": X}      -> rec[X] verbatim
	guidMarker                 // {"marker": m}     -> resolve(m)
	guidNone                   // {"none": True}    -> nil (assigned later)
)

type guidSpec struct {
	kind   guidKind
	field  string
	marker src
	fields []string
}

// resolveGUID mirrors normalize._guid. Only a MISSING (nil) component voids a
// fields-guid; "" is a legitimate identity value (a registry default value's name).
func (g guidSpec) resolve(obj string, rec car.Record) any {
	switch g.kind {
	case guidNone:
		return nil
	case guidMarker:
		return g.marker.resolve(rec)
	case guidField:
		return rec[g.field]
	default: // guidFields
		parts := make([]string, len(g.fields))
		for i, f := range g.fields {
			v, ok := rec[f]
			if !ok || v == nil {
				return nil
			}
			parts[i] = value.Str(v)
		}
		return obj + "-" + strings.Join(parts, "-")
	}
}

// --- the map + variant selection ---------------------------------------------

type variant struct {
	pred func(car.Record) bool
	m    *carMap
}

type carMap struct {
	object       string
	action       any // nil == None
	ts           string // "" == None (no field carries the timestamp)
	guid         guidSpec
	owningPID    string // "" == none
	owningOffset string
	parentPID    string
	props        map[string]src
	keep         []string
	variants     []variant
	def          *carMap
}

// selectMap picks the map for this record: the first matching variant, else the
// default (a plugin without variants IS its own map).
func selectMap(m *carMap, rec car.Record) *carMap {
	if len(m.variants) == 0 && m.def == nil {
		return m
	}
	for _, v := range m.variants {
		if v.pred(rec) {
			return v.m
		}
	}
	return m.def
}

// Normalize turns one raw record into one CAR event, or nil if the plugin has no
// CAR map.
func Normalize(plugin string, rec car.Record) car.Event {
	entry, ok := mappings[plugin]
	if !ok {
		return nil
	}
	m := selectMap(entry, rec)

	ev := car.Event{
		"car_object":      m.object,
		"car_action":      m.action,
		"timestamp":       nil,
		"guid":            m.guid.resolve(m.object, rec),
		"owning_pid":      lookup(rec, m.owningPID),
		"owning_offset":   lookup(rec, m.owningOffset),
		"parent_pid":      lookup(rec, m.parentPID),
		"owning_guid":     nil, // set in enrichment (create-time-window / offset join)
		"parent_guid":     nil, // set in enrichment
		"link_confidence": nil, // set in enrichment
		"source_plugin":   plugin,
		"_native":         nativeKept(rec, m.keep),
	}
	if m.ts != "" {
		ev["timestamp"] = cleanTS(rec[m.ts])
	}
	for carField, s := range m.props {
		ev[carField] = s.resolve(rec)
	}
	return ev
}

// lookup returns rec[name] when name is set (nil when absent), else nil — the
// analogue of `rec.get(m["owning_pid"]) if m.get("owning_pid") else None`.
func lookup(rec car.Record, name string) any {
	if name == "" {
		return nil
	}
	return rec[name]
}

func nativeKept(rec car.Record, keep []string) map[string]any {
	out := make(map[string]any, len(keep))
	for _, k := range keep {
		if v, ok := rec[k]; ok {
			out[k] = v
		}
	}
	return out
}
