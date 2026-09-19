// Package value holds the loose value coercions the CAR pipeline needs. Records
// and events are map[string]any (the faithful analogue of the original Python
// dicts): values arrive as native Go integers from the collectors, or as
// json.Number from JSONL loaded with a number-preserving decoder (never float64,
// so 64-bit offsets keep full precision). These helpers read them uniformly.
package value

import (
	"encoding/json"
	"strconv"
)

// IsBlank reports whether v is one of the pipeline's "empty" sentinels: nil, "" or
// "-" (normalize._blank).
func IsBlank(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return s == "" || s == "-"
	}
	return false
}

// Str renders v the way Python's str() would for the values we handle — used for
// path/regex work on fields that are logically strings. Integers render in
// base 10 (json.Number already is its own text).
func Str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return ""
	}
}

// Int coerces v to an int64 (pids, tids — small identity ints). ok is false when
// v is nil or not an integer-ish value.
func Int(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case uint64:
		return int64(t), true
	case float64:
		return int64(t), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			// a float-formatted number (e.g. "10.0") still yields an int
			if f, ferr := t.Float64(); ferr == nil {
				return int64(f), true
			}
			return 0, false
		}
		return n, true
	case string:
		n, err := strconv.ParseInt(t, 0, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// Uint coerces v to a uint64 — for kernel object addresses / offsets, which on
// x64 exceed int64 (canonical higher-half VAs). Exact for native uint64 and for
// json.Number; a decimal or 0x-prefixed hex string is parsed.
func Uint(v any) (uint64, bool) {
	switch t := v.(type) {
	case uint64:
		return t, true
	case int64:
		return uint64(t), true
	case int:
		return uint64(t), true
	case float64:
		return uint64(t), true
	case json.Number:
		if n, err := strconv.ParseUint(t.String(), 10, 64); err == nil {
			return n, true
		}
		if f, err := t.Float64(); err == nil {
			return uint64(f), true
		}
		return 0, false
	case string:
		if n, err := strconv.ParseUint(t, 0, 64); err == nil {
			return n, true
		}
		return 0, false
	default:
		return 0, false
	}
}
