// Package car holds the shared record/event types for the CAR pipeline. Both are
// string-keyed maps — the faithful Go analogue of the original Python dicts — so the
// normalize/enrich/store/timeline logic ports across directly. A Record is one raw
// collector row; an Event is one normalized CAR event.
package car

// Record is one raw record as a collector emits it (mirrors a Volatility
// per-plugin JSONL row: named columns → values).
type Record = map[string]any

// Event is one normalized MITRE CAR event.
type Event = map[string]any
