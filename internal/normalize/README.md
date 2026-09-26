# normalize — the plugin → CAR delegation table

`mappings.yaml` (embedded via `go:embed`) is the static delegation table the
normalizer loads: one entry per plugin — the CAR object it yields, the
action, the timestamp field, the identity that becomes the CAR guid, the
owning-process link, and how each raw field maps to a canonical CAR
property. **Data only** — the marker resolvers and variant predicates are
named Go functions this package binds by name, so a mapping that uses the
existing resolvers and predicates is a data edit with no Go change. A
mapping that needs a **new** resolver or predicate adds that one Go
function first; an unknown name is refused at load time (the package
panics at init), never silently ignored.

## Source expression grammar

A prop or guid marker value is one of:

| expression | meaning |
| ---------- | ------- |
| `"Field"` | the raw field's value |
| `{first: [srcA, srcB, …]}` | the first non-blank source |
| `{basename: src}` | ntpath basename of src |
| `{ext: src}` | lowercase extension of src (no dot) |
| `{transport: src}` | L4 protocol from a Proto string (`"TCPv4"` → `"TCP"`) |
| `{family: src}` | address family from a Proto string (`"TCPv4"` → `"ipv4"`) |
| `{user_from_hive: src}` | the profile user parsed from a hive path |
| `{exe_path: src}` | the executable path parsed from a command line |
| `{proc_guid: src}` | `proc-<hex>` from an `_EPROCESS` offset field |
| `{file_guid: src}` | `file-<hex>` from a `FILE_OBJECT` offset field — the same kernel-pointer convention as `proc_guid` |
| `{const: <literal>}` | a constant the observation itself proves |

`guid:` takes `{field: X}`, `{fields: [..]}`, `{marker: <src>}` or
`{none: true}`. A map with `variants` (ordered `{predicate, map}` entries)
plus `default` splits one plugin across objects (a bound socket vs. a
connection flow).

## supersedes

An `anamnesis.*` plugin supersedes the built-in it improves on: when the
new plugin's JSONL is present, the old one's is skipped at store-build
time.
