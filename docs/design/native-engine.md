# anamnesis — native (Go / MemProcFS) engine

Tracks the rewrite that removes Volatility 3 (and its Python engine) from the
memory-forensics lane. This is the design of record for **anamnesis**, the pure-Go
successor to PIIAT-Mem. It supersedes the Volatility runner (`piiat_mem/runner.py`,
`piiat_mem/container.py`), the custom Volatility plugins (`plugins/windows/piiat/*`)
and the `jsonl_dfir` renderer — none of which survive the rename. It **keeps** the
CAR data model and the normalize → enrich → store → output pipeline, re-implemented
in Go, and it keeps the external output contract byte-for-byte where consumers depend
on it (see §4).

## 0. Why

PIIAT-Mem drives Volatility 3 — which *is* Python, irreducibly — over a memory image.
Even fused into a hardened container (`get-sybers/piiat-mem`), that means a Python
runtime, `pip install volatility3`, the ISF symbol dance, and the general weight and
speed of the Python engine. The DX_DFIR / GoDFIR-toolz ecosystem has already replaced
its other Python DFIR tools with static Go binaries (goevtx, gomft, gore, goese,
goprefetch, …). anamnesis brings the memory lane in line: a Go tool that parses the
image with a **native, non-Python engine** and emits the same finished MITRE CAR.

## 1. Engine: MemProcFS via purego

The memory parsing is done by [MemProcFS](https://github.com/ufrisk/MemProcFS) (Ulf
Frisk) — a mature, fast, C-based physical-memory analysis engine with no Python
anywhere. anamnesis calls its `vmm` shared library (`vmm.so` + `leechcore.so`)
through **purego**, so the Go binary itself stays `CGO_ENABLED=0`: the native library
is `dlopen`'d at runtime, not linked at build time. The image opens the dump with the
LeechCore `file://` device; no kernel driver, no live target.

- Go binding: a thin wrapper over `vmmdll` behind our own `internal/memprocfs.Engine`
  interface (our domain structs, not the binding's), so the binding is swappable and
  the collectors never see purego. Reference bindings:
  [`sergeyzav/gomemprocfs`](https://pkg.go.dev/github.com/sergeyzav/gomemprocfs)
  (purego, no cgo) and [`pineda89/vmmgo`](https://pkg.go.dev/github.com/pineda89/vmmgo).
- SQLite for `car.db` is [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite)
  — a pure-Go, cgo-free driver — so the whole binary builds without a C toolchain.
- The only runtime native artefacts are MemProcFS's own `.so` files, shipped beside
  the binary in the image (see §7). The base is therefore a minimal glibc image
  (distroless / debian-slim, hardened), **not** `FROM scratch` — MemProcFS's `.so`
  needs libc + the dynamic loader. This is the one deliberate departure from the
  pure-scratch GoDFIR pattern, and it is still no-Python, no-Volatility.

### 1.1 Symbols

MemProcFS resolves kernel/type offsets from its bundled `info.db` and, for full
fidelity, PDBs from the Microsoft Symbol Server on first use (the analogue of
Volatility's ISF fetch). anamnesis keeps the same offline-first posture as PIIAT-Mem:
default `--network none`, pre-seed a symbol/PDB cache; `--symbols-online`
(`ANAMNESIS_SYMBOLS_ONLINE`) is the knob that documents a run given network for the
fetch. Much of the process/handle/module/network surface resolves from `info.db`
alone (offline); PDBs mainly sharpen symbol-name resolution (e.g. thread start
function).

## 2. Architecture

```
cmd/anamnesis            CLI (single-image) + env-driven batch orchestrator
internal/
  memprocfs/             Engine interface + purego/vmmdll implementation (the ONLY native seam)
  collect/               collectors: Engine -> raw records (one map per artefact) + JSONL
  carmodel/              embeds car_data_model.json (13 objects) — the model of record
  normalize/             raw record -> one CAR event (port of mappings.py + normalize.py)
  enrich/                dedupe, link (definitive/heuristic), inherit (port of enrich.py)
  store/                 car.db (modernc sqlite), 1 table/object + image_context (port of store.py)
  timeline/              timeline.json (wide) + car/<object>.csv + malfind overlay (port of timeline.py)
```

**Static delegations live in YAML, not Go.** The mapping/config data is embedded
via `go:embed` and interpreted at load — Go carries only logic (marker resolvers,
predicates, collector functions), never the tables:

- `internal/normalize/mappings.yaml` — the per-plugin → CAR delegation table
  (object/action/timestamp/guid/props/keep, variant predicates) + `supersedes`.
- `internal/enrich/data.yaml` — the well-known-SID names + the inheritable-property list.
- `internal/collect/collectors.yaml` — the default collector set (run order) + the
  curated registry targets.
- `internal/carmodel/car_data_model.json` — the vendored MITRE model (upstream JSON).

Data flow (Plaso-shaped, unchanged from PIIAT-Mem): **extract → normalize → store →
output**. Collectors are the Volatility-plugin analogues; each emits raw records under
the **same field/column names** the old per-plugin JSONL used, so the normalize maps
(and the golden tests) port across verbatim. The raw per-collector JSONL is retained
for traceability under `plugins/<name>.jsonl` (see §4 on why the name stays).

### 2.1 Collectors ↔ MemProcFS ↔ CAR

Every collector keeps its PIIAT plugin *name* (the identity the pipeline and idempotency
key on) and emits the columns `normalize` already expects. The native source changes;
the record shape does not.

| collector (name kept) | CAR object / action | MemProcFS source | fidelity note |
|---|---|---|---|
| `windows.piiat.processes` | process / create | `GetProcessInfoAll` (PID, PPID, `EPROCESS` VA, name, full path, cmdline, create time), PEB read, token via `/sys` | **`guid = proc-<hex EPROCESS VA>`**, `Offset = EPROCESS VA` — the definitive identity byakugan joins on (`memory_proc_offset`). `Hidden` = process seen by pool/scan but not the active list. |
| `windows.piiat.threads` | thread / create | `GetThreadList(pid)` (TID, create time, stack base/limit, start addr) + owning `EPROCESS` VA | emits `OwnerOffset` → **definitive** owner link |
| `windows.piiat.modules` | module / load | `GetModuleList(pid)` (base, full path, name, load time) + owning `EPROCESS` VA | emits `OwnerOffset` → **definitive** |
| `windows.piiat.network` | flow / socket | `GetNetList` (proto, endpoints, state, pid, create time) + owning `EPROCESS` VA | listener→socket, connection→flow (variant predicate unchanged) |
| `windows.piiat.files` | file (store-only) | `GetHandleList(pid)` filtered to File handles (path, granted access) + owning `EPROCESS` VA | one event per (FILE_OBJECT, observing process) — owners memory-native |
| `windows.piiat.access` | process / access | `GetHandleList(pid)` filtered to Process handles (target pid/name/`EPROCESS` VA, granted access) | initiator + target both by `EPROCESS` VA |
| `windows.piiat.registry` | registry / value_edit | `GetRegistrySubKeys`/`GetRegistryValues` over the curated key list (hive, key, value, type, data, last-write) | user via hive path / ProfileList (enrichment) |
| `windows.piiat.sessions` | user_session / login | token AuthenticationId LUID per process (`/sys` + token) | LUID identity = real `login_id` |
| `windows.svcscan` | service (store-only) | `GetServiceList` (name, pid, image path, cmdline, state) | pid → heuristic owner |
| `windows.modules` | driver / load | `GetKDriverList` (name, base, path) | kernel-global, no owner |
| `windows.netstat` | flow / socket | `GetNetList` (second view; dedupes against piiat.network by 5-tuple) | pid → heuristic |
| `windows.filescan` | file (store-only) | forensic VFS file scan (`/forensic/…`) — ownerless FILE_OBJECTs | none (no owner) |
| `windows.mftscan.MFTScan` | file / create | forensic NTFS MFT (`/forensic/ntfs/…`) — SI/FILE_NAME times | timestomp tell preserved (SI vs FN birth time) |
| `windows.malfind` | (trigger, not stored) | VAD walk: private, executable, non-image regions | overlay retrieves the stored process at output time |
| `windows.pslist` | image_context | active `GetProcessInfoAll` list | the Hidden contrast for processes |
| `windows.info`, `banners.Banners` | image_context | `ConfigGet` version/build + `GetKObjectList` metadata | image metadata, not CAR objects |

Anything MemProcFS cannot supply for a field stays **honestly null** — the same rule
PIIAT-Mem already follows (no near-miss fills; §3 of `car-store.md`).

## 3. Fidelity: the definitive-link guarantee is preserved

The value of PIIAT-Mem is that a spoke (thread/module/handle) links to its owning
process by the kernel's own pointer — the `_EPROCESS` object address — not by the
reused PID (`docs/design/car-store.md` §3). MemProcFS exposes each process's
`EPROCESS` virtual address (`GetProcessInfoAll`), and its per-process module/thread/
handle enumerations are produced *from* that `EPROCESS`, so anamnesis emits
`OwnerOffset = <owning EPROCESS VA>` on every spoke exactly as the Volatility
`windows.piiat.*` plugins did. `enrich` is unchanged: join on `OwnerOffset` →
`link_confidence="definitive"`, else the `(pid, create-time window)` join →
`"heuristic"`. `process.guid = "proc-<hex EPROCESS VA>"` and `native.Offset =
<EPROCESS VA>` are preserved verbatim, which is also the cross-source join key
byakugan declares in `sources/memory.yaml` (`identity.external: memory_proc_offset`).

## 4. Output contract (what must not break)

Downstream consumers were audited:

- **byakugan** (`sources/memory.yaml`): `input_pattern: car.db`, `mappings: []` —
  it passes PIIAT's finished CAR through **1:1** and joins on `memory_proc_offset`.
  **`car.db` is the hard contract.**
- **DX_DFIR** volatility lane: `docker run`s the image, reads the per-image output
  tree; the CAR lane feeds byakugan the `car.db`.

anamnesis therefore reproduces, per image:

- `car.db` — SQLite, **one table per CAR object** (13, from `car_data_model.json`) +
  `image_context`, the exact header + property columns of `store.py`, indexes on
  `guid` and `timestamp`. Same guid conventions, same `native` JSON (with `Offset`).
- `timeline.json` — wide JSONL, `_META` + the full property superset, timestamped
  events + the malfind overlay (standalone / non-`--no-timeline`).
- `car/<object>.csv` — per-object CSV (`--format csv`).
- `plugins/<name>.jsonl` — raw per-collector records, for traceability. The names
  stay the Volatility plugin ids (`windows.piiat.processes`, …) because the batch
  idempotency and PIIAT plugin-set selection (`--plugins`, `PIIAT/ANAMNESIS_PLUGINS`)
  key on them; the *columns* are anamnesis's own but mirror the old ones.

The env-driven batch contract (self-orchestrating container) is reproduced with the
renamed env vars (§6): discover images, per-plugin idempotency, one JSON summary line,
exit codes 0/1/2 — identical semantics to `piiat_mem_batch.py`.

## 5. Testing

- **Pipeline (normalize/enrich/store/timeline): fully tested in-repo, no target
  needed.** `tests/test_car_pipeline.py` is ported to Go table-driven tests verbatim
  (same synthetic records, same assertions) — this is the behavioral spec and proves
  parity with the Python pipeline.
- **Collectors: need on-target validation** — a real memory image plus the MemProcFS
  `.so`. They are structured against the documented `vmmdll` API and unit-tested with
  a fake `Engine`; field-level parity is validated on the standard corpora (LS24,
  M57, lonewolf) once the image + libs are present. This is called out at every
  collector as the remaining gate.

## 6. Rename: PIIAT-Mem → anamnesis

The user's directive is a full rename ("everything"). Layers:

1. **Tool / CLI / package / module** → `anamnesis` (this repo). Binary `anamnesis`;
   Go module `anamnesis`.
2. **Docker image** `get-sybers/piiat-mem` → `get-sybers/anamnesis`;
   **env contract** `PIIAT_*` → `ANAMNESIS_*` (GoDFIR-toolz Dockerfile + build-all.sh,
   DX_DFIR ansible volatility lane, `images.yml`, Go health check).
3. **GitHub repo** `Get-Sybers/PIIAT-Mem` → `Get-Sybers/Anamnesis` — done by the owner
   in GitHub settings, and it must happen **before the images are built**: the
   GoDFIR-toolz Dockerfile clones `Get-Sybers/Anamnesis` at the `sources.yml` pin, so
   the rename is a build prerequisite (GitHub redirects the old URL, but the rename
   should land first). Every cross-repo reference (`sources.yml` key + URL, byakugan
   `sources/memory.yaml` url, doc links) already points at the new name.
4. **Docs / branding** across all four repos: READMEs, `docs/`, CHANGELOGs, and the
   "Put It In A Timeline (Memory)" backronym.

## 7. Container (GoDFIR-toolz)

`docker/GoDFIR-toolz/anamnesis/Dockerfile` replaces the Python image: a Go build stage
(`CGO_ENABLED=0 go build` of the pinned anamnesis source) and a minimal hardened glibc
runtime carrying the `anamnesis` binary + MemProcFS `.so` files (fetched + checksum-
pinned from the MemProcFS release), the shared hardener (uid renamed/locked, no shell,
no package manager), and the same batch ENTRYPOINT semantics. No Python, no Volatility,
no `pip`. The DX_DFIR lane keeps `docker run … -v <mem>:/mem:ro -v <out>:/out …` with
`ANAMNESIS_*` env — a drop-in for the current `get-sybers/piiat-mem` invocation.

## 8. Phasing / status

1. Design doc (this file). ✅
2. CAR pipeline in Go (carmodel/normalize/enrich/store/timeline) + the ported golden
   tests — the tested core, no target needed. ✅
3. CLI + env-driven batch orchestrator (ANAMNESIS_* contract). ✅
4. `internal/memprocfs` binding (`-tags memprocfs`) + collector framework + collectors
   — compiles against gomemprocfs; runtime needs on-target validation. ✅ (build)
5. Volatility engine removed (Python package, plugins, renderer, old Dockerfile). ✅
6. Static delegation tables moved to embedded YAML (§2). ✅
7. GoDFIR-toolz image + DX_DFIR wiring + ecosystem rename sweep. ✅
8. **Prerequisite before building images:** the GitHub repo rename (§6.3).
9. Remaining: on-target validation on the standard corpora (field parity + the
   `TODO(on-target)` engine items); pin `MEMPROCFS_SHA256`.

