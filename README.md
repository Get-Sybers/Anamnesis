# anamnesis — memory image to a MITRE CAR timeline (native, no Volatility)

Point it at a memory image; get a **MITRE CAR** event store and timeline. anamnesis
is a **pure-Go** memory-forensics tool built on
[MemProcFS](https://github.com/ufrisk/MemProcFS) — **no Volatility, no Python**. The
pipeline is Plaso-shaped — **extract → normalize → store → output** — and the
deliverable is finished [MITRE CAR](https://car.mitre.org/data_model/): every
extractable record becomes a CAR **object** doing an **action** at a **timestamp**,
carrying that object's canonical **properties**.

anamnesis keeps the same CAR output contract (`car.db`, `timeline.json`,
per-object CSVs) but replaces the Volatility 3 Python engine with a native one.
See [docs/design/native-engine.md](docs/design/native-engine.md).

```
anamnesis -f memory.raw -o out/                 # CAR store + wide JSONL timeline
anamnesis -f memory.raw -o out/ --format csv    # CAR store + one CSV per CAR object
anamnesis -f memory.raw -o out/ --no-timeline   # raw per-plugin JSONL + car.db only
anamnesis --list-plugins                        # the default collector set, as JSON
```

Output:

```
out/plugins/<plugin>.jsonl   raw per-collector output (traceability)
out/car.db                   the CAR-event store (SQLite) — the primary artifact
out/timeline.json            wide CAR timeline: timestamp, car_object, car_action,
                             every CAR property (null or not), links + provenance
out/car/<object>.csv         (--format csv) one CSV per CAR object instead
```

**Identity is definitive, never guessed.** A process's CAR `guid` is synthesized from
its `_EPROCESS` virtual address — the kernel's reuse-proof object identity — because
the OS reuses PIDs. Every spoke (threads, modules, handles, flows) carries its owning
`_EPROCESS` offset (`OwnerOffset`), so its process link is **definitive**
(`link_confidence="definitive"`), not a reused-PID guess; only where no offset is
available does the `(pid, create-time window)` join apply, honestly marked
`heuristic`. This is exactly the `memory_proc_offset` identity the downstream CAR
engine (byakugan) joins on. See [docs/design/car-store.md](docs/design/car-store.md).

## What it runs

Each collector maps to one CAR object, keeping its plugin name (the output and
idempotency contract). The native source is MemProcFS; the record shape is unchanged.

| collector | CAR object / action | source (MemProcFS) |
|---|---|---|
| `windows.anamnesis.processes` | process / create | process list + PEB/token (EPROCESS VA = guid) |
| `windows.anamnesis.threads` | thread / create | per-process thread list (+ OwnerOffset) |
| `windows.anamnesis.modules` | module / load | per-process module list (+ OwnerOffset) |
| `windows.anamnesis.network` | flow / socket | net list (+ OwnerOffset) |
| `windows.netstat` | flow / socket | net list (second view) |
| `windows.anamnesis.files` | file / access | per-process File handles (+ OwnerOffset); guid = the FILE_OBJECT |
| `windows.anamnesis.access` | process / access | per-process Process handles (target = object EPROCESS) |
| `windows.anamnesis.sessions` | user_session / login | process token LUID |
| `windows.svcscan` | service / enumerate | service list |
| `windows.modules` | driver / load | kernel driver list |
| `windows.filescan` | file (store-only) | forensic file scan |
| `windows.mftscan.MFTScan` | file / create | forensic NTFS MFT |
| `windows.malfind` | (trigger, overlay) | VAD private+executable regions |
| `windows.info`, `banners.Banners`, `windows.pslist` | image_context | version/build + active list |

## Build

anamnesis is a single static binary (`CGO_ENABLED=0`). The native memory engine is
compiled in with the `memprocfs` build tag and calls the MemProcFS `vmm` shared
library at runtime (via purego — no cgo):

```
make build            # default build (the CAR pipeline + CLI; engine backend stubbed)
make build-memprocfs  # the real build: -tags memprocfs, links the MemProcFS engine
make test             # unit tests (the full CAR pipeline, no memory image needed)
```

The `memprocfs` build needs the MemProcFS `vmm.so` (+ `leechcore.so`) at runtime;
point at it with `--lib` or `ANAMNESIS_VMM_LIB` (default `/opt/anamnesis/lib/vmm.so`).
The hardened `get-sybers/anamnesis` image (built by
[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz)) bundles the binary and the
libraries.

## In a pipeline

anamnesis stays a standalone tool inside a larger pipeline. In **DX_DFIR** it runs as
the hardened, env-driven `get-sybers/anamnesis` container: with no arguments it
discovers every image under `ANAMNESIS_INPUT_DIR` and writes
`<out>/<image>/plugins/<plugin>.jsonl` + `car.db`, printing one JSON summary line —
a drop-in for the previous memory-lane container invocation.

```
docker run --rm --network none --read-only --tmpfs /tmp \
  -e ANAMNESIS_PLUGINS= -e ANAMNESIS_FORCE=0 \
  -v "$input_dir:/input:ro" -v "$out:/out" \
  get-sybers/anamnesis:latest
```

The engine is always offline: PDB symbols come from the cache baked into the
image at build time (`Symbols/` beside `vmm.so`), never the network — there is
no symbol mount and no symbol variable.

Any CLI argument switches to single-image pass-through
(`... get-sybers/anamnesis -f /input/<image> -o /out`).

A collector blocked inside the native engine past `ANAMNESIS_STALL_TIMEOUT`
(a Go duration, default `5m`; `0` disables) is recorded as stalled
(`plugins/<plugin>.stalled`) and the batch re-execs itself: completed
collectors skip, the stalled one is retried, and after two stalls it is
skipped as failed — a poisoned native call never wedges the batch.

## License

MIT — see [LICENSE](LICENSE).
