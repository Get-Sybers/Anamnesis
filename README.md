# PIIAT-Mem — Put It In A Timeline (Memory)

Point it at a memory image; get a **MITRE CAR** event store and timeline, built
from [Volatility 3](https://github.com/volatilityfoundation/volatility3). The
pipeline is Plaso-shaped — **extract → normalize → store → output** — and the
deliverable is finished [MITRE CAR](https://car.mitre.org/data_model/): every
extractable record becomes a CAR **object** doing an **action** at a
**timestamp**, carrying that object's canonical **properties**. The analysis
runs inside a **minimal hardened container** by default (no shell, no package
manager, uid 0 renamed and locked, `--cap-drop ALL --read-only --network none`),
or natively against an installed Volatility 3.

```
piiat-mem -f memory.raw -o out/                 # CAR store + wide JSONL timeline
piiat-mem -f memory.raw -o out/ --format csv    # CAR store + one CSV per CAR object
piiat-mem -f memory.raw -o out/ --native        # use an installed volatility3
piiat-mem -f memory.raw -o out/ --symbols-online  # allow ISF symbol download (network)
```

Output:

```
out/plugins/<plugin>.jsonl   raw per-plugin Volatility output (traceability)
out/car.db                   the CAR-event store (SQLite) — the primary artifact
out/timeline.json            wide CAR timeline: timestamp, car_object, car_action,
                             every CAR property (null or not), links + provenance
out/car/<object>.csv         (--format csv) one CSV per CAR object instead
```

**Identity is definitive, never guessed.** A process's CAR `guid` is synthesized
from its `_EPROCESS` offset — the kernel's reuse-proof object identity — because
the OS reuses PIDs. Spoke events (threads, modules, flows, services) are linked
to their owning process by PID **within a create-time window** and honestly
marked `link_confidence="heuristic"`; inherited process context (user, exe, …)
fills only null properties, never overwriting a natively-extracted value.
Events with no timestamp (files, services, drivers from memory) live in the
store and the CSVs but not on the timeline. Bound/listening sockets are CAR
**socket** events (no connection, so no direction is asserted); actual
connections are CAR **flow** events where, by stated convention, `src_*` is the
LOCAL endpoint and `dest_*` the FOREIGN one — a memory snapshot cannot know the
originator, so `network_direction` stays null and consumers must not infer it.
See [docs/design/car-store.md](docs/design/car-store.md).

## What it runs

Each plugin's records normalize to one CAR object. The **`windows.piiat.*`
family** covers every object memory can supply, and every piiat spoke emits
`OwnerOffset` — the owning `_EPROCESS` address — so its process link is
**definitive** (`link_confidence="definitive"`), not a reused-PID guess:

| Plugin | CAR object | action | time | owner link |
|---|---|---|---|---|
| `windows.piiat.processes` | process | create | create time (psscan; + token Sid/User/LogonId) | — (the hub) |
| `windows.piiat.threads` | thread | create | thread create time (+ stack fields) | definitive |
| `windows.piiat.modules` | module | load | module load time | definitive |
| `windows.piiat.network` (connections) | flow | start | socket created time | definitive |
| `windows.piiat.network` (bound/LISTENING) | socket | listen | socket created time | definitive |
| `windows.piiat.files` | file | — | — (store-only) | definitive (via handles — filescan can never say whose) |
| `windows.piiat.registry` | registry | value_edit | key last-write time | user via hive path / ProfileList |
| `windows.piiat.sessions` | user_session | login | earliest process create per logon **LUID** | definitive |
| `windows.svcscan` | service | — | — (store-only) | heuristic (pid) |
| `windows.modules` | driver | load | — (store-only) | — (kernel) |
| `windows.filescan` | file | — | — (store-only; ownerless FILE_OBJECT scan) | none |
| `windows.netstat` | flow / socket | start / listen | socket created time | heuristic (pid) |

`windows.pslist` still runs (it flags `Hidden` processes by contrast) and
`banners.Banners` / `windows.info` become **image-context metadata** in the
store's `image_context` table — they are not CAR objects.

### Custom plugins
- **`windows.piiat.processes`** — one row per process via `psscan`
  (pool-tag scanning, so rootkit-unlinked processes are still found), each
  carrying PID/PPID, the full image path and command line from the PEB, the
  parent's full path, loaded DLLs, and a `Hidden` flag for processes the active
  list missed. It rebuilds the process address space from the DTB so the PEB
  resolves even for unlinked processes.
- **`windows.piiat.registry`** — reads a curated list of high-value keys out
  of the hives resident in memory and emits one row per value (Hive, Key,
  ValueName, ValueType, ValueData, LastWrite). Override with `--plugins` or
  the plugin's `--targets`.

## Backends

- **Container (default)** — the hardened `dfir/volatility:latest` image. Build it:
  ```
  docker build -t dfir/volatility:latest -f docker/Dockerfile docker
  ```
  The plugins and the `jsonl_dfir` renderer are bind-mounted read-only; the ISF
  symbol cache is the one writable mount. No network unless `--symbols-online`.
- **Native (`--native`)** — an installed `volatility3` (`pip install
  piiat-mem[native]`). The renderer is imported so Volatility discovers
  `-r jsonl_dfir`, then the CLI runs in-process.

## Install

```
pip install .            # the piiat-mem CLI (container backend)
pip install .[native]    # also pull in volatility3 for --native
```

## In a pipeline

PIIAT-Mem stays a standalone tool inside a larger pipeline: a consumer clones
this repo at a pinned commit and bakes it into its own hardened image with
Volatility 3 in-process (`get-sybers/piiat-mem`, built by GoDFIR-toolz's
`piiat-mem/Dockerfile`, is exactly that), then drives PIIAT-Mem **through its
CLI** (`python3 -m piiat_mem --native …`) — one invocation per image, as an
automated consumer, not by importing its internals. It never has to
re-implement the runner, the `jsonl_dfir` renderer or the plugin set. Two flags
exist for exactly that automated use:

```
piiat-mem -f mem.raw -o out/ --plugins windows.pslist,windows.piiat.processes --no-timeline
piiat-mem --list-plugins        # the default plugin set, as JSON
```

`--no-timeline` skips only the rendered views (timeline/CSVs) — the raw
`out/plugins/<plugin>.jsonl` and the `car.db` store are always written (a
consumer may ingest either); `--list-plugins` lets a consumer discover the
plugin names without hardcoding a second copy. It is the memory-forensics
engine behind the DX_DFIR volatility lane.

## License

MIT — see [LICENSE](LICENSE).
