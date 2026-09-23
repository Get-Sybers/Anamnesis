# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking: the engine is always offline — the runtime symbol options are
  gone.** The `--symbols` / `--symbols-online` flags, the
  `ANAMNESIS_SYMBOLS_DIR` / `ANAMNESIS_SYMBOLS_ONLINE` env variables and the
  `symbols_dir` / `symbols_online` batch-summary keys are removed;
  `OpenOptions` loses `SymbolsDir` / `SymbolsOnline` (the former was read
  nowhere). PDB symbols are a baked dependency of the container image now: the
  GoDFIR-toolz build seeds a `Symbols/` cache beside `vmm.so` at build time,
  and at open the engine stages that cache into `/tmp` when it is read-only —
  mirroring MemProcFS's own Linux fallback (an unwritable `<lib>/Symbols` is
  silently swapped for `/tmp`, so a read-only baked cache would otherwise
  never be read). `-disable-symbolserver` is now passed unconditionally.
- Batch input contract normalized to the family standard: the batch orchestrator
  now reads `ANAMNESIS_INPUT_DIR` (default `/input`) for image discovery. During
  transition, `ANAMNESIS_MEMORY_DIR` is still accepted as a fallback (with a
  deprecation notice on stderr when used).
- Batch JSON summary key renamed from `memory_dir` to `input_dir`.
- **Breaking: the collector/plugin-id family `windows.piiat.*` is renamed
  `windows.anamnesis.*`** (processes, threads, modules, network, files, access,
  sessions, registry) — the last of the pre-rename naming. The ids flow through
  `--plugins` / `ANAMNESIS_PLUGINS` selection, the `plugins/<plugin>.jsonl`
  filenames, the `supersedes` table and `car.db` provenance. Output trees written
  by earlier releases keep the old names; rerun the tool (or `ANAMNESIS_FORCE=1`)
  to re-key them.

## [2.0.0] - 2026-09-19

**Renamed to anamnesis, and the Volatility 3 (Python) engine is gone.** anamnesis
is a pure-Go memory-forensics tool built on
[MemProcFS](https://github.com/ufrisk/MemProcFS) — no Volatility, no Python. The
**CAR output contract is preserved**: the same `car.db` (13-object SQLite store),
`timeline.json`, and per-object CSVs, keyed on the same `_EPROCESS`-offset process
identity (`guid = proc-<hex>`, the `memory_proc_offset` join key byakugan consumes
1:1).

- **Engine.** MemProcFS via [gomemprocfs](https://github.com/sergeyzav/gomemprocfs)
  (purego, no cgo) — the `vmm` library is loaded at runtime, so the binary stays
  `CGO_ENABLED=0`. Compiled in with the `memprocfs` build tag; the default build
  carries a clear "no backend" stub so the pipeline builds and tests with no
  native library.
- **Pipeline ported to Go.** normalize → enrich → store → timeline, a faithful
  port of the original Python package, with SQLite via the cgo-free
  `modernc.org/sqlite`. Every case from the old `tests/test_car_pipeline.py` is a
  Go table test and passes (definitive/heuristic linking, host identity, session
  collapse, MFT merge, ProfileList SID resolution, dedupe, malfind overlay).
- **Collectors** replace the Volatility plugins, keeping the same plugin names and
  record fields, so the CAR maps and the downstream contract are unchanged. Every
  spoke still carries the owning `_EPROCESS` offset for definitive links; a Process
  handle's object IS the target `_EPROCESS`, so access-target links are definitive.
- **CLI + env-driven batch** (`ANAMNESIS_*`) reproduce the old single-image CLI and
  the self-orchestrating container contract (one JSON summary line, exit 0/1/2).
- **Removed.** The old Python package, the `windows.piiat.*` Volatility
  plugins, the `jsonl_dfir` renderer, and the `docker/` Volatility image — the
  hardened image is now built by GoDFIR-toolz around the Go binary + MemProcFS libs.

On-target validation (a real image + the vmm library) is pending for a few engine
mappings: process create time, the Hidden flag, thread start-module resolution,
SID→name, and the forensic MFT/filescan/malfind collectors — all marked
`TODO(on-target)` in `internal/memprocfs`.

## [1.0.0] - 2026-08-29

First stable release. PIIAT-Mem turns a memory image into a **MITRE CAR** event
store and timeline — Plaso-shaped (extract → normalize → enrich → store →
output) — consolidating the 0.2–0.4 development arc into a stable interface:

- The custom **`windows.piiat.*` plugin family** (processes, threads, modules,
  files, network, sessions, registry): each spoke emits the owning `_EPROCESS`
  offset for **definitive** process links — `guid` is the reuse-proof kernel
  identity, never the reused PID.
- A **SQLite CAR-event store** (the `.plaso` analogue) keyed on the vendored
  `car_data_model.json` (MITRE's authoritative 13-object model), with a wide
  JSONL timeline (`timestamp, car_object, car_action`, every property null or
  not) and per-object CSVs.
- **Audited field completeness**: every canonical CAR property is filled from the
  image or is an honest null — host identity, process token identity / cwd /
  integrity_level / env_vars, thread start_function, MFT-derived file times,
  and process `access` events from handles.
- **malfind as a timeline overlay** populated by store retrieval — a trigger,
  not a stored record.
- Hardened, network-isolated container backend; consumed by the DX_DFIR
  volatility lane through this tool's CLI.

Detailed change history for the pre-1.0 milestones is retained below.

## [0.4.0] - 2026-08-29

### Added
- **The windows.piiat.\* plugin family** (epic #1 follow-on): a custom plugin per
  CAR object, each spoke emitting **`OwnerOffset`** — the owning `_EPROCESS`
  address — so enrichment links process context **definitively** (the kernel's
  own pointer, immune to PID reuse) instead of by the heuristic PID join:
  - `windows.piiat.threads` — thread scan with OwnerOffset, kernel + user stack
    fields (TEB via the rebuilt process layer), union-safe ExitTime (gated on the
    TERMINATED flag).
  - `windows.piiat.modules` — per-process PEB walk with OwnerOffset (Win10
    address-mask normalization so offsets join psscan's identically).
  - `windows.piiat.files` — handle-enumerated files WITH owners: the capability
    filescan can never provide; one CAR file event per (FILE_OBJECT, process).
  - `windows.piiat.network` — netscan with the owner `_EPROCESS` pointer
    surfaced, surviving owner teardown on stale sockets.
  - `windows.piiat.sessions` — per-process token identity: the AuthenticationId
    **LUID** (the real CAR `login_id`, matching event-log TargetLogonId), SID and
    resolved user; user_session identity is now the LUID, not the TS session
    number.
  - `windows.piiat.processes` gained token-derived `Sid`/`User`/`LogonId`
    (native CAR process user/sid — no weak join needed).
- Enrichment: a two-tier owner link — `link_confidence="definitive"` when the
  spoke's OwnerOffset matches a process offset, falling back to the create-time
  windowed PID join (`"heuristic"`).
- Registry `user` resolution for SID-form hives (`\REGISTRY\USER\S-1-5-...`)
  via the image's OWN SOFTWARE-hive ProfileList mapping (SID →
  ProfileImagePath basename); hive FILE paths now also cover
  `ServiceProfiles\<name>\` (service-account NTUSER.DAT).

### Added (completeness pass — epic #1 capstone)
- A 10-agent per-object **field-coverage audit** (every canonical CAR property
  classified filled / fillable-but-missed / honestly-unfillable against a real
  store) drove the final fills:
  - **hostname/fqdn on every object** from the image's OWN registry
    (ComputerName + Tcpip Hostname/Domain/DhcpDomain), following the same
    convention as the DX_DFIR log2timeline processor (identity resolved once
    per image, stamped on every event; a dotted name IS the fqdn). A flow's
    src_hostname/src_fqdn get the same (src = the local endpoint).
  - process.current_working_directory (PEB CurrentDirectory.DosPath) and
    process.integrity_level (token S-1-16 mandatory label → low/medium/high/
    system) — new Cwd/IntegrityLevel plugin columns.
  - registry.new_content = the resident data (the content AFTER the asserted
    value_edit at LastWrite).
  - file.extension (lossless derivation from the path); spoke `ppid` inherited
    from the definitively-linked owner (file/service/flow).
  - service.image_path/exe parsed from Binary OR the registry ImagePath
    (stopped services included — 305→717/721 on the real dump); arguments stay
    in command_line.
  - socket.success = true by existence (a kernel socket object exists only
    after a successful bind/listen).
- Honest nulls documented per object (hashes/signers need unmapped file bytes;
  call traces are ephemeral; src_pid of thread creation is not recorded; …).
- **Process ACCESS events** — `windows.piiat.access`: an open Process-type
  handle is an observed "A holds access to B" fact; one CAR process event with
  `car_action="access"`, guid = the INITIATING process (per CAR), plus
  `access_level` (the granted mask), `target_pid`/`target_name`/`target_guid`
  (the target's offset-derived guid). Both sides' offsets follow psscan's
  convention; initiator context inherits definitively; the dedupe key includes
  target_guid + access_level so distinct targets never collapse.
- **NTFS times from memory-resident $MFT** — `windows.mftscan.MFTScan` (built-in)
  joins the run; enrichment merges its per-attribute rows into one file
  `create` event per record (`file-mft-<record#>`): name from the longest
  FILE_NAME form, `creation_time` from STANDARD_INFORMATION, and
  `previous_creation_time` where the FILE_NAME birth time differs — the
  timestomp tell recorded as data, the verdict left to the analyst.
- **malfind → timeline via store retrieval** (not persisted): a malfind region
  is a TRIGGER, not a record. It is NOT written to the store; at output time each
  region is joined by PID to the process we ALREADY extracted, and a CAR `module`
  timeline entry is populated from THAT stored record (guid, image_path,
  hostname/fqdn, user, create-time) plus the region detail malfind uniquely
  supplies (base_address, Protection, Tag, Disasm) in native. Unbacked
  (module_path null — the injection tell); timelined at the owning process's
  create time. `timeline.malfind_overlay`.
- **Fix:** process `access` events (which share the `process` object) were
  polluting the PID-fallback and offset process indexes, silently defeating
  offset-less links (e.g. malfind); the indexes now count only process `create`
  events.
- **`process.env_vars`** (PEB Environment block, capped excerpt) and
  **`thread.start_function`/Win32 variant** (pe_symbols export-name resolution)
  — the last provably-fillable audit items.

### Changed
- Default plugin set: the piiat.* family supersedes windows.thrdscan /
  dlllist / netscan / sessions. A superseded built-in's JSONL is now SKIPPED at
  store-build when its successor's output is present (`mappings.SUPERSEDES`) —
  without this, the old and new user_session identity schemes (TS session
  number vs token LUID) would double-count every logon.
- Adversarial-review fixes (4 dimensions × refuters over the family):
  - every spoke plugin now normalizes `OwnerOffset` to psscan's offset
    convention (mask-normalized virtual on Win10, PHYSICAL before that) — this
    was modules-only, so on pre-Win10 images the definitive tier would have
    silently degraded to PID heuristics for 4 of 5 spokes.
  - well-known account names are canonicalized store-wide in enrichment
    (S-1-5-18 → "Local System", S-1-5-19 → "Local Service", S-1-5-20 →
    "Network Service") so `user` means the same string in every table.
  - a session row whose token is unreadable (no LUID) no longer becomes a
    phantom timelined login — it asserts nothing beyond the process row.
  - thread `start_address`/`start_module` now always come from the SAME source
    pair (Win32); mixing the Win32 address with the kernel path could assert an
    injected address lives in a legitimate module.

## [0.3.0] - 2026-08-29

### Added
- **The CAR-event store** (epic #1): the pipeline is now Plaso-shaped —
  extract → normalize → store → output — and the deliverable is finished
  **MITRE CAR**, not raw plugin output:
  - `carmodel.py` + a vendored `car_data_model.json` (regenerated from MITRE's
    authoritative `mitre-attack/car` repo — 13 objects, incl. the
    `guid`/`parent_guid`/`target_guid` process identity).
  - `normalize.py` + `mappings.py`: every plugin's records map to CAR
    objects/actions/properties; the object identity (`guid`) is a memory object
    offset or natural key — never the reused PID. netscan/netstat rows split by
    kind: bound/LISTENING sockets become CAR **socket** events (no direction is
    asserted) and connections become **flow** events (src=local / dest=foreign
    by stated convention; `network_direction` stays null — a snapshot cannot
    know the originator). Flow/socket identity is the protocol+endpoint tuple
    (scan offsets aren't comparable across netscan/netstat and dual-stack twins
    share one offset).
  - `enrich.py`: process-context links (`owning_guid`, `parent_guid`) resolved by
    PID within a create-time window and marked `link_confidence="heuristic"`
    (PID reuse makes bare-PID joins non-definitive); inherited properties fill
    only nulls; windows.sessions rows collapse to one login per session and feed
    `process.user`; same-guid duplicates (netscan/netstat) collapse.
  - `store.py`: `out/car.db` (SQLite, the `.plaso` analogue) — one table per CAR
    object (header + canonical properties) + `image_context` for non-CAR
    metadata (banners, windows.info).
  - `timeline.py` reworked into the output stage: `timeline.json` is now the
    **wide CAR timeline** (timestamp, car_object, car_action, every CAR property
    null or not); `--format csv` writes one CSV per CAR object under `out/car/`.
  - a unit-test suite (`tests/`) over normalize/enrich/store/output.

### Changed
- **Breaking:** `timeline.json` schema replaced (was
  `{timestamp, plugin, artifact, description, …}`; now the wide CAR event form),
  and `--format csv` writes per-object CSVs instead of a single `timeline.csv`.
  `--no-timeline` now skips only the rendered outputs — the `car.db` store is
  always built.

## [0.2.0] - 2026-08-29

### Changed
- **Breaking:** the two custom plugins now live in a `windows.piiat` subpackage,
  following the built-in Volatility naming (lowercase modules; registry-style
  grouping like `windows.registry.*`), and are referenced by the shorthand the
  rest of the pipeline uses:
  - `dfir_processes.DfirProcesses` → `windows.piiat.processes` (class
    `Processes`, now at `plugins/windows/piiat/processes.py`)
  - `dfir_registry.DfirRegistry` → `windows.piiat.registry` (class
    `Registry`, now at `plugins/windows/piiat/registry.py`)
  Anything selecting the old `dfir_processes.DfirProcesses` /
  `dfir_registry.DfirRegistry` identifiers must switch to the new names.

### Added
- `--no-timeline` — write only the raw per-plugin JSONL under `<out>/plugins/`,
  skipping the merged timeline. For automated consumers (e.g. the DX_DFIR CAR
  lane) that ingest the raw output and build their own timeline downstream.
- `--list-plugins` — print the default plugin set as a JSON list and exit, so a
  consumer can name the plugins it wants without hardcoding a second copy.
- `runner.ALL_PLUGINS` — the default plugin set, exported (also behind
  `--list-plugins`).
- `runner.run_plugin` / `run_all` gained a `symbols_online` param; the CLI's
  `--symbols-online` now flows through it instead of monkeypatching
  `container.run`.

## [0.1.0] - 2026-08-28

### Added
- Initial release. `piiat-mem -f <image> -o <out>` runs Volatility 3 over a
  memory image and writes a time-ordered timeline (`timeline.json` JSONL or
  `--format csv`) alongside the raw per-plugin JSONL.
- Custom Volatility 3 plugins: `dfir_processes.DfirProcesses` (psscan-based
  process records with full image path, parent path and loaded DLLs, unlinked
  processes flagged) and `dfir_registry.DfirRegistry` (RECmd-style target keys
  read from in-memory hives).
- Flat `jsonl_dfir` renderer — one JSON object per TreeGrid node.
- Minimal hardened Volatility 3 container (uid 0 renamed and locked, no shell,
  no package manager, runs as uid 2000); every run is `--cap-drop ALL
  --security-opt no-new-privileges --read-only --network none` (network only
  with `--symbols-online`). `--native` runs an installed Volatility 3 instead.
