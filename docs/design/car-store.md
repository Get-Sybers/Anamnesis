# CAR-event store — relational model (Phase 1)

This is the **relational design** the store is built on: the CAR
objects, what makes each event unique, how the objects relate, and the identity
key each object needs to **inherit** properties from a related entry. Source of
truth for objects / actions / properties: `internal/carmodel/car_data_model.json`
(vendored; regenerated from MITRE's own mitre-attack/car repo — see §7).

Scope: the **anamnesis processor** only. CAR-at-query-time still applies to the
artefacts we don't own; anamnesis is ours, so it emits finished CAR.

## 1. The objects — identity, action, timestamp (from memory)

Each CAR object is sourced from one Volatility plugin. "Timelineable" = memory
gives it a timestamp (so it appears on the timeline); the rest are stored and
join-able but carry no time.

| CAR object | memory plugin | unique identity | action | timestamp (source) | timelineable |
|---|---|---|---|---|---|
| process | `windows.piiat.processes` | `pid` | create | CreateTime | yes |
| thread | `windows.thrdscan` | `tgt_pid` + `tgt_tid` | create | create time | yes |
| module | `windows.dlllist` | `pid` + `module_path` (`base_address`) | load | LoadTime | yes |
| flow | `windows.netscan` / `netstat` (connected rows) | protocol + 5-tuple | start | Created | yes |
| socket | `windows.netscan` / `netstat` (bound/LISTENING rows) | protocol + local endpoint + pid | listen | Created | yes |
| user_session | `windows.sessions` | `logon_id` (+ `user`) | login | create time | yes |
| registry | `windows.piiat.registry` | `hive`+`key`+`value` | edit | LastWrite | yes |
| driver | `windows.modules` | `image_path` + `base_address` | load | — | no (store-only) |
| file | `windows.filescan` | `file_path` | — | — | no (store-only) |
| service | `windows.svcscan` | `name` (+ `pid`) | — | — | no (store-only) |

`banners` / `windows.info` are not CAR objects — they are **image-context
metadata** (kept in a side table, not `car_events`).

## 2. Relationships — `process` is the hub

Almost every object references the process it belongs to via **`pid`**. `process`
references its parent via `ppid`. `driver` is kernel-global (no process).

```
                                 ┌── ppid ──┐  (parent process)
                                 ▼          │
   thread ──tgt_pid─▶┐        ┌─────────────┴──┐
   thread ──src_pid─▶│        │   process(pid) │◀── pid ── module
   flow   ──pid─────▶├───────▶│                │◀── pid ── service (+ppid)
   file   ──pid─────▶│        └────────────────┘◀── pid ── registry
   user_session ─user/logon_id┘
   driver ── (standalone, kernel — hostname/fqdn only)
```

Foreign keys:

- `process.ppid  → process.pid`   (parent process; self-referential)
- `thread.tgt_pid → process.pid`  (thread runs in process) · `thread.src_pid → process.pid` (creator, for `remote_create`)
- `module.pid   → process.pid`    · `flow.pid → process.pid` · `file.pid → process.pid` · `registry.pid → process.pid`
- `service.pid  → process.pid`    · `service.ppid → process.pid`
- `user_session.user → process.user` (weak; or `login_id` where present)

The PIDs above are the *surface* the plugins expose. Because PIDs are **reused**,
the real join is on process **`guid` (= `_EPROCESS` offset)**, with PID only as a
fallback — see §3.

## 3. Inheritance — when can a property *definitively* be said to belong?

The logical test: **object A's property may be attributed to object B only if A
and B share a key that identifies the *same entity instance* beyond doubt.** A
non-unique key is a guess, not a proof.

**`pid` is not that key.** The OS **reuses** PIDs — after a process exits, its PID
is handed to a new, unrelated process. So a `pid` match in a memory image can join
across two *different* process instances. Attribution on bare `pid` is a
**heuristic**, never definitive.

**MITRE CAR already says so.** The authoritative CAR `process` object identifies a
process by **`guid`** ("global unique identifier for the initiating process"),
with **`parent_guid`** / **`target_guid`** for the parent and access-target links —
reuse-immune identities, distinct from `pid`/`ppid`. (The local
`car_data_model.json` is a 9-object subset that omits `guid` — see §7.)

**Memory has no Sysmon `guid`** (it is not stored in `_EPROCESS`). The
memory-native unique identity is the **`_EPROCESS` offset** — every process object
has a unique address in the image, and the kernel itself links threads, modules
and handles to a process **by pointer to that object**, not by PID. So:

> anamnesis **synthesizes CAR `guid` = the `_EPROCESS` offset** (the process's
> kernel-object identity). That becomes the definitive join key; `pid` is demoted
> to a plain attribute.

**Definitive vs heuristic, per link** — a spoke inherits process context
(`exe, image_path, command_line, user, sid, parent_*, fqdn, hostname`) via a
LEFT JOIN that fills a property **only where the spoke's own value is null**:

| link | what memory actually gives | verdict |
|---|---|---|
| module → process | `dlllist` walks **each process's** PEB — the row is *produced from* that `_EPROCESS`, so its offset is known at extraction | **definitive** (carry the owning offset) |
| thread → process | `thrdscan` gives the thread offset + `pid`; the owning `_EPROCESS` pointer is reachable but not currently emitted | **definitive if** we emit the owning-`_EPROCESS` offset; else `pid` = heuristic |
| flow → process | `netscan` gives owner `pid` only | **heuristic** (pid) |
| service → process | `svcscan` gives `pid` only | **heuristic** (pid) |
| process → parent | `ppid` is a *recorded* PID; the real parent may be dead/reused | **heuristic**; `parent_guid` from the parent `_EPROCESS` pointer (create-time ordered) is definitive |
| file → process | `filescan` finds global FILE_OBJECTs with **no owner** | **none** — needs handle enumeration; stays null |
| registry → user | the hive's **file path** (`…\<user>\NTUSER.DAT`) *is* that user's | **definitive by path** (not a join) |
| user_session → process | shares only `user` (+ time) | **heuristic** |

**Rule for the store:** key `process` on **`guid` (= `_EPROCESS` offset)**; carry
`pid`/`ppid` as attributes only. Populate a spoke's inherited properties by joining
on `guid` and mark those rows **definitive**; where only `pid` is available, join
on `pid` disambiguated by a create-time window and record
**`link_confidence = "heuristic"`** — never assert a reused-PID match as fact. Our
current process plugin resolves `ParentPath` by a bare PID→path map (§ processes.py);
that is a heuristic and Phase 2 replaces it with the offset/`parent_guid` link.

**Consequence for extraction (Phase 2):** the process plugin must emit the
`_EPROCESS` **`Offset`** (it does not today) so `guid` can be synthesized; a
*definitive* thread/module link needs the owning-`_EPROCESS` offset emitted too
(custom plugins that follow the pointer) — otherwise those links are honestly
marked heuristic.

## 4. What makes an event unique (distinct entry AND join target)

Composite identity per object = `(car_object, <identity>, timestamp, action)`.
Where the object's identity IS a memory object, the offset is the identity — not
the reused PID:

- **process `(guid = _EPROCESS offset)`** — `pid`+`create_time` only as a fallback
- thread `(_ETHREAD offset, tgt_tid)` · module `(owning guid, base_address|module_path)`
- flow `(protocol + 5-tuple)` · socket `(protocol, local endpoint, pid)` — NOT the
  scan offset: netscan's physical and netstat's virtual offsets aren't comparable,
  and dual-stack twins share one offset · driver `(image_path|module_name, base_address)`
- registry `(hive, key, value, last_write)` · user_session `(token AuthenticationId LUID — the real login_id)`
- file: filescan rows `(FILE_OBJECT offset)` — ownerless scan observations; piiat.files
  rows `(FILE_OBJECT offset, observing PID)` — one event per (file, process-holding-a-handle)
- service `(name)`

## 5. Store schema (SQLite, relational)

One **table per object** — its CAR properties (all nullable) — plus a common
event header on every table:

```
event_id (pk) · timestamp · car_object · car_action · guid · pid · owning_guid · link_confidence · source_plugin · source_image · _native (json: non-CAR fields kept, never faked into CAR columns)
```

`guid` (= `_EPROCESS` offset) is the process's identity and the shared join
column; `owning_guid` on a spoke is the FK to its process; `pid` is a plain
attribute. `link_confidence ∈ {definitive, heuristic}` records how an inherited
property was attributed (§3). Objects with no timestamp still populate their
table (join targets) but never reach the timeline.

## 6. Output (derived from the store)

- **per-object CSV** — `SELECT * FROM <object>` per table (that object's properties).
- **wide JSONL timeline** — `UNION ALL` across every object, projected onto the
  full property superset (absent properties → null), each row tagged
  `car_object` / `car_action` (and `link_confidence`), `ORDER BY timestamp`. Only
  timestamped rows appear; file / service / driver without a time remain
  store-only (still enrichment join targets).

## 7. car_data_model.json — refreshed to the authoritative model

`car_data_model.json` (repo root) has been regenerated from MITRE's own
`mitre-attack/car` repo (`docs/data_model/*.md`) — now the full **13 objects**
(was a 9-object subset): added **authentication, email, http, socket**, and
`process` regained **`guid`, `parent_guid`, `target_guid`** + the `access` action
(the reuse-immune identity §3 relies on). The refresh also picked up CAR's own
renames since the old file: `flow.protocol` → `transport_protocol` (+`application_protocol`,
`tcp_flags`), `registry.edit` → `key_edit`/`value_edit`, `user_session.logon_id` →
`login_id` (the interactive/local/rdp/remote actions folded into a `login_type`
field). `mappings.py` targets these authoritative names; the KQL `Car*` views still
use the old names and need the same alignment (deferred — see the volatility lane).

---

**Status:** implemented (v0.3.0), and §3's **definitive tier is now real**
(v0.4.0): the `windows.piiat.*` family — threads, modules, files, network,
sessions, plus the token-upgraded processes — emits `OwnerOffset` (the owning
`_EPROCESS` address) on every spoke, and enrichment links on it with
`link_confidence="definitive"`, falling back to the create-time-window PID join
(`heuristic`) only where no offset is available (built-ins, freed owners).
Files now HAVE owners (handle enumeration — one CAR file event per
(FILE_OBJECT, process), while `filescan` keeps contributing ownerless scan
rows). `user_session` identity is the token AuthenticationId **LUID** (the real
CAR `login_id`); process `user`/`sid` come natively from the token. Registry
`user` on SID-form hives resolves through the image's own ProfileList mapping.

**Completeness (v0.4.0+):** a 10-agent per-object field audit drove every
provably-fillable CAR property to filled — host identity (hostname/fqdn from the
image's own registry, l2t-processor convention), process cwd / integrity_level /
env_vars, thread start_function (export resolution), registry new_content, file
extension, service paths for stopped services, spoke ppid inheritance. Two
capabilities the audit surfaced were added: **`windows.piiat.access`**
(Process-type handles → CAR process `access` events with access_level /
target_*), and **`windows.mftscan.MFTScan`** integration (memory-resident $MFT →
file `create` events with creation_time and, on an SI/FILE_NAME birth-time
mismatch, previous_creation_time — the timestomp tell). Remaining nulls are
honest: hashes/signers (unmapped file bytes), call_trace (ephemeral), thread
src_pid (not recorded), flow byte counters (not in a snapshot).

A follow-up completeness pass filled three more provably-derivable fields: (1)
`user_session.login_successful = true` — an access token bearing the
AuthenticationId LUID exists only because LSA completed the logon, the same
"the observation proves the constant" rule as `socket.success`; (2) `uid` (the
generic account key = the token SID) on `process`, and inherited into the
spokes that carry a `uid` field but no `sid` field (thread/file/flow/service),
so the account SID has a canonical home store-wide; (3) host identity is
hardened — the registry plugin now targets the whole `…\Control\ComputerName`
key so both the boot-time `ComputerName` and the running `ActiveComputerName`
are captured, and `_host_identity` falls back to `ActiveComputerName` (then
Tcpip `Hostname`) when the boot-time value is smeared. `windows.info` carries
no NetBIOS name (only kernel/OS build metadata), so the registry ComputerName
is the sole memory-native host source; a run without the registry plugin leaves
hostname honestly null rather than faking it from the dump filename.

**Triggers vs records (malfind):** malfind is a *trigger*, not a stored CAR
record — it is never written to the store. At output, each flagged region is
joined by PID to the process already in the store and a `module` timeline entry
is *populated from that stored record* (identity/host/user/image + create-time),
carrying only the region detail (address/Protection/disasm) natively. This is
the store→retrieve pattern: memory-native evidence points at what to surface;
the CAR fields come from what was already extracted.

**Export dedup:** not needed. Enrichment's `_dedupe` (identity + action +
target_guid + access_level) plus timestamp-gating leaves the exported timeline
duplicate-free — measured 0 exact-duplicate rows on a real ~45k-event timeline;
cross-source file evidence (filescan / piiat.files / mftscan) is intentionally
distinct and only the timestamped MFT records reach the timeline.
