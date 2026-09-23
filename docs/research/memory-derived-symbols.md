# Memory-derived Windows symbols research plan

## Problem

anamnesis currently treats Windows symbols as an offline dependency of the
container image: MemProcFS runs with the symbol server disabled and reads the
baked `Symbols/` cache beside `vmm.so` (staged to `/tmp` when the runtime
filesystem is read-only). That is safe and reproducible, but it still assumes
the relevant Microsoft PDB-derived facts have already been collected.

The research question is whether anamnesis can derive enough symbol information
directly from a memory image to avoid querying Microsoft PDBs for every new
kernel build.

## Short answer

Do not aim to synthesize a full Microsoft-compatible PDB from memory. A PDB is a
rich debug database and much of it is not present in RAM. Instead, aim for a
narrow, evidence-backed **memory-derived symbol profile** containing only the
fields anamnesis needs: structure offsets, key global addresses, object identity
rules, and confidence/provenance.

This is feasible for a useful subset because Windows memory contains many
self-describing or cross-checkable invariants:

- PE headers, exports, imports, sections, unwind data and code bytes for loaded
  kernel modules.
- Kernel global anchors such as processor control structures, debugger data
  blocks, loaded-module lists and object lists.
- Pool headers and pool tags (`Proc`, `Thre`, `File`, `TcpE`, etc.) around
  allocations.
- Intrusive lists where `Flink`/`Blink` pairs must point back to the candidate
  object.
- Known scalar shapes: PIDs, FILETIME values, virtual-address ranges, handles,
  session IDs, token pointers and UTF-16 strings.
- Cross-artifact constraints: a candidate `_EPROCESS` must agree with threads,
  handles, VADs, modules, token data, DTB/CR3 and active/scanned process views.

The SDR analogy is useful: rather than downloading a map, infer the map by
searching for structure in noisy observations, then score candidate mappings
until a consistent layout emerges.

## What "symbol file" should mean for anamnesis

The practical deliverable should be an anamnesis-owned profile, not a synthetic
PDB:

```text
kernel:
  image: ntoskrnl.exe
  timestamp/checksum/pdb_guid_age: observed when available
  build: observed from registry/KUSER_SHARED_DATA/PE version resources
types:
  _EPROCESS:
    UniqueProcessId: {offset: 0x..., confidence: 0.99, evidence: [...]}
    ActiveProcessLinks: {offset: 0x..., confidence: 0.99, evidence: [...]}
    CreateTime: {offset: 0x..., confidence: 0.95, evidence: [...]}
    Token: {offset: 0x..., confidence: 0.90, evidence: [...]}
  _ETHREAD:
    Cid.UniqueThread: ...
globals:
  PsActiveProcessHead: {va: 0x..., confidence: 0.99, evidence: [...]}
```

The profile can later be translated into whatever backend is useful:

- direct offsets consumed by `internal/memprocfs` fallbacks,
- a small SQLite cache analogous to MemProcFS `info.db`,
- JSON fixtures for test corpora,
- or, only if truly required, an adapter that writes a symbol-provider format.

## Candidate derivation strategy

### 1. Fingerprint the image

Start by extracting stable identity facts before guessing offsets:

- Windows version/build from registry hives, `KUSER_SHARED_DATA`, PE version
  resources and MemProcFS metadata when available.
- Kernel module base, image size, timestamp/checksum, and PDB GUID+age if present
  in the PE CodeView debug directory.
- Architecture, canonical virtual-address layout, page size and DTB candidates.

This gives cache keys and prevents mixing profiles across incompatible builds.

### 2. Find anchors

Prefer anchors that can be validated without prior private type offsets:

- PE export table names for exported globals/functions.
- Loaded kernel module list candidates validated by PE headers and address
  ranges.
- Processor/KPCR/KPRCB-like regions validated by self-pointers and CPU-count
  consistency.
- Debugger data/KDBG-like blocks when present.
- Pool allocations with known tags and sane sizes.

Anchors reduce the search space for private fields.

### 3. Solve structure offsets as constraints

Treat each field offset as a variable and each memory invariant as a constraint.
For example, a candidate `_EPROCESS` layout can be scored by:

- `UniqueProcessId` looks like a plausible PID and matches handle/thread/network
  owners.
- `ActiveProcessLinks` is a valid doubly linked list where each node points back
  to the containing object at the same offset.
- `ImageFileName` is short ASCII and agrees with PEB/process path data when
  available.
- `CreateTime` decodes as a plausible FILETIME before acquisition time.
- `Token` points to a token-like object, with low reference-count bits masked.
- `DirectoryTableBase` looks like a valid paging root.
- thread lists point to `_ETHREAD`-like objects whose owning process pointer
  resolves back to the candidate process.

A solver does not need one perfect signature. It needs enough independent
signals to make one layout dominate alternatives.

### 4. Use iterative bootstrapping

The first pass can find only high-confidence fields. Those fields make later
passes easier:

1. Find kernel base and image metadata.
2. Find process objects and a minimal `_EPROCESS` layout.
3. Use processes to validate threads, handles, VADs, modules and tokens.
4. Use the new artifacts to infer additional offsets.
5. Re-score the whole profile and emit only fields above a confidence threshold.

This matches the "keep trying until knowns are found" intuition while keeping
the result auditable.

### 5. Keep PDBs as training labels, not runtime requirements

For development, use known PDB-backed corpora to learn and validate heuristics:

- Run with baked PDBs and record the true offsets.
- Run the memory-derived solver without PDB offsets.
- Compare inferred offsets to the PDB-backed truth.
- Store mismatches with the image fingerprint and evidence bundle.

Over time this builds a regression corpus and a local profile cache. Runtime can
remain offline, and PDBs become a CI/research aid rather than a hard production
dependency.

## Failure modes and guardrails

- **Patch drift:** Windows field offsets move. Cache profiles by exact kernel
  identity, not only major/minor build.
- **Tampering/rootkits:** malware can unlink lists or forge objects. Prefer
  multiple independent views: active lists, pool scans, handle tables, threads,
  VADs and network objects.
- **Crash dumps vs raw memory:** available regions differ. Evidence should record
  missing pages and partial confidence, not silently fabricate fields.
- **Architecture differences:** x64, ARM64 and PAE/non-PAE layouts need separate
  solvers and validation rules.
- **False positives:** any inferred field must carry confidence and evidence.
  Downstream collectors should use only fields meeting a conservative threshold.
- **Scope creep:** exported symbols and private type fields are different
  problems. Start with the private offsets anamnesis actually needs.

## Proposed phases

### Phase 0: Define the target schema

Document the exact offsets and globals required by current collectors:
`_EPROCESS.CreateTime`, process identity/list fields, thread owner/start fields,
token/SID fields, handle-table fields, VAD/module fields and network object
fields. Mark which are already covered by MemProcFS `info.db`, which require
PDBs today, and which can remain null.

### Phase 1: Build a corpus harness

Create a repeatable harness that, for each memory image, captures:

- image fingerprint,
- PDB-backed offsets from MemProcFS where available,
- memory-derived candidate offsets,
- evidence and confidence,
- collector-level output differences.

The harness should fail only on regressions against known-good corpora, not on
unknown images where confidence is intentionally low.

### Phase 2: Infer the minimal process profile

Start with `_EPROCESS` because it unlocks the rest of anamnesis:

- active process list,
- PID,
- parent PID,
- image name,
- create time,
- DTB,
- token pointer,
- object address / pool identity.

This creates immediate value because process create time is currently called out
as PDB-offset-dependent in `internal/memprocfs/engine_vmm.go`.

### Phase 3: Extend to spokes

Add `_ETHREAD`, handles, VAD/module ownership and network/file object offsets.
Prioritize fields that preserve anamnesis's definitive `_EPROCESS`-based links.

### Phase 4: Integrate as an offline fallback

Do not replace MemProcFS symbol handling immediately. Add the profile as a
fallback path:

1. Try MemProcFS `info.db`/baked symbols.
2. If an offset is missing, run or load the memory-derived profile.
3. Emit provenance in raw plugin JSONL so reviewers can tell whether a field came
   from PDB/info.db or inference.

### Phase 5: Decide whether to upstream/cache

If the derived profiles are stable, decide whether they should live as:

- anamnesis fixtures,
- an anamnesis runtime cache,
- an augmentation to the container's baked symbol cache,
- or an upstream contribution to MemProcFS-style offline symbol data.

## Open questions

- Which exact fields does MemProcFS already resolve from `info.db` versus full
  PDBs for supported Windows builds?
- Can MemProcFS expose enough low-level reads/enumerations for anamnesis to run
  this solver without bypassing the existing engine abstraction?
- What confidence threshold is acceptable before a collector may use an inferred
  offset?
- Should inferred fields be used automatically, or only with an opt-in research
  flag until the corpus is large enough?
- How should profile provenance appear in `car.db` or raw plugin output?

## Recommendation

Proceed with a narrow research spike: derive a minimal `_EPROCESS` profile from
memory, validate it against PDB-backed truth on a small corpus, and wire it only
as an offline fallback for fields that would otherwise be null. That keeps the
production path conservative while testing whether the "symbols from structure"
approach is reliable enough to expand.

References worth keeping nearby:

- MemProcFS command-line and symbol/offline options:
  <https://github.com/ufrisk/MemProcFS/wiki/_CommandLine>
- MemProcFS offline symbol discussion:
  <https://github.com/ufrisk/MemProcFS/issues/327>
- Current anamnesis symbol behavior:
  `docs/design/native-engine.md` and `internal/memprocfs/engine_vmm.go`
