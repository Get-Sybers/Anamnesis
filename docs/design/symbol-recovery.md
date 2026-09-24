# anamnesis — offline symbol & offset recovery

This is the design of record for resolving Windows kernel/user type offsets and
global addresses **without querying Microsoft's PDB symbol server**, and for
reading the structures Windows and malware deliberately obfuscate. It extends
[native-engine.md](native-engine.md) §1.1 (Symbols), which established that
anamnesis is always offline and that PDBs are a baked build-time dependency.
Nothing here weakens that contract; it removes the dependency's fragile tail —
the image whose exact build was never seeded — and it does so with deterministic,
auditable methods rather than guesses, consistent with the pipeline's
"identity is definitive, never guessed" rule ([car-store.md](car-store.md) §3).

## 0. Why

MemProcFS resolves offsets two ways: its bundled `info.db` (a common subset,
keyed by build) and, for full fidelity, PDBs matched to the image's exact binary
revisions by CodeView **GUID+age**. The GUID+age fetch is the network dependency.
The GoDFIR-toolz build seeds `Symbols/` by running the engine over representative
images in a networked stage, then ships it read-only.

Two gaps remain, both real:

1. **Unseen builds.** An image whose `ntoskrnl`/`ntdll` revision was not in the
   seed set has no baked PDB, and the offline container cannot fetch one.
2. **User-mode fidelity — the [Issue #14](https://github.com/Get-Sybers/Anamnesis/issues/14)
   gap.** `command_line`, `sid`, and `user` come back empty for every process
   because they do not live in the kernel `_EPROCESS` surface `info.db` covers:
   the command line is in the PEB → `_RTL_USER_PROCESS_PARAMETERS.CommandLine`
   (offsets from **ntdll.pdb**), and the SID is in the process token. #14 was
   closed by baking `ntdll`/`ntoskrnl` PDBs at build time — correct as far as it
   goes, but it inherits gap (1): a build you did not seed still yields nothing.

This document is how the engine keeps producing correct output on a build it has
never seen, offline, with honest confidence labeling.

## 1. Two obfuscations, two responses

Recovery fights two very different things, and conflating them causes bad calls:

- **OS hardening obfuscation** — Windows encodes `KdDebuggerDataBlock`, masks
  `_OBJECT_HEADER.TypeIndex`, encodes handle-table pointers, and compresses
  pages. It is **deterministic and keyed on kernel globals**, so it is defeated
  by recovering the keys and applying a fixed transform. Result: `definitive`.
- **Adversarial anti-forensics** — malware unlinks objects (DKOM), forges pool
  tags/headers, hollows or stomps images, hashes its imports. It is **arbitrary**,
  so it is defeated by redundancy and structural invariants, never by trusting a
  single view. Result: `heuristic`, consensus-scored.

### 1.1 Relation to the Windows symbol taxonomy

Windows splits symbol data in two ([public and private symbols](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/public-and-private-symbols)):
**private** symbols carry full type layouts (struct field offsets), **public**
symbols carry only the names and addresses of functions and globals. The
recovery tiers rebuild both surfaces with neither present: accessor
disassembly and PEB anchoring reconstruct the private surface (the offset
battery), export-walking and function fingerprinting reconstruct the public
surface (global addresses, stored as build-stable RVAs). The offline contract
is the container-enforced form of dbghelp's
[`SYMOPT_SECURE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-options#symopt-secure)
(no symbol-server or network access, ever), and as under
[`SYMOPT_NO_PUBLICS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-options#symopt-no-publics),
no name→address source is consulted beyond the export table the image itself
carries.

## 2. Tiered architecture

Three tiers, descending preference. The engine tries them in order and records
which one answered.

- **Tier 1 — the offset store (primary).** A table keyed by module
  `(GUID, age)` → the ~150–200 offsets and global RVAs anamnesis actually
  consumes. Ship *this*, not whole PDBs: small, diffable, auditable, extensible —
  the same idea as `info.db` and Volatility 3 ISF, scoped to our fields. At
  analysis time: read the in-memory PE's CodeView RSDS record → look up
  `(GUID, age)` → done, zero network. Populated at build time three ways
  (§5, §8): PDB conversion where reachable, accessor-disassembly of harvested
  PEs where not, and binary-diff porting for the tail.
- **Tier 2 — in-image recovery (fallback).** For a build in neither the store
  nor the baked cache, recover from the image itself using the deterministic
  primitives (§5) and structural anchors (§6). Keeps the offline container
  producing output on an unseen build instead of hard-failing.
- **Self-teaching cache.** A Tier 2 recovery **writes its result back** into the
  store under that `(GUID, age)`. The second occurrence of a build is a Tier 1
  hit. Over time the store converges and the network is never touched.

## 3. Structural invariants we scan for

Each is an invariant that holds regardless of build, so a structure announces
itself out of raw bytes with no type database.

| Technique | What it recovers |
|---|---|
| **Self-referential pointer** — `mem[p] == p` at a fixed sub-offset | KPCR (`_KPCR.Self`); the page-table base (PML4 self-map, §4) |
| **Doubly-linked-list closure** — `x->Flink->Blink == x` | every kernel ring (process, module, handle) even when the head symbol is unknown |
| **Fixed-stride periodicity** — a field pattern repeating every N bytes | `sizeof(struct)` for arrays (handle tables, PFN db, object dirs) |
| **Sync-word / magic scan** — literal 4-byte tags | pool-tagged allocations (`Proc`, `Thre`, `File`, `Driv`, `MmLd`, `Toke`) → candidate populations, DKOM-resistant |
| **Pointer-density scan** — score aligned windows by canonical-pointer count | "here be structures" — pointer-dense regions above the data-page noise floor |
| **Known-value constraint** — a field consistently holding a known constant | offsets (System PID = 4 → `UniqueProcessId`; `"System"` → `ImageFileName`; a self-validating CR3 → `DirectoryTableBase`) |

## 4. Kernel bootstrap without a PDB

The chain MemProcFS itself uses (`vmm/vmmwininit.c`), reproduced here so the
recovery tier does not depend on MemProcFS having symbols:

- **DTB / CR3 — the low stub.** Scan the first 1 MB of physical memory for the
  processor start block: first qword `0x00000001000600E9`, kernel entry in the
  `0xFFFFF800_00000000` range at `+0x70`, **PML4 physical address at `+0xA0`**.
  That is CR3, no symbols, no guessing.
- **Validate CR3** by the PML4 self-map entry (a kernel-half index whose target
  is `CR3 + 0x03`) and by translating `KUSER_SHARED_DATA` at the fixed
  `0xFFFFF78000000000`.
- **Kernel base** — scan for `MZ` **plus the `POOLCODE` section magic**
  (`0x45444F434C4F4F50`); far fewer false positives than `MZ` alone.
- **System-process anchor** — `PsInitialSystemProcess` **is exported**: resolve
  it from ntoskrnl's export table, add to the in-memory base, deref → the System
  `_EPROCESS`, then walk `ActiveProcessLinks`. (`PsActiveProcessHead` is *not*
  exported, but is unnecessary — System is already in the ring.
  `PsLoadedModuleList` *is* export-resolvable on modern x64.)
- **KDBG is a dead end on modern x64** — the debugger block is encoded, and
  decoding needs `KdpDataBlockEncoded` / `KiWaitAlways` / `KiWaitNever`, which are
  themselves symbols (circular). MemProcFS skips it once it can resolve
  `PsLoadedModuleList` from exports. Keep KDBG only for pre-Win10 / x86 and crash
  dumps, and validate a hit Rekall-style by *list reflection* (follow its
  pointers, confirm the rings close), not by trusting the `KDBG` tag.

## 5. Deterministic offset recovery

**The offsets are latent in the kernel's own code.** ntoskrnl exports accessor
functions whose entire body is a single `[rcx+OFFSET]` read against the
`_EPROCESS`/`_ETHREAD` passed in rcx (Win64 ABI). `PsGetProcessId` is effectively
`mov rax,[rcx+OFFSET]; ret`, where `OFFSET` **is** `UniqueProcessId`. Disassemble
the prologue, read the displacement — deterministic, build-exact, no PDB, no
value guessing. The battery:

| Exported accessor | Field |
|---|---|
| `PsGetProcessId` | `UniqueProcessId` |
| `PsGetProcessInheritedFromUniqueProcessId` | PPID |
| `PsGetProcessImageFileName` | `ImageFileName` (lea) |
| `PsGetProcessCreateTimeQuadPart` | `CreateTime` |
| `PsGetProcessSectionBaseAddress` | `SectionBaseAddress` |
| `PsGetProcessDebugPort` / `PsGetProcessExitStatus` | `DebugPort` / `ExitStatus` |
| `PsIsProtectedProcess(Light)` | `Protection` (offset only) |
| `PsGetThreadId` / `PsGetThreadProcessId` | `Cid.UniqueThread` / `Cid.UniqueProcess` |

Use a real length-aware decoder (not a regex) so it survives `endbr64`, the
hot-patch `mov edi,edi`, NOP padding, and `mov`/`movzx`/`lea` variants. Fields
with no clean accessor (`ActiveProcessLinks`, `Token`, `DirectoryTableBase`, the
`Peb` chain) fall to **constraint solving**: intersect known-value constraints
across a pool-tag-scanned candidate population (System PID = 4, known process
names, a page-aligned CR3 that self-validates), which collapses each field to a
unique offset. **Cross-validate**: recover load-bearing facts (the System
`_EPROCESS`, the process count) by ≥2 independent methods and require consensus;
disagreement is a DKOM/corruption signal, flagged rather than trusted.

**Implemented (this repo):** `internal/symbols` provides `AccessorDisplacement`
(offset out of an accessor), `RIPTarget` (global address out of a RIP-relative
reference — §7), the `ProcessAccessors` battery, a `PEImage` `CodeSource` that
resolves exports for on-disk / carved kernels, and `cmd/symrec` to run it against
an `ntoskrnl.exe`. Unit-tested with synthetic encodings; field-level parity on
real builds is the on-target gate.

## 6. User-mode recovery — the #14 gap

`command_line` / `sid` do not need ntoskrnl.pdb; they need ntdll/token layout.
The lever: **anamnesis already knows each process's image path from the kernel
side** — use it as the anchor.

- **`command_line` without ntdll.pdb.** `_RTL_USER_PROCESS_PARAMETERS` holds
  `ImagePathName` and `CommandLine` as adjacent `_UNICODE_STRING`s
  (`{ USHORT Length; USHORT MaximumLength; ULONG pad; PWSTR Buffer }`,
  `Length ≤ MaximumLength`, both even, `Buffer` a canonical user pointer to
  `Length/2` UTF-16 units). Find the `_UNICODE_STRING` whose buffer **equals the
  image path you already have**; `CommandLine` is the next one. Lock the offset
  once per ntdll build, apply to all processes.
- **`sid` / `user` without full token symbols.** A `_SID` has its own signature
  — `Revision == 1`, `SubAuthorityCount ≤ 15`, `IdentifierAuthority` usually
  `{0,0,0,0,0,5}` (NT Authority). Scan the token allocation for a valid `_SID`;
  the primary user SID is recoverable structurally.

## 7. Deobfuscation layer

Exact transforms for the OS-encoded structures (MemProcFS does these *with*
symbols; the offline win is recovering the keys without a PDB, below):

- **Encoded `KdDebuggerDataBlock`** — per 8-byte entry, in order:
  `e = rol(e XOR KiWaitNever, KiWaitNever & 0xFF)`;
  `e = bswap(e XOR (VA(KdpDataBlockEncoded) | 0xFFFF000000000000))`;
  `e = e XOR KiWaitAlways`.
- **`_OBJECT_HEADER.TypeIndex`** —
  `real = TypeIndex XOR (byte)(VA(OBJECT_HEADER) >> 8) XOR ObHeaderCookie`.
- **Handle-table entry pointer** (Win8+ x64) — shift the encoded `LowValue`
  right, realign to 16 bytes, restore the canonical `0xFFFF000000000000` kernel
  high bits; low bits carry the (inverted) refcount and access mask; walk levels
  via `TableCode & ~0x7`. Exact shift varies by build — key it to the build.
- **Compressed pages** — `SmGlobals` (signature) → `SMKM_STORE_MGR.KeyToStoreTree`
  → the `SMKM_STORE` whose `OwnerProcess` is `MemCompression` →
  `_ST_DATA_MGR.PagesTree` → `_ST_PAGE_RECORD` → chunk → `RtlDecompressBufferEx`
  with Xpress / Xpress-Huffman. Recovers resident-but-compressed blocks; only
  truly paged-to-disk stays unreachable.

**Keyless key recovery.** The keys (`KiWaitNever`, `KiWaitAlways`,
`ObHeaderCookie`, `SmGlobals`) are not exported — but the routines that read them
have stable code shapes. Fingerprint the routine (§8), disassemble to the
RIP-relative `lea`/`mov` that references the global, and read the displacement to
get its VA (`internal/symbols.RIPTarget`). Same deterministic move as reading an
offset out of an accessor, applied to recover keys.

## 8. Reverse-engineering toolbox

What makes §5–§7 work without symbols and generalize across builds:

- **Emulation** — lift a decode/accessor stub and run it in a CPU emulator
  (Unicorn, or a small Go x86-64 core) with the real globals mapped in. Tracks a
  future transform change automatically where a reimplemented formula would
  silently break. Run the kernel's own code to undo the kernel's own obfuscation.
- **Function fingerprinting** — FLIRT / Ghidra FunctionID / radare2-zignature
  patterns to locate the accessors and key-holding routines when exports/symbols
  are stripped.
- **Xref / backward slice** — from inside a fingerprinted routine, the global is
  a RIP-relative operand; slice it out to get the address (`RIPTarget`).
- **Binary diffing** — for a build with neither PDB nor fingerprint hit, diff
  ntoskrnl against the nearest known build (BinDiff / Diaphora / headless
  Ghidriff) and port function/offset identifications. Runs headless in the build
  pipeline; closes the "seed-image source" tail without needing a representative
  *dump* for every build.
- **Entropy triage** — high-entropy aligned regions flag the encoded/compressed
  targets so the expensive deobfuscation runs only where needed.

## 9. Malware anti-forensics

The adversarial layer, defeated by redundancy (some already present in anamnesis):

- **DKOM unlinking** — pool-tag scan + pslist-vs-psscan consensus. The README's
  `Hidden` flag (seen by scan, not the active list) is exactly this; make it the
  general anti-DKOM primitive.
- **Pool tag / header forgery** — validate structurally (`DISPATCHER_HEADER`
  type/size, `ActiveProcessLinks` closure, CR3 self-validation), not by the tag.
- **Hollowing / module stomping / manual mapping** — reconcile VAD vs mapped PE;
  `windows.malfind` already collects private+executable regions; add PE-header
  reconstruction when `MZ`/headers are wiped in memory.
- **API hashing** (ROR13/FNV/CRC) — resolve with a precomputed hash→API DB so
  enriched malfind hits show real API names.
- **Import reconstruction** — rebuild the IAT from call targets when imports are
  stripped.

## 10. Provenance & confidence

Every recovered value carries how it was obtained, mapped to the CAR link model:

- **`definitive`** — Tier 1 store hit; accessor disassembly; an OS-obfuscation
  decode with recovered keys. Deterministic and verifiable.
- **`heuristic`** — constraint-solved offsets not yet cross-validated; user-mode
  anchoring by a single match; any malware anti-forensic recovery. Consensus
  raises confidence; disagreement is surfaced, never silently resolved.

The tier that answered and the method are recorded in the record's provenance so
downstream (byakugan) can weight it.

## 11. Where it lives

A **deobfuscation + recovery pre-pass** in `internal/symbols`, run before
collection: identify the image PE(s), look up Tier 1 by `(GUID, age)`, else
recover (accessor disassembly + structural anchors), decode any encoded
structures (keys via `RIPTarget`), and hand clean offsets/structures to the
existing collectors through the `internal/memprocfs` seam. Keys and offsets
share one `(GUID, age)`-keyed store and one provenance model. This complements
MemProcFS rather than replacing it: MemProcFS still parses the image; anamnesis
supplies the offsets/keys it would otherwise have needed the network for.

Effort is staged: the accessor/offset store and keyless key recovery are the
core (and the accessor primitive is landed). Memory decompression and the full
anti-forensics suite are larger, and sit behind the core.

## 12. Phasing / status

1. Design doc (this file). ✅
2. Deterministic primitive: `internal/symbols` — `AccessorDisplacement`,
   `RIPTarget`, `ProcessAccessors`, `PEImage`, `cmd/symrec`; unit-tested. ✅
3. `(GUID, age)` offset store: schema, engine lookup, and the self-teaching
   write-back over the accessor battery (`internal/symbols/store.go`, keyed by
   the in-memory ntoskrnl's CodeView identity, persisted in the symbol-cache
   mount under `anamnesis-offsets/`). ✅ — the build-time generator (PDB
   convert + harvested-PE disassembly) remains. ▶
4. In-image Tier 2: low-stub CR3, kernel-base, exported anchors, constraint
   solving, cross-validation. ▶ — first slice landed: the in-memory ntoskrnl
   accessor disassembly (`recover_vmm.go` `kernelCode` → `RecoverOffsets`)
   feeds `_EPROCESS.CreateTime` behind a System-process plausibility gate.
5. User-mode recovery: image-path-anchored `command_line`
   (`internal/symbols/procparams.go`: PEB → ProcessParameters, fixed offsets
   validated against the anchor, bounded scan on mismatch, 32-bit variant) ✅;
   `sid` from the ProcessInfo SID buffer + `user` from the registry-derived
   user list ✅; the SID-signature token scan for processes those miss. ▶
6. Deobfuscation: encoded-KDBG (pre-Win10/x86), TypeIndex, handle-entry; keyless
   key recovery via fingerprint + `RIPTarget`. ▶
7. RE toolbox: emulation of decode stubs; binary-diff porting for tail builds. ▶
8. Memory decompression; malware anti-forensics suite. ▶ (staged last)
9. On-target validation of recovered offsets against the standard corpora
   (LS24, M57, lonewolf), field parity vs a PDB ground truth.

## 13. References

- MemProcFS bootstrap — `ufrisk/MemProcFS` `vmm/vmmwininit.c` (kernel base via
  `POOLCODE`, low-stub CR3, encoded-KDBG skip).
- Accessor disassembly — itm4n, "Debugging Protected Processes"; moyix,
  "Finding Kernel Global Variables in Windows" (`PsInitialSystemProcess`
  exported; `PsActiveProcessHead` not).
- KDBG decode — Volatility `win8_kdbg.py`; `Air14/KDBGDecryptor`.
- TypeIndex — TANGO, "A Light on Windows 10's OBJECT_HEADER->TypeIndex";
  Geoff Chappell, OBJECT_HEADER.
- Compressed memory — Mandiant, "Finding Evil in Windows 10 Compressed Memory";
  `mandiant/win10_volatility`; `aleksost/MemoryDecompression`.
- Binary diffing — `google/bindiff`; Diaphora; Ghidriff.
- KDBG reliability — Rekall, "Do we need the Kernel Debugging Block?"; Rekall
  `kdbgscan.py` (validation by list reflection).
