# Offline Symbol and Structure Recovery for Windows Memory Forensics

*A design/research paper for the anamnesis engine. Companion to
[docs/design/symbol-recovery.md](../design/symbol-recovery.md) (the design of
record) and [docs/design/native-engine.md](../design/native-engine.md). This
paper is the theory; the design doc is what we build to and the code is under
`internal/`.*

## Abstract

anamnesis parses Windows memory images fully offline, with no access to
Microsoft's PDB symbol server. Correct parsing nonetheless requires per-build
type offsets and global addresses that the bundled MemProcFS `info.db` only
partially covers, and it requires reading structures that Windows (and malware)
deliberately obfuscate. This paper sets out a coherent theory for obtaining that
information without the network: recover offsets and globals deterministically
from the kernel's own machine code; bootstrap the kernel from build-invariant
structural anchors; reverse the small, keyed transforms Windows applies to a
handful of structures; and discover unknown fixed-size record arrays directly
from raw bytes by frame profiling. We treat two obfuscations as fundamentally
different problems -- deterministic OS hardening (defeated by recovering keys and
applying a fixed transform) and arbitrary adversarial anti-forensics (defeated by
redundancy and structural invariants) -- and we develop each accordingly. We give
particular attention to a structure-discovery method, *frame profiling*, that
recovers record size and field constancy from an unlabeled byte region by
sweeping a frame width and scoring per-column invariance, and we describe how to
calibrate and evaluate it against symbol-known images.

## 1. Introduction

Memory forensics reconstructs system state -- processes, threads, handles,
network endpoints, loaded modules -- from a physical memory image. Doing so means
interpreting kernel structures whose field layout changes per OS build. The
conventional source of that layout is the debugging PDB matched to the image's
exact binary revision (CodeView GUID+age), fetched from Microsoft. anamnesis
forbids that fetch: it runs in a hardened, network-isolated container, and PDBs
are a baked build-time dependency. That works until the image's build was not
seeded, at which point the engine has no layout and, today, fails silently on the
affected fields (empty command line, SID, and user for every process).

This paper's contributions:

1. **Deterministic offset recovery from code** (Section 3): read `_EPROCESS` /
   `_ETHREAD` field offsets straight out of exported accessor functions, whose
   bodies embed the offset as an instruction immediate.
2. **PDB-free bootstrap** (Section 4): locate the kernel, directory table base,
   and initial process from build-invariant anchors.
3. **User-mode recovery** (Section 5): recover command line and SID without
   ntdll/token PDBs by anchoring on values already known from the kernel side.
4. **Deobfuscation of OS-encoded structures** (Section 6): the exact, keyed
   transforms, plus keyless recovery of their keys.
5. **Frame profiling** (Section 7): a method to discover unknown fixed-size
   record arrays and their field constancy from raw bytes, with a calibration and
   evaluation methodology against symbol-known images.

The unifying design principle matches the pipeline's contract: identity and
layout are *definitive, never guessed*. Every recovered value carries provenance
and a confidence tier; deterministic methods yield `definitive`, structural or
statistical methods yield `heuristic` unless corroborated.

## 2. Background and threat model

**Symbols, two kinds.** "Symbols" conflates two things: *global addresses* (VAs
of named globals such as `PsActiveProcessHead`), which are RVAs plus the kernel
base; and *struct field offsets* (where fields sit inside `_EPROCESS`, `_TOKEN`,
`_MMPTE`, ...). `info.db` covers a common subset of the second; the per-image PDB
fetch supplies the rest and the naming needed for user-mode fidelity.

**Two obfuscations, two responses.** Windows hardens a few structures with
*deterministic, key-driven* encodings (the debugger data block, the object-header
type index, handle-table pointers) and compresses pages. These are defeated by
recovering the key and applying a fixed transform; the result is verifiable and
`definitive`. Malware applies *arbitrary* anti-forensics (unlinking objects,
forging tags and headers, hollowing images, hashing imports). These are defeated
by redundancy and by invariants an attacker cannot cheaply violate; the result is
`heuristic`, consensus-scored. Conflating the two produces overconfident output.

**Adversary.** For the OS-hardening case there is no adversary -- the transform is
a documented anti-tamper measure and our job is only to read it. For the
anti-forensics case the adversary controls arbitrary memory contents but not the
OS's own structural invariants (a running process must be reachable by the
scheduler; a valid object must have a coherent header), which is what we lean on.

## 3. Deterministic offset recovery from code

The offsets are latent in the kernel image already present in the dump. The Win64
ABI passes the first integer argument in `rcx`, and ntoskrnl exports small
accessor routines whose entire body is a single memory operand against that
pointer. `PsGetProcessId` compiles to `mov rax,[rcx+OFFSET]; ret`, where `OFFSET`
is `_EPROCESS.UniqueProcessId`; `PsGetProcessImageFileName` is a `lea` exposing
`ImageFileName`; `PsIsProtectedProcess(Light)` exposes `Protection` via a `movzx`
and a bit test. Disassembling the prologue and reading the displacement recovers
the offset deterministically and build-exactly, with no PDB and no value guessing.

A curated battery covers the identity-bearing surface (`UniqueProcessId`, PPID,
`ImageFileName`, `CreateTime`, `SectionBaseAddress`, `DebugPort`, `ExitStatus`,
thread `Cid` fields). Robustness requires a real length-aware decoder rather than
a byte pattern, to tolerate CET `endbr64`, the hot-patch `mov edi,edi`, NOP
padding, and `mov`/`movzx`/`lea` variants; anything unrecognized must fail closed
so a misread is never recorded. Fields without a clean accessor
(`ActiveProcessLinks`, `Token`, `DirectoryTableBase`, the PEB chain) fall to
constraint solving (Section 7's cousin): intersect known-value constraints
(System PID = 4; known process names; a page-aligned CR3 that self-validates)
over a candidate population until each field's offset is unique. This is
implemented in `internal/symbols` (`AccessorDisplacement`, `ProcessAccessors`,
`PEImage`).

## 4. PDB-free kernel bootstrap

The bootstrap chain is build-invariant and needs no symbols:

- **Directory table base (CR3):** the processor start block ("low stub") in the
  first 1 MB of physical memory -- first qword `0x00000001000600E9`, kernel entry
  in the `0xFFFFF800_00000000` range at `+0x70`, PML4 physical address at `+0xA0`.
- **Validation:** the self-referential PML4 entry (a kernel-half index whose
  target is `CR3 + 0x03`) and translation of `KUSER_SHARED_DATA` at the fixed
  `0xFFFFF78000000000`.
- **Kernel base:** scan for `MZ` plus the `POOLCODE` section magic
  (`0x45444F434C4F4F50`), which rejects the false positives that `MZ` alone
  yields.
- **Initial process:** `PsInitialSystemProcess` is exported; resolve it from the
  export table, add the base, dereference, and walk `ActiveProcessLinks`.
  `PsActiveProcessHead` is not exported but is unnecessary, as the System process
  is in the ring. `PsLoadedModuleList` is export-resolvable on modern x64.

The kernel debugger data block (KDBG) is deliberately deprioritized: on modern
x64 it is encoded, and decoding it requires symbols (Section 6), so it is
circular for the offline case. It is retained only for pre-Windows-10 and x86
images and crash dumps, validated by list reflection rather than by its tag.

## 5. User-mode recovery

The empty command line, SID, and user do not need ntoskrnl layout; they need
ntdll and token layout. The lever is that the kernel side already yields each
process's image path. `_RTL_USER_PROCESS_PARAMETERS` stores `ImagePathName` and
`CommandLine` as adjacent `_UNICODE_STRING`s (`Length <= MaximumLength`, both
even, `Buffer` a canonical user pointer to `Length/2` UTF-16 units). Find the
`_UNICODE_STRING` whose buffer equals the known image path; `CommandLine` is the
next one. This locks the ntdll-version-specific offset once per build with no
ntdll PDB. The SID is recovered by its own signature (`Revision == 1`,
`SubAuthorityCount <= 15`, `IdentifierAuthority` usually the NT authority
`{0,0,0,0,0,5}`) scanned within the token allocation.

## 6. Deobfuscation of OS-encoded structures

The transforms are small and keyed; MemProcFS applies them when it has symbols,
so the offline contribution is recovering the keys without a PDB (below).

- **Encoded `KdDebuggerDataBlock`**, per 8-byte entry, in order:
  `e = rol(e XOR KiWaitNever, KiWaitNever & 0xFF)`;
  `e = bswap(e XOR (VA(KdpDataBlockEncoded) | 0xFFFF000000000000))`;
  `e = e XOR KiWaitAlways`. Keys: `KiWaitNever`, `KiWaitAlways`, and the two VAs.
- **`_OBJECT_HEADER.TypeIndex`:**
  `real = TypeIndex XOR (byte)(VA(OBJECT_HEADER) >> 8) XOR ObHeaderCookie`. Mixing
  the object's own address defeats a pool-overflow retarget of the type.
- **Handle-table entry pointer** (Win8+ x64): shift the encoded `LowValue` right,
  realign to 16 bytes, restore the canonical `0xFFFF000000000000` kernel high
  bits; low bits carry the inverted refcount and access mask; walk levels via
  `TableCode & ~0x7`. The exact shift varies by build.
- **Compressed pages:** `SmGlobals` (signature) -> `SMKM_STORE_MGR.KeyToStoreTree`
  -> the `SMKM_STORE` whose owner is the Memory Compression process ->
  `_ST_DATA_MGR.PagesTree` -> `_ST_PAGE_RECORD` -> chunk ->
  `RtlDecompressBufferEx` (Xpress / Xpress-Huffman). Recovers resident-but-
  compressed pages; content paged to disk stays out of reach.

**Keyless key recovery.** The keys are not exported, but the routines that read
them have stable code shapes. Fingerprint the routine, then read the RIP-relative
`lea`/`mov` operand that references the global to recover its VA
(`internal/symbols.RIPTarget`). This is the same deterministic move as Section 3,
applied to globals instead of struct fields.

## 7. Structure discovery by frame profiling

Sections 3-6 assume we know which structure we are looking at. Frame profiling
addresses the complementary problem: given an unlabeled region of memory,
discover the fixed-size record arrays in it and the offsets of their constant
fields, with no symbols at all.

### 7.1 Model

Treat the region as a byte stream `x[0..n)`. A contiguous array of fixed-size
records of size `S`, starting at offset `phi`, tiles the stream so that a field at
record offset `k` recurs at absolute offsets `phi + k, phi + k + S, phi + k + 2S,
...`. Reshaping the stream into rows of width `W` places byte position `p` at
row `floor(p/W)`, column `p mod W`. When `W = S`, every record becomes one row
and the field at offset `k` occupies column `k` in every row. If that field is
constant or low-variance across records -- a pool tag, a type index, a flag byte,
the high bytes of a kernel pointer -- then column `k` is a near-constant column.
This is the "preamble in every row" intuition, made precise: a preamble is a
low-entropy column, and the correct frame width is the one that produces them.

### 7.2 Objective and detection

Let `X_c(W) = { x[r*W + c] : r = 0..floor(n/W)-1 }` be the byte series of column
`c` under width `W`, and `H(.)` Shannon entropy. Define the width score as the
number of columns with `H(X_c(W)) < tau` for a low threshold `tau` (equivalently,
columns whose modal value covers nearly all rows). At the true stride `S`, one or
more columns are near-constant and the score spikes; at an unrelated width the
tiling cuts across field boundaries inconsistently and every column approaches the
region's baseline entropy, so the score is flat. Integer multiples of `S` also
score (a `2S` framing has the constant field at two columns), so the *fundamental*
stride is the smallest strong width; equivalently, the first strong peak of the
byte-stream autocorrelation `A(k) = corr(x[i], x[i+k])`, which is the cheap
prefilter that proposes candidate widths before the entropy confirm step.

### 7.3 Refinements that make it work on real memory

A naive byte-equality search fails on most kernel structure. Three refinements
are load-bearing:

1. **Bit-plane and partial-column constancy.** Many "constant" fields are constant
   only in some *bits* (a reserved PTE bit is always zero; the present bit is
   usually one) or in their *high bytes* (a kernel pointer's canonical
   `0xFFFFF8..` prefix) while the containing byte varies. Score per bit-plane and
   per byte-within-lane, not only per whole byte.
2. **Alignment prior.** Kernel records are 8- or 16-byte aligned and their sizes
   are multiples of 8 (usually 16). Restricting `W` to multiples of 8 shrinks the
   search 8-16x and removes most spurious hits.
3. **Extent segmentation.** A real array is bounded. Slide a window over the rows
   and track whether the candidate preamble columns hold their modal values;
   change points bound the array's extent. The extent itself is forensically
   useful: the PFN database's extent yields the physical page count, a handle
   table's extent yields the handle count.

### 7.4 Targets and non-targets

Frame profiling finds *contiguous, fixed-stride* arrays. Its natural targets in
Windows kernel memory:

- **PFN database** (`_MMPFN`, ~0x30 bytes, build-dependent): large, contiguous,
  fixed stride, with small-integer and flag columns -- the ideal case.
- **Page-table pages** (`_MMPTE`, 512 x 8 bytes = one 4 KB page): frame cleanly
  even in physical memory; flag-bit columns are near-constant.
- **Handle tables** (`_HANDLE_TABLE_ENTRY`, 0x10 bytes on Win10 x64): access-mask
  and attribute bit columns.
- **Object-type array; big-pool tracker table**: fixed stride, tagged.

It does *not* find `_EPROCESS` / `_ETHREAD` (few, large, pool-scattered -- not
arrays; use the linked-list and pool-tag methods) or singletons (KPCR,
`KUSER_SHARED_DATA`). The general pool is *quantized but variable-stride*: pool
headers carry a constant per-type tag but recur at 0x10 granularity, not a fixed
row width, so tag-scanning rather than framing is the right tool there. Frame
profiling is thus complementary to Sections 3-6, not a replacement: it discovers
unknown record sizes, and the accessor and constraint methods resolve field
offsets within a known structure.

### 7.5 Physical versus virtual space

A raw dump is physical memory. A virtually-contiguous array (such as the PFN
database) is scattered across non-adjacent 4 KB physical pages, so a physical-space
framing aligns structure *within* a page but breaks at every page boundary. Two
consequences: block starts coincide with page boundaries (the "a new block may
start" intuition is exactly page alignment); and to profile an array larger than a
page one should first linearize it through the page tables into a contiguous
buffer. Page-table pages are the exception -- each is exactly one 4 KB page -- and
frame cleanly without linearization.

### 7.6 Calibration and evaluation on symbol-known images

The method is developed against images whose symbols we hold, which provides
ground truth:

1. Enumerate the true arrays from symbols -- `MmPfnDatabase` with
   `sizeof(_MMPFN)`, page-table pages, per-process handle tables, the object-type
   array -- each as `(base, stride, count)`.
2. Linearize each through the page tables and run the profiler; confirm that the
   entropy minimum lands at the true stride and that the low-entropy columns
   coincide with the known constant fields. This fixes the metric and thresholds.
3. Measure precision and recall of the blind detector against those labels, the
   same corpus-validation discipline the rest of the engine uses.

Two products follow. First, the per-structure column signature becomes a
*classifier*: an unknown array can be identified as a PFN database, a PTE page, or
a handle table by its column pattern alone, with no symbols. Second, scoring the
framing/entropy response over every page yields a *structural map* of the whole
dump -- labeling each page as code, PTE, PFN, pool, heap, zeroed, or high-entropy
(encrypted or compressed) -- which is a useful artifact in itself and a
stepping-stone to the blind case. High-entropy regions are the anti-signal:
uniform column entropy at every width means there is no structure to find.

## 8. Reverse-engineering toolbox

The techniques above are made robust and build-general by standard reverse-
engineering methods: **emulation** of a decode or accessor stub (run the kernel's
own code, under a CPU emulator with the real globals mapped, rather than
reimplementing the arithmetic); **function fingerprinting** (FLIRT, Ghidra
FunctionID, radare2 zignatures) to locate accessors and key-holding routines when
exports are stripped; **cross-reference / backward slicing** to pull a global's
address from a RIP-relative operand; **binary diffing** (BinDiff, Diaphora,
headless Ghidriff) to port function and offset identifications from a known build
to an unseen one, closing the tail without a representative dump per build; and
**entropy triage** to point the expensive passes only at structured or encoded
regions.

## 9. Adversarial anti-forensics

The arbitrary-obfuscation layer is defeated by redundancy: **DKOM unlinking** by
pool-tag scan plus list-versus-scan consensus (the engine's existing `Hidden`
flag); **tag and header forgery** by structural validation (dispatcher-header
type/size, list closure, CR3 self-validation) rather than tag trust; **hollowing
and module stomping** by reconciling the VAD against the mapped PE and by the
existing `malfind` private-executable overlay, extended with PE-header
reconstruction when headers are wiped; **API hashing** by a precomputed
hash-to-API database; and **stripped imports** by IAT reconstruction from call
targets. Frame profiling contributes here too: a forged singleton cannot easily
reproduce the column statistics of a genuine array, and unexpected periodicity in
a region that should be unstructured is itself an indicator.

## 10. Limitations

Deterministic recovery depends on the accessor shapes and encodings remaining as
documented; a future compiler or transform change is tracked by emulation and
binary diffing but can still require re-calibration. Frame profiling finds only
contiguous fixed-stride arrays and is defeated by fragmentation (mitigated by
linearization), by variable-size records (the pool), and by genuinely high-entropy
regions (compressed or encrypted, which it can flag but not read). Anti-forensic
recoveries are heuristic by nature and are labeled as such. Content paged to disk
or lost to compression eviction is unrecoverable from the image alone.

## 11. Related work

Kernel-structure discovery from memory has three main lineages that frame
profiling draws together. *Value-distribution clustering* -- Laika (Cozzie et al.,
OSDI 2008, "Digging for Data Structures") -- infers structures from the
observation that same-type objects have similar byte patterns, the same premise as
the preamble. *Graph-signature scanning* -- SigGraph (Lin et al., NDSS 2011) and
SigPath (ESORICS 2014) -- brute-force scans for instances using points-to
invariants rather than value constancy, and is complementary. *Binary
visualization* -- Conti and Bratus's "Voyage of the Reverser," Domas's
cantor.dust, and senseye -- performs the reshape-and-look operation manually;
frame profiling is its quantified, automated form. On the systems side the work
builds directly on MemProcFS (Frisk), Volatility, and Rekall for the bootstrap and
decode mechanics, and on Mandiant's compressed-memory analysis for the store
walk.

## 12. References

- U. Frisk. MemProcFS. `vmm/vmmwininit.c` (kernel base, low-stub CR3, KDBG).
- B. Dolan-Gavitt (moyix). "Finding Kernel Global Variables in Windows," 2008.
- itm4n. "Debugging Protected Processes," 2021 (accessor offset disassembly).
- Volatility Foundation. "The Secret to 64-bit Windows 8 and 2012 Raw Memory Dump
  Forensics"; `win8_kdbg.py`. Air14. KDBGDecryptor.
- Rekall. "Do we need the Kernel Debugging Block?"; `kdbgscan.py`.
- TANGO. "A Light on Windows 10's OBJECT_HEADER->TypeIndex." G. Chappell.
  OBJECT_HEADER.
- Mandiant. "Finding Evil in Windows 10 Compressed Memory" (Black Hat USA 2019);
  `mandiant/win10_volatility`; `aleksost/MemoryDecompression`.
- A. Cozzie, F. Stratton, H. Xue, S. T. King. "Digging for Data Structures,"
  OSDI 2008 (Laika).
- Z. Lin, J. Rhee, X. Zhang, D. Xu, X. Jiang. "SigGraph: Brute Force Scanning of
  Kernel Data Structure Instances Using Graph-based Signatures," NDSS 2011.
- G. Conti, S. Bratus. "Voyage of the Reverser." C. Domas. cantor.dust.
  letoram. senseye.
- Google. BinDiff. J. Koret. Diaphora. clearbluejar. Ghidriff.
