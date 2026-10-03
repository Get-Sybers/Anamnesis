// Package symbols recovers Windows kernel type offsets and global addresses
// from a memory image without querying Microsoft's PDB symbol server.
//
// It exists because anamnesis runs fully offline (see docs/design/native-engine.md
// §1.1): MemProcFS's bundled info.db covers only a common subset of offsets, and
// the per-image ntoskrnl/ntdll PDBs — matched by CodeView GUID+age — are the
// network dependency we want to remove. The techniques here are the tiered
// fallback described in docs/design/symbol-recovery.md.
//
// This first increment implements the deterministic primitive that underpins the
// whole plan: reading a struct field offset (or a global's address) straight out
// of the kernel's own machine code, which is already present in the dump. Two
// primitives are provided:
//
//   - AccessorDisplacement: decode a small exported accessor such as
//     nt!PsGetProcessId — effectively `mov rax,[rcx+OFFSET]; ret` — and return
//     OFFSET, which is the _EPROCESS field the accessor exposes. Deterministic
//     and build-exact: no PDB, no heuristics, no value guessing.
//
//   - RIPTarget: resolve the absolute virtual address referenced by a
//     RIP-relative operand inside a routine, turning a code reference to a global
//     (e.g. nt!ObHeaderCookie or nt!KiWaitNever) into that global's address. This
//     is the "keyless key recovery" that lets the deobfuscation layer decode
//     structures Windows encodes (KDBG, OBJECT_HEADER.TypeIndex) without symbols.
//
// The instruction decoding here is deliberately narrow — it is not a general
// disassembler. It handles the handful of prologue and memory-operand shapes the
// target routines actually use, and fails closed (ok=false) on anything else so a
// caller never acts on a misread. Field-level validation against real ntoskrnl
// builds is the on-target gate, consistent with the collector validation policy.
package symbols
