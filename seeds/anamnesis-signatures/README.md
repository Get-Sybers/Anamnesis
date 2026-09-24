# Build-time fingerprint signatures

Masked byte-pattern signatures (`symrec -fingerprint`) that locate a kernel
routine which references a non-exported global, so the engine can `RIPTarget`
that global on a build it has never seen. The image bakes this directory
read-only at `/opt/anamnesis/seed-signatures` (`ANAMNESIS_SIG_DIR` overrides).

Unlike the offset store, a signature is **not** keyed by `(GUID, age)`: the
disp32 is wildcarded so one pattern generalizes across builds. One
`<module>.json` holds a module's signatures. Author one with:

    symrec -fingerprint seeds/anamnesis-signatures <ntoskrnl.exe> <routine> <global> [byte]

`routine` is resolved by export name (the in-image anchor-recovery slice adds
non-exported RVA targets). The engine's runtime self-test + ground-truth
cross-check prove the scanner before any signature is trusted.
