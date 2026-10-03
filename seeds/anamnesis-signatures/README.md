# Build-time fingerprint signatures

Masked byte-pattern signatures (`symrec -fingerprint`) that locate a kernel
routine which references a non-exported global, so the engine can `RIPTarget`
that global on a build it has never seen. The image bakes this directory
read-only at `/opt/anamnesis/seed-signatures` (`ANAMNESIS_SIG_DIR` overrides).

Unlike the offset store, a signature is **not** keyed by `(GUID, age)`: the
disp32 is wildcarded so one pattern generalizes across builds. One
`<module>.json` holds a module's signatures. Author one with:

    symrec -fingerprint seeds/anamnesis-signatures <ntoskrnl.exe> <routine> <global> [byte]

`routine` is resolved by export name. Non-exported globals need no build-time
harvest: the engine recovers them in-image from structural anchors and authors
their signatures itself, into the persistent cache's `anamnesis-signatures/`
(the self-teaching mirror of this directory). The runtime self-test, the
ground-truth cross-check, and each global's consume gate prove the scanner and
every located address before either source is trusted.
