# Build-time offset-store seeds

`(GUID, age)`-keyed `_EPROCESS`/`_ETHREAD` offset files, one per Windows kernel
build, produced by `symrec -store <dir> <ntoskrnl.exe>` from harvested kernel
PEs. The engine reads them read-only (the image bakes this directory at
`/opt/anamnesis/seed-offsets`), so an unseen build is a Tier-1 store hit on its
first image instead of a runtime accessor recovery. A fuller image still writes
its converged entry into the read-write symbol-cache mount; seeds stay pristine.

Files are engine-recovered offsets, not Microsoft code — small, diffable,
license-clean. Add a build by running the generator on its `ntoskrnl.exe` (or
hand-drop a file; `symbols.Merge` treats an existing entry as authoritative).
