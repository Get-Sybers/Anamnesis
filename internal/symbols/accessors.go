package symbols

// Confidence records how much trust a recovered value carries, mirroring the
// pipeline's definitive/heuristic link contract (docs/design/car-store.md §3).
type Confidence string

const (
	// Definitive: a deterministic decode of a single-instruction accessor. The
	// offset is read straight from the build's own code and is verifiable.
	Definitive Confidence = "definitive"
	// BestEffort: the accessor's shape varies across builds (a wrapper, a
	// computed getter, a bit test). The offset is usually right but must be
	// cross-checked before it is trusted.
	BestEffort Confidence = "best_effort"
)

// Accessor names an exported ntoskrnl routine whose body reveals a struct field
// offset when disassembled. The Win64 ABI passes the process/thread pointer in
// rcx, so these routines are effectively `mov rax,[rcx+OFFSET]; ret`.
type Accessor struct {
	Func       string     // exported symbol, resolved via the PE export table
	Struct     string     // owning structure, e.g. "_EPROCESS"
	Field      string     // field the accessor exposes
	Confidence Confidence // Definitive for single-instruction getters
	Note       string     // shape hint / caveat
}

// ProcessAccessors is the curated battery of ntoskrnl exports that expose
// _EPROCESS / _ETHREAD field offsets through a single memory operand. Together
// they cover the identity-bearing surface anamnesis needs from the kernel side
// with no PDB. Fields without a clean accessor (ActiveProcessLinks, Token,
// DirectoryTableBase, Peb chain) are recovered by the constraint-solving tier
// described in docs/design/symbol-recovery.md, not here.
var ProcessAccessors = []Accessor{
	{"PsGetProcessId", "_EPROCESS", "UniqueProcessId", Definitive, "mov rax,[rcx+off]"},
	{"PsGetProcessInheritedFromUniqueProcessId", "_EPROCESS", "InheritedFromUniqueProcessId", Definitive, "PPID"},
	{"PsGetProcessImageFileName", "_EPROCESS", "ImageFileName", Definitive, "lea rax,[rcx+off]"},
	{"PsGetProcessCreateTimeQuadPart", "_EPROCESS", "CreateTime", Definitive, ""},
	{"PsGetProcessSectionBaseAddress", "_EPROCESS", "SectionBaseAddress", Definitive, ""},
	{"PsGetProcessDebugPort", "_EPROCESS", "DebugPort", Definitive, ""},
	{"PsGetProcessExitStatus", "_EPROCESS", "ExitStatus", Definitive, ""},
	{"PsGetProcessWin32Process", "_EPROCESS", "Win32Process", BestEffort, "wrapper varies by build"},
	{"PsGetProcessPeb", "_EPROCESS", "Peb", BestEffort, "may compute; verify"},
	{"PsReferencePrimaryToken", "_EPROCESS", "Token", BestEffort, "EX_FAST_REF; low bits are the refcount"},
	{"PsIsProtectedProcess", "_EPROCESS", "Protection", BestEffort, "movzx + bit test; offset only"},
	{"PsIsProtectedProcessLight", "_EPROCESS", "Protection", BestEffort, "movzx + bit test; offset only"},
	{"PsGetThreadId", "_ETHREAD", "Cid.UniqueThread", Definitive, ""},
	{"PsGetThreadProcessId", "_ETHREAD", "Cid.UniqueProcess", Definitive, ""},
	{"PsGetThreadProcess", "_ETHREAD", "ThreadsProcess", BestEffort, "returns owning _EPROCESS"},
	{"PsGetThreadTeb", "_ETHREAD", "Tcb.Teb", BestEffort, ""},
}

// CodeSource yields the machine code of an exported function and the function's
// virtual address. It is the seam the recovery logic is written against, so the
// decoders can be unit-tested with synthetic bytes and driven in production by a
// real PE (*PEImage) or, later, by the in-memory ntoskrnl read through the engine.
type CodeSource interface {
	FunctionCode(name string) (code []byte, va uint64, err error)
}

// RecoveredOffset is one field offset read out of an accessor.
type RecoveredOffset struct {
	Func       string     `json:"func"`
	Struct     string     `json:"struct"`
	Field      string     `json:"field"`
	Offset     int32      `json:"offset"`
	Confidence Confidence `json:"confidence"`
}

// DiagnosticKind separates a transient failure from a permanent one, so a
// self-teaching store knows whether a later image of the same build is worth
// re-attempting for this accessor.
type DiagnosticKind string

const (
	// Unresolved: the export could not be resolved or its code could not be
	// read (e.g. the page was not resident). Another image of the same build
	// may succeed — worth retrying.
	Unresolved DiagnosticKind = "unresolved"
	// Unrecognised: the code was read but carries no [reg+disp] operand in its
	// prologue. That is deterministic for the build — never worth retrying.
	Unrecognised DiagnosticKind = "unrecognised"
)

// Diagnostic records why an accessor did not yield an offset (missing export,
// unrecognised shape) so the caller can report coverage honestly.
type Diagnostic struct {
	Func string         `json:"func"`
	Kind DiagnosticKind `json:"kind"`
	Err  string         `json:"err"`
}

// codeWindow is how many leading bytes of a function a CodeSource is expected to
// provide — comfortably more than any single-instruction accessor needs.
const codeWindow = 64

// RecoverOffsets resolves each accessor against src and returns the offsets it
// could read plus a diagnostic for each it could not. It never guesses: an
// accessor whose shape is unrecognised becomes a diagnostic, not a fabricated
// offset.
func RecoverOffsets(src CodeSource, accessors []Accessor) ([]RecoveredOffset, []Diagnostic) {
	var out []RecoveredOffset
	var diags []Diagnostic
	for _, a := range accessors {
		code, _, err := src.FunctionCode(a.Func)
		if err != nil {
			diags = append(diags, Diagnostic{a.Func, Unresolved, err.Error()})
			continue
		}
		off, ok := AccessorDisplacement(code)
		if !ok {
			diags = append(diags, Diagnostic{a.Func, Unrecognised, "no [rcx/rdx+disp] memory operand in prologue"})
			continue
		}
		out = append(out, RecoveredOffset{
			Func:       a.Func,
			Struct:     a.Struct,
			Field:      a.Field,
			Offset:     off,
			Confidence: a.Confidence,
		})
	}
	return out, diags
}
