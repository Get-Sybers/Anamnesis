package symbols

// Keyless recovery of kernel globals the accessor battery cannot reach
// (docs/design/symbol-recovery.md §7): a global like ObHeaderCookie is not
// exported, but a routine that READS it is, and its body references the global
// with a RIP-relative operand. Fingerprint by the exported routine, slice the
// operand with RIPTarget, read the value. This is the same deterministic move
// as reading an offset out of an accessor, applied to a global's address.

// GlobalRef names an exported routine and the global its body references.
// ByteOperand selects the byte-sized reference (movzx/mov r8) over any
// pointer-sized lea in the same routine — e.g. ObGetObjectType reads the byte
// ObHeaderCookie with movzx and loads ObTypeIndexTable with a pointer lea.
type GlobalRef struct {
	Func        string
	Global      string
	ByteOperand bool
}

// KernelGlobals is the curated set recovered this way. ObHeaderCookie is the
// first: it deobfuscates _OBJECT_HEADER.TypeIndex, the prerequisite for typing
// any scanned kernel object.
var KernelGlobals = []GlobalRef{
	{Func: "ObGetObjectType", Global: "ObHeaderCookie", ByteOperand: true},
}

// globalWindow is how many leading bytes of a global-reading routine to scan —
// wider than an accessor's single instruction, since the reference can sit a
// little into the body.
const globalWindow = 192

// codeReaderN is the optional wider-window read a CodeSource may offer; without
// it RecoverGlobalVA falls back to the standard codeWindow.
type codeReaderN interface {
	FunctionCodeN(name string, n int) ([]byte, uint64, error)
}

// RIPHit is one RIP-relative memory reference: the absolute address it names,
// its offset in the scanned window, and whether the referencing instruction is
// byte-sized (movzx byte / mov r8 — a byte global) rather than pointer-sized.
type RIPHit struct {
	Target uint64
	At     int
	Byte   bool
}

// RecoverGlobalVA resolves the virtual address of ref.Global by disassembling
// ref.Func to the RIP-relative operand that reads it. With ByteOperand set the
// first byte-sized reference wins (skipping pointer-sized leas); otherwise the
// first reference of any width. ok=false when the routine is unavailable or
// carries no matching reference — never a guessed address.
func RecoverGlobalVA(src CodeSource, ref GlobalRef) (va uint64, ok bool) {
	code, base, err := functionCode(src, ref.Func, globalWindow)
	if err != nil {
		return 0, false
	}
	for _, h := range RIPTargetAll(code, base) {
		if ref.ByteOperand && !h.Byte {
			continue
		}
		return h.Target, true
	}
	return 0, false
}

func functionCode(src CodeSource, name string, n int) ([]byte, uint64, error) {
	if r, ok := src.(codeReaderN); ok {
		return r.FunctionCodeN(name, n)
	}
	return src.FunctionCode(name)
}

// RIPTargetAll returns every RIP-relative memory reference in code (bounded
// walk over the tracked mov/lea/movzx opcodes), each with its resolved address
// and whether the instruction is byte-sized. It generalises RIPTarget, which
// returns only the first.
func RIPTargetAll(code []byte, codeVA uint64) []RIPHit {
	var hits []RIPHit
	for i := 0; i < len(code); {
		j := i
		if code[j]&0xF0 == 0x40 {
			j++ // REX
		}
		if j >= len(code) {
			break
		}
		var modrmAt int
		byteSized := false
		switch op := code[j]; {
		case op == 0x8B || op == 0x8D || op == 0x89 || op == 0x03 || op == 0x2B:
			modrmAt = j + 1
		case op == 0x8A: // mov r8, r/m8
			modrmAt = j + 1
			byteSized = true
		case op == 0x0F && j+1 < len(code) && (code[j+1] == 0xB6 || code[j+1] == 0xB7):
			modrmAt = j + 2
			byteSized = code[j+1] == 0xB6 // B6 = byte source, B7 = word
		default:
			i++
			continue
		}
		if modrmAt >= len(code) {
			break
		}
		d, _, ripRel, n, pok := parseModRM(code[modrmAt:])
		if pok && ripRel {
			end := modrmAt + n
			hits = append(hits, RIPHit{Target: codeVA + uint64(end) + uint64(int64(d)), At: end, Byte: byteSized})
			i = end
			continue
		}
		if pok && n > 0 {
			i = modrmAt + n
		} else {
			i++
		}
	}
	return hits
}

// DecodeTypeIndex reverses the _OBJECT_HEADER.TypeIndex obfuscation
// (Win10+): real = raw XOR (byte)(headerVA>>8) XOR cookie. The result indexes
// nt!ObTypeIndexTable.
func DecodeTypeIndex(rawIdx uint8, headerVA uint64, cookie uint8) uint8 {
	return rawIdx ^ uint8(headerVA>>8) ^ cookie
}
