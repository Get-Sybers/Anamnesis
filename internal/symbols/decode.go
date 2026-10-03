package symbols

import "encoding/binary"

// Memory-operand base registers, as encoded in the low 3 bits of ModRM.rm
// (or SIB.base). Only the ones we key on are named.
const (
	regRAX = 0
	regRCX = 1 // first integer argument in the Win64 ABI — the process/thread ptr
	regRDX = 2 // second integer argument
	regRSP = 4 // ModRM.rm==4 in a memory form means "SIB byte follows"
	regRBP = 5 // ModRM.rm==5 with mod==00 means RIP-relative
)

// skipPrologue advances past the padding/no-op sequences that can precede the
// first real instruction of a function: CET endbr64, the classic hot-patch
// `mov edi,edi`, and plain NOPs. It intentionally does not try to parse the
// multi-byte 0F 1F NOP family; the accessors we target do not use it before
// their first memory operand, and stopping early simply yields ok=false upstream.
func skipPrologue(code []byte) int {
	i := 0
	for i < len(code) {
		switch {
		case i+4 <= len(code) && code[i] == 0xF3 && code[i+1] == 0x0F && code[i+2] == 0x1E && code[i+3] == 0xFA:
			i += 4 // endbr64
		case i+2 <= len(code) && code[i] == 0x8B && code[i+1] == 0xFF:
			i += 2 // mov edi,edi (hot-patch pad)
		case code[i] == 0x90:
			i++ // nop
		case i+2 <= len(code) && code[i] == 0x66 && code[i+1] == 0x90:
			i += 2 // 66 90 nop
		default:
			return i
		}
	}
	return i
}

// parseModRM decodes a ModRM byte at code[0] together with any SIB byte and
// displacement, for the 64-bit memory-operand forms we care about. It returns
// the sign-extended displacement, the base register (or -1 when there is none),
// whether the operand is RIP-relative, and the number of bytes consumed
// (ModRM + SIB + displacement). It does not consume the opcode or REX prefix.
func parseModRM(code []byte) (disp int32, base int, ripRel bool, n int, ok bool) {
	if len(code) < 1 {
		return 0, -1, false, 0, false
	}
	modrm := code[0]
	mod := modrm >> 6
	rm := modrm & 7
	i := 1

	if mod == 3 {
		return 0, -1, false, i, true // register-direct: no memory operand
	}

	base = int(rm)
	sibBase := int(rm)
	if rm == regRSP { // SIB byte follows
		if len(code) < i+1 {
			return 0, -1, false, 0, false
		}
		sib := code[i]
		i++
		sibBase = int(sib & 7)
		base = sibBase
	}

	switch mod {
	case 0:
		switch {
		case rm == regRBP: // RIP-relative: disp32, no base
			if len(code) < i+4 {
				return 0, -1, false, 0, false
			}
			d := int32(binary.LittleEndian.Uint32(code[i:]))
			return d, -1, true, i + 4, true
		case rm == regRSP && sibBase == regRBP: // SIB base==101, mod==00: disp32, no base
			if len(code) < i+4 {
				return 0, -1, false, 0, false
			}
			d := int32(binary.LittleEndian.Uint32(code[i:]))
			return d, -1, false, i + 4, true
		default:
			return 0, base, false, i, true // no displacement
		}
	case 1:
		if len(code) < i+1 {
			return 0, -1, false, 0, false
		}
		return int32(int8(code[i])), base, false, i + 1, true
	case 2:
		if len(code) < i+4 {
			return 0, -1, false, 0, false
		}
		return int32(binary.LittleEndian.Uint32(code[i:])), base, false, i + 4, true
	}
	return 0, -1, false, 0, false
}

// AccessorDisplacement decodes the first real instruction of a small accessor
// function and returns the displacement of a `[rcx+disp]` (or `[rdx+disp]`)
// memory read or lea — i.e. the offset of the struct field the accessor exposes.
//
// It recognises the shapes these routines actually compile to:
//
//	mov  r64, [rcx+disp]     48 8B ...      (e.g. PsGetProcessId -> UniqueProcessId)
//	lea  r64, [rcx+disp]     48 8D ...      (e.g. PsGetProcessImageFileName)
//	movzx r32/r64, [rcx+disp] 0F B6/B7 ...  (byte/word fields, e.g. Protection)
//
// A REX prefix is tolerated. Anything else — a computed getter, an unexpected
// prologue, a RIP-relative or register operand — yields ok=false, so the caller
// never records a misread offset.
func AccessorDisplacement(code []byte) (disp int32, ok bool) {
	i := skipPrologue(code)
	if i < len(code) && code[i]&0xF0 == 0x40 {
		i++ // REX prefix
	}
	if i >= len(code) {
		return 0, false
	}

	var modrmAt int
	switch op := code[i]; {
	case op == 0x8B || op == 0x8D: // mov r64,r/m64 ; lea r64,m
		modrmAt = i + 1
	case op == 0x0F:
		if i+1 >= len(code) || (code[i+1] != 0xB6 && code[i+1] != 0xB7) {
			return 0, false
		}
		modrmAt = i + 2 // movzx
	default:
		return 0, false
	}
	if modrmAt >= len(code) {
		return 0, false
	}

	d, base, ripRel, _, pok := parseModRM(code[modrmAt:])
	if !pok || ripRel || (base != regRCX && base != regRDX) {
		return 0, false
	}
	return d, true
}

// RIPTarget resolves the absolute virtual address named by the first
// RIP-relative memory operand in code, given codeVA (the virtual address of
// code[0]). It is used to recover a global's address from a reference inside a
// routine that touches it — e.g. the read of nt!ObHeaderCookie or nt!KiWaitNever
// — so the deobfuscation layer gets its keys with no PDB.
//
// The scan is a bounded, best-effort walk over the tracked mov/lea opcodes: on a
// RIP-relative hit it returns target = codeVA + end_of_instruction + disp32.
// Callers point it at a small window at or just before the known reference site.
func RIPTarget(code []byte, codeVA uint64) (target uint64, at int, ok bool) {
	for i := 0; i < len(code); {
		j := i
		if code[j]&0xF0 == 0x40 {
			j++ // REX
		}
		if j >= len(code) {
			break
		}
		var modrmAt int
		switch op := code[j]; {
		case op == 0x8B || op == 0x8D || op == 0x89 || op == 0x03 || op == 0x2B:
			modrmAt = j + 1
		case op == 0x0F && j+1 < len(code) && (code[j+1] == 0xB6 || code[j+1] == 0xB7):
			modrmAt = j + 2
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
			return codeVA + uint64(end) + uint64(int64(d)), end, true
		}
		if pok && n > 0 {
			i = modrmAt + n
		} else {
			i++
		}
	}
	return 0, 0, false
}
