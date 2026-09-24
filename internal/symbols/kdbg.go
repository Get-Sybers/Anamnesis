package symbols

import (
	"encoding/binary"
	"math/bits"
)

// KdDebuggerDataBlock (nt!KdDebuggerDataBlock) carries the authoritative
// kernel bookkeeping pointers — PsActiveProcessHead, PsLoadedModuleList, the
// kernel base — behind a header that always reads "KDBG". On Win8+ the block
// is encoded in place with a per-boot-random pair of keys (KiWaitNever,
// KiWaitAlways) and the address of KdpDataBlockEncoded, unless kernel
// debugging was enabled (docs/design/symbol-recovery.md §7). Decoding it is a
// fixed, reversible transform; the recovered "KDBG" tag is the built-in proof
// that the keys and the transform were right, so a wrong decode is always
// detectable rather than silently trusted.

// KdbgOwnerTag is the DBGKD_DEBUG_DATA_HEADER64.OwnerTag: the bytes 'K','D',
// 'B','G' as they sit in memory (little-endian u32).
const KdbgOwnerTag uint32 = 0x4742444B // 'KDBG'

// kdbgOwnerTagOffset is OwnerTag's offset in the block: past the 16-byte
// LIST_ENTRY header. Size follows at +4.
const kdbgOwnerTagOffset = 0x10

// kernelHighBits forces the canonical kernel-address high 16 bits, matching
// how the encoder folds the KdpDataBlockEncoded address into the transform.
const kernelHighBits uint64 = 0xFFFF000000000000

// DecodeKdbgEntry reverses one 8-byte entry of an encoded KdDebuggerDataBlock,
// in the order the kernel's decoder applies (§7): XOR KiWaitNever, rotate left
// by KiWaitNever's low byte, XOR the (canonicalized) KdpDataBlockEncoded
// address, byte-swap, XOR KiWaitAlways. kdpDataBlockEncodedVA is the ADDRESS
// of the flag, not its value.
func DecodeKdbgEntry(e, kiWaitNever, kiWaitAlways, kdpDataBlockEncodedVA uint64) uint64 {
	e ^= kiWaitNever
	e = bits.RotateLeft64(e, int(kiWaitNever&0xFF))
	e ^= kdpDataBlockEncodedVA | kernelHighBits
	e = bits.ReverseBytes64(e)
	e ^= kiWaitAlways
	return e
}

// EncodeKdbgEntry is the exact inverse of DecodeKdbgEntry — the kernel's
// encoder. It is not needed offline, but it lets the decoder be proven by
// round-trip and documents the transform's reversibility.
func EncodeKdbgEntry(d, kiWaitNever, kiWaitAlways, kdpDataBlockEncodedVA uint64) uint64 {
	d ^= kiWaitAlways
	d = bits.ReverseBytes64(d)
	d ^= kdpDataBlockEncodedVA | kernelHighBits
	d = bits.RotateLeft64(d, -int(kiWaitNever&0xFF))
	d ^= kiWaitNever
	return d
}

// DecodeKdbg decodes an encoded block into a fresh buffer, entry by entry. The
// trailing bytes of a non-multiple-of-8 block are dropped (the header and
// every field this engine reads are 8-byte aligned).
func DecodeKdbg(block []byte, kiWaitNever, kiWaitAlways, kdpDataBlockEncodedVA uint64) []byte {
	out := make([]byte, len(block)&^7)
	for i := 0; i+8 <= len(out); i += 8 {
		v := binary.LittleEndian.Uint64(block[i:])
		binary.LittleEndian.PutUint64(out[i:], DecodeKdbgEntry(v, kiWaitNever, kiWaitAlways, kdpDataBlockEncodedVA))
	}
	return out
}

// ScanKdbgTag finds the next unencoded KdDebuggerDataBlock in image at or
// after byte `from`: an OwnerTag "KDBG" whose block — starting 0x10 earlier —
// lies within image and passes the tag+size gate. Returns the block's offset
// in image. Only the natively-unencoded case is scannable this way; an
// encoded block carries no plaintext tag. The stride is 4 bytes, so a block
// on any 32-bit-aligned boundary is found.
func ScanKdbgTag(image []byte, from int) (blockOff int, ok bool) {
	if from < 0 {
		from = 0
	}
	for p := (from + 3) &^ 3; p+4 <= len(image); p += 4 {
		if binary.LittleEndian.Uint32(image[p:]) != KdbgOwnerTag {
			continue
		}
		b := p - kdbgOwnerTagOffset
		if b >= 0 && KdbgTagOK(image[b:]) {
			return b, true
		}
	}
	return 0, false
}

// KdbgTagOK reports whether a block (decoded, or natively unencoded) carries
// the "KDBG" OwnerTag with a plausible Header.Size — the self-validating check
// that a decode was correct or a scanned block is genuine. size is bounded
// generously: real blocks are a few hundred to ~0x360 bytes across builds.
func KdbgTagOK(block []byte) bool {
	if len(block) < kdbgOwnerTagOffset+8 {
		return false
	}
	tag := binary.LittleEndian.Uint32(block[kdbgOwnerTagOffset:])
	size := binary.LittleEndian.Uint32(block[kdbgOwnerTagOffset+4:])
	return tag == KdbgOwnerTag && size >= 0x40 && size <= 0x1000
}
