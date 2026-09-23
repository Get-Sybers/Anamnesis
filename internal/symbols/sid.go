package symbols

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DecodeSID renders a SID buffer as its "S-1-…" string form. The buffer may
// carry either representation — MemProcFS's ProcessInfo SID field mirrors a
// C char array that some builds fill with the already-formatted string and
// others leave as the binary _SID — so both are tried: the ASCII form first
// (cheap, unambiguous prefix), then the binary _SID layout
// {u8 Revision; u8 SubAuthorityCount; u8 IdentifierAuthority[6] (big-endian);
// u32 SubAuthority[count] (little-endian)}. A buffer matching neither returns
// ok=false; no value is ever fabricated.
func DecodeSID(raw []byte) (string, bool) {
	if s, ok := sidFromASCII(raw); ok {
		return s, true
	}
	return sidFromBinary(raw)
}

// sidFromASCII accepts a NUL-terminated "S-1-…" string of digits and dashes.
func sidFromASCII(raw []byte) (string, bool) {
	if len(raw) < 4 || raw[0] != 'S' || raw[1] != '-' || raw[2] != '1' || raw[3] != '-' {
		return "", false
	}
	end := len(raw)
	if i := strings.IndexByte(string(raw), 0); i >= 0 {
		end = i
	}
	if end > 256 {
		return "", false
	}
	s := string(raw[:end])
	for _, c := range s[4:] {
		if c != '-' && (c < '0' || c > '9') {
			return "", false
		}
	}
	// The prefix guarantees at least one authority digit follows "S-1-".
	if len(s) == 4 || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return "", false
	}
	return s, true
}

// sidFromBinary decodes the packed _SID structure. Revision must be 1 and a
// process SID always carries at least one sub-authority; the Windows maximum
// is 15 (SID_MAX_SUB_AUTHORITIES).
func sidFromBinary(raw []byte) (string, bool) {
	if len(raw) < 8 || raw[0] != 1 {
		return "", false
	}
	count := int(raw[1])
	if count < 1 || count > 15 || len(raw) < 8+4*count {
		return "", false
	}
	// IdentifierAuthority is a 48-bit big-endian integer.
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var sb strings.Builder
	if authority < 1<<32 {
		fmt.Fprintf(&sb, "S-1-%d", authority)
	} else {
		// The documented SID string form switches to hex above 32 bits.
		fmt.Fprintf(&sb, "S-1-0x%012X", authority)
	}
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(raw[8+4*i:]))
	}
	return sb.String(), true
}
