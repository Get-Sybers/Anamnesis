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

// sidFromASCII accepts an "S-1-…" string of digits and dashes. A NUL, if
// present, ends it; the buffer need not be terminated (a fixed-size field may
// carry the string flush to its end).
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
	return sidBinary(raw, false)
}

// sidBinary decodes a packed _SID. In strict mode the identifier authority
// must be a real one (0..16), which lets a memory buffer be swept for SIDs
// without a random qword — Revision 1, a small count — passing as one.
func sidBinary(raw []byte, strict bool) (string, bool) {
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
	if strict && authority > 16 {
		return "", false
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

// PickUserSID chooses the user SID from the SIDs swept out of a token, and
// the method for provenance. A SID the registry knows as a real account
// (knownAccount) is the strongest signal and also yields the account name;
// otherwise a well-known service identity, then any machine/domain account
// SID (S-1-5-21-*). Group and integrity SIDs are passed over. "" when nothing
// qualifies (docs/design/symbol-recovery.md §6, §10 — heuristic, single-view).
func PickUserSID(sids []string, knownAccount func(string) bool) (string, string) {
	for _, s := range sids {
		if knownAccount != nil && knownAccount(s) {
			return s, "token+profile"
		}
	}
	for _, s := range sids {
		switch s {
		case "S-1-5-18", "S-1-5-19", "S-1-5-20":
			return s, "token+wellknown"
		}
	}
	for _, s := range sids {
		if strings.HasPrefix(s, "S-1-5-21-") {
			return s, "token+account"
		}
	}
	return "", ""
}

// ScanSIDs returns every structurally valid _SID found on a 4-byte boundary
// in buf, deduped in first-seen order. SIDs sit 4-aligned in a token
// allocation; the strict authority bound keeps a stray qword from reading as
// a SID, so a token can be swept for the SIDs it carries (docs/design/
// symbol-recovery.md §6).
func ScanSIDs(buf []byte) []string {
	var out []string
	seen := map[string]bool{}
	for off := 0; off+8 <= len(buf); off += 4 {
		s, ok := sidBinary(buf[off:], true)
		if !ok || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
