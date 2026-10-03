package symbols

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// fakeMem is a sparse address space of byte segments. A read inside a segment
// returns what the segment holds from that point (short when the request runs
// past its end); a read starting outside every segment fails.
type fakeMem struct {
	segs map[uint64][]byte
}

func (m fakeMem) ReadVirtual(va uint64, n uint32) ([]byte, bool) {
	for base, b := range m.segs {
		if va >= base && va < base+uint64(len(b)) {
			off := va - base
			end := off + uint64(n)
			if end > uint64(len(b)) {
				end = uint64(len(b))
			}
			return b[off:end], true
		}
	}
	return nil, false
}

const (
	tPEB    = 0x0000_0000_0020_0000
	tParams = 0x0000_0000_0030_0000
	tImgBuf = 0x0000_0000_0040_0000
	tCmdBuf = 0x0000_0000_0041_0000
)

func utf16LE(s string) []byte {
	words := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[2*i:], w)
	}
	return b
}

func putUS64(block []byte, off int, length, maxLen uint16, buffer uint64) {
	binary.LittleEndian.PutUint16(block[off:], length)
	binary.LittleEndian.PutUint16(block[off+2:], maxLen)
	binary.LittleEndian.PutUint64(block[off+8:], buffer)
}

func putUS32(block []byte, off int, length, maxLen uint16, buffer uint32) {
	binary.LittleEndian.PutUint16(block[off:], length)
	binary.LittleEndian.PutUint16(block[off+2:], maxLen)
	binary.LittleEndian.PutUint32(block[off+4:], buffer)
}

// space builds a 64-bit PEB → params → string-buffer layout with the
// ImagePathName/CommandLine headers at the given offsets in the params block.
func space(img, cmd string, imgOff, cmdOff int) fakeMem {
	peb := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(peb[pebProcessParams64:], tParams)
	params := make([]byte, paramsScanWindow)
	imgB, cmdB := utf16LE(img), utf16LE(cmd)
	putUS64(params, imgOff, uint16(len(imgB)), uint16(len(imgB)+2), tImgBuf)
	putUS64(params, cmdOff, uint16(len(cmdB)), uint16(len(cmdB)+2), tCmdBuf)
	return fakeMem{segs: map[uint64][]byte{
		tPEB:    peb,
		tParams: params,
		tImgBuf: imgB,
		tCmdBuf: cmdB,
	}}
}

func TestRecoverProcParamsFastPath(t *testing.T) {
	m := space(`C:\Windows\System32\svchost.exe`, `svchost.exe -k netsvcs`, paramsImagePath64, paramsCommandLine64)
	res, ok := RecoverProcParams(m, tPEB, `C:\Windows\System32\svchost.exe`)
	if !ok || res.CommandLine != `svchost.exe -k netsvcs` || res.Method != "peb+0x60_anchor" {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
	if res.Confidence != BestEffort {
		t.Fatalf("confidence %q, want %q", res.Confidence, BestEffort)
	}
}

func TestRecoverProcParamsNTPrefixAnchor(t *testing.T) {
	m := space(`\??\C:\Tools\a.exe`, `a.exe /x`, paramsImagePath64, paramsCommandLine64)
	if res, ok := RecoverProcParams(m, tPEB, `c:\tools\A.EXE`); !ok || res.CommandLine != `a.exe /x` {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
}

func TestRecoverProcParamsDeviceVsDrive(t *testing.T) {
	m := space(`\Device\HarddiskVolume2\Windows\explorer.exe`, `explorer.exe`, paramsImagePath64, paramsCommandLine64)
	if res, ok := RecoverProcParams(m, tPEB, `C:\Windows\explorer.exe`); !ok || res.CommandLine != `explorer.exe` {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
}

func TestRecoverProcParamsScanPath(t *testing.T) {
	// Layout shifted: strings live at +0x88/+0x98 — only the anchored scan finds them.
	m := space(`C:\a\b.exe`, `b.exe 1`, 0x88, 0x98)
	res, ok := RecoverProcParams(m, tPEB, `C:\a\b.exe`)
	if !ok || res.CommandLine != `b.exe 1` || res.Method != "peb_scan_anchor" {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
}

func TestRecoverProcParamsAnchorMismatchNoGuess(t *testing.T) {
	m := space(`C:\evil\hollowed.exe`, `hollowed.exe`, paramsImagePath64, paramsCommandLine64)
	if res, ok := RecoverProcParams(m, tPEB, `C:\Windows\System32\lsass.exe`); ok {
		t.Fatalf("anchor mismatch must fail, got %+v", res)
	}
}

func TestRecoverProcParamsUnanchored(t *testing.T) {
	m := space(`C:\x\y.exe`, `y.exe`, paramsImagePath64, paramsCommandLine64)
	res, ok := RecoverProcParams(m, tPEB, "")
	if !ok || res.Method != "peb_fixed_unanchored" || res.CommandLine != `y.exe` {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
	// A non-path-shaped ImagePathName is rejected without an anchor.
	m2 := space(`garbage`, `y.exe`, paramsImagePath64, paramsCommandLine64)
	if res, ok := RecoverProcParams(m2, tPEB, ""); ok {
		t.Fatalf("non-path image must fail unanchored, got %+v", res)
	}
}

func TestRecoverProcParamsEmptyLength(t *testing.T) {
	m := space(`C:\x\y.exe`, ``, paramsImagePath64, paramsCommandLine64)
	res, ok := RecoverProcParams(m, tPEB, `C:\x\y.exe`)
	if !ok || res.CommandLine != "" {
		t.Fatalf("Length 0 is a legitimate empty, got (%+v, %v)", res, ok)
	}
}

func TestRecoverProcParamsStructuralRejects(t *testing.T) {
	base := func() fakeMem {
		return space(`C:\x\y.exe`, `y.exe`, paramsImagePath64, paramsCommandLine64)
	}
	corrupt := []struct {
		name string
		mut  func(m fakeMem)
	}{
		{"odd length", func(m fakeMem) {
			binary.LittleEndian.PutUint16(m.segs[tParams][paramsCommandLine64:], 3)
		}},
		{"max below length", func(m fakeMem) {
			binary.LittleEndian.PutUint16(m.segs[tParams][paramsCommandLine64+2:], 2)
		}},
		{"max above cap", func(m fakeMem) {
			binary.LittleEndian.PutUint16(m.segs[tParams][paramsCommandLine64:], 0xfffe)
			binary.LittleEndian.PutUint16(m.segs[tParams][paramsCommandLine64+2:], 0xffff)
		}},
		{"non-canonical buffer", func(m fakeMem) {
			binary.LittleEndian.PutUint64(m.segs[tParams][paramsCommandLine64+8:], 0xffff_8000_0000_0000)
		}},
		{"paged-out buffer", func(m fakeMem) {
			delete(m.segs, tCmdBuf)
		}},
	}
	for _, c := range corrupt {
		t.Run(c.name, func(t *testing.T) {
			m := base()
			c.mut(m)
			if res, ok := RecoverProcParams(m, tPEB, `C:\x\y.exe`); ok {
				t.Fatalf("corrupt CommandLine must fail, got %+v", res)
			}
		})
	}
}

func TestRecoverProcParamsPagedPEB(t *testing.T) {
	m := space(`C:\x\y.exe`, `y.exe`, paramsImagePath64, paramsCommandLine64)
	delete(m.segs, tPEB)
	if _, ok := RecoverProcParams(m, tPEB, `C:\x\y.exe`); ok {
		t.Fatal("unreadable PEB must fail")
	}
	if _, ok := RecoverProcParams(m, 0, `C:\x\y.exe`); ok {
		t.Fatal("PEB 0 must fail")
	}
}

func TestRecoverProcParams32(t *testing.T) {
	const (
		peb32 = 0x0000_0000_0002_0000
		par32 = 0x0000_0000_0003_0000
		img32 = 0x0000_0000_0004_0000
		cmd32 = 0x0000_0000_0005_0000
	)
	peb := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(peb[pebProcessParams32:], par32)
	params := make([]byte, paramsScanWindow)
	imgB, cmdB := utf16LE(`C:\m57\iexplore.exe`), utf16LE(`iexplore.exe -home`)
	putUS32(params, paramsImagePath32, uint16(len(imgB)), uint16(len(imgB)+2), img32)
	putUS32(params, paramsCommandLine32, uint16(len(cmdB)), uint16(len(cmdB)+2), cmd32)
	m := fakeMem{segs: map[uint64][]byte{peb32: peb, par32: params, img32: imgB, cmd32: cmdB}}
	res, ok := RecoverProcParams32(m, peb32, `C:\m57\iexplore.exe`)
	if !ok || res.CommandLine != `iexplore.exe -home` || res.Method != "peb32+0x38_anchor" {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
}

func TestRecoverProcParamsSiblings(t *testing.T) {
	const (
		tCwdBuf = 0x0000_0000_0042_0000
		tEnvBuf = 0x0000_0000_0043_0000
	)
	m := space(`C:\Windows\System32\svchost.exe`, `svchost.exe -k netsvcs`, paramsImagePath64, paramsCommandLine64)
	// CurrentDirectory.DosPath at +0x38 and the Environment pointer at +0x80.
	cwdB := utf16LE(`C:\Windows\system32\`)
	putUS64(m.segs[tParams], paramsCwd64, uint16(len(cwdB)), uint16(len(cwdB)+2), tCwdBuf)
	binary.LittleEndian.PutUint64(m.segs[tParams][paramsEnv64:], tEnvBuf)
	env := append(utf16LE("PATH=C:\\Windows;C:\\Tools"), 0, 0)
	env = append(env, utf16LE("TEMP=C:\\Users\\a\\Temp")...)
	env = append(env, 0, 0, 0, 0) // entry NUL + block terminator
	m.segs[tCwdBuf] = cwdB
	m.segs[tEnvBuf] = env
	res, ok := RecoverProcParams(m, tPEB, `C:\Windows\System32\svchost.exe`)
	if !ok || res.CommandLine != `svchost.exe -k netsvcs` {
		t.Fatalf("got (%+v, %v)", res, ok)
	}
	if res.Cwd != `C:\Windows\system32\` {
		t.Fatalf("Cwd = %q", res.Cwd)
	}
	if res.Env != "PATH=C:\\Windows;C:\\Tools\nTEMP=C:\\Users\\a\\Temp" {
		t.Fatalf("Env = %q", res.Env)
	}
	// Siblings are best-effort: a paged-out env block costs only Env.
	delete(m.segs, tEnvBuf)
	res, ok = RecoverProcParams(m, tPEB, `C:\Windows\System32\svchost.exe`)
	if !ok || res.CommandLine == "" || res.Env != "" || res.Cwd == "" {
		t.Fatalf("paged env must cost only Env: (%+v, %v)", res, ok)
	}
}

func TestParseEnvBlock(t *testing.T) {
	entry := func(s string) []byte { return append(utf16LE(s), 0, 0) }
	full := append(append(entry("A=1"), entry("B=2")...), 0, 0)
	if got := parseEnvBlock(full); got != "A=1\nB=2" {
		t.Fatalf("full block = %q", got)
	}
	// Truncated window: the trailing fragment (no NUL) is dropped.
	trunc := append(entry("A=1"), utf16LE("B=partial")...)
	if got := parseEnvBlock(trunc); got != "A=1" {
		t.Fatalf("truncated block = %q", got)
	}
	if got := parseEnvBlock([]byte{0, 0, 0, 0}); got != "" {
		t.Fatalf("empty block = %q", got)
	}
}

func TestAnchorMatch(t *testing.T) {
	cases := []struct {
		img, anchor string
		want        bool
	}{
		{`C:\a\b.exe`, `c:/A/B.EXE`, true},
		{`\??\C:\a\b.exe`, `C:\a\b.exe`, true},
		{`\Device\HarddiskVolume3\a\b.exe`, `D:\a\b.exe`, true},
		{`C:\a\b.exe`, `C:\a\c.exe`, false},
		{``, `C:\a\b.exe`, false},
		{`\Device\HarddiskVolume3`, `\Device\HarddiskVolume4`, false},
	}
	for _, c := range cases {
		if got := anchorMatch(c.img, c.anchor); got != c.want {
			t.Errorf("anchorMatch(%q, %q) = %v, want %v", c.img, c.anchor, got, c.want)
		}
	}
}
