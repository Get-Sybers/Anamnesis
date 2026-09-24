package symbols

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
)

// PEImage is a CodeSource backed by an on-disk PE (e.g. a harvested ntoskrnl.exe
// at build time, or a kernel image carved from a dump). It resolves exported
// function names to code bytes via the PE export directory — which debug/pe does
// not surface — so accessor disassembly needs no external tooling.
type PEImage struct {
	imageBase uint64
	sections  []peSection
	exports   map[string]uint32 // name -> function RVA
	debugRVA  uint32            // IMAGE_DIRECTORY_ENTRY_DEBUG
	debugSize uint32
}

type peSection struct {
	va   uint32
	size uint32 // readable extent (min of virtual and raw size)
	data []byte
}

// OpenPE parses the PE at path and indexes its exports.
func OpenPE(path string) (*PEImage, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return newPEImage(f)
}

func newPEImage(f *pe.File) (*PEImage, error) {
	img := &PEImage{exports: map[string]uint32{}}

	var exportRVA, exportSize uint32
	dir := func(d []pe.DataDirectory, i int) (uint32, uint32) {
		if len(d) > i {
			return d[i].VirtualAddress, d[i].Size
		}
		return 0, 0
	}
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		img.imageBase = oh.ImageBase
		exportRVA, exportSize = dir(oh.DataDirectory[:], 0)
		img.debugRVA, img.debugSize = dir(oh.DataDirectory[:], 6)
	case *pe.OptionalHeader32:
		img.imageBase = uint64(oh.ImageBase)
		exportRVA, exportSize = dir(oh.DataDirectory[:], 0)
		img.debugRVA, img.debugSize = dir(oh.DataDirectory[:], 6)
	default:
		return nil, fmt.Errorf("unsupported PE optional header %T", f.OptionalHeader)
	}

	for _, s := range f.Sections {
		data, err := s.Data()
		if err != nil {
			return nil, fmt.Errorf("read section %s: %w", s.Name, err)
		}
		size := s.VirtualSize
		if uint32(len(data)) < size {
			size = uint32(len(data)) // only file-backed bytes are readable
		}
		img.sections = append(img.sections, peSection{va: s.VirtualAddress, size: size, data: data})
	}
	sort.Slice(img.sections, func(i, j int) bool { return img.sections[i].va < img.sections[j].va })

	if exportRVA != 0 && exportSize != 0 {
		if err := img.parseExports(exportRVA, exportSize); err != nil {
			return nil, err
		}
	}
	if len(img.exports) == 0 {
		return nil, fmt.Errorf("no exports found (not a kernel image?)")
	}
	return img, nil
}

// readAtRVA returns n bytes at a relative virtual address, or as many as are
// file-backed if the section is shorter.
func (p *PEImage) readAtRVA(rva, n uint32) ([]byte, bool) {
	for _, s := range p.sections {
		if rva >= s.va && rva < s.va+s.size {
			off := rva - s.va
			end := off + n
			if end > uint32(len(s.data)) {
				end = uint32(len(s.data))
			}
			return s.data[off:end], true
		}
	}
	return nil, false
}

// IMAGE_EXPORT_DIRECTORY field offsets we use.
const (
	edNumberOfFunctions    = 0x14
	edNumberOfNames        = 0x18
	edAddressOfFunctions   = 0x1C
	edAddressOfNames       = 0x20
	edAddressOfNameOrdinal = 0x24
	edSize                 = 0x28
)

func (p *PEImage) parseExports(dirRVA, dirSize uint32) error {
	hdr, ok := p.readAtRVA(dirRVA, edSize)
	if !ok || len(hdr) < edSize {
		return fmt.Errorf("export directory not readable at rva %#x", dirRVA)
	}
	numNames := binary.LittleEndian.Uint32(hdr[edNumberOfNames:])
	numFuncs := binary.LittleEndian.Uint32(hdr[edNumberOfFunctions:])
	funcsRVA := binary.LittleEndian.Uint32(hdr[edAddressOfFunctions:])
	namesRVA := binary.LittleEndian.Uint32(hdr[edAddressOfNames:])
	ordsRVA := binary.LittleEndian.Uint32(hdr[edAddressOfNameOrdinal:])

	const sane = 1 << 20 // guard against a corrupt header steering huge loops
	if numNames > sane || numFuncs > sane {
		return fmt.Errorf("implausible export counts (names=%d funcs=%d)", numNames, numFuncs)
	}

	names, ok := p.readAtRVA(namesRVA, numNames*4)
	if !ok {
		return fmt.Errorf("export name table not readable")
	}
	ords, ok := p.readAtRVA(ordsRVA, numNames*2)
	if !ok {
		return fmt.Errorf("export ordinal table not readable")
	}
	funcs, ok := p.readAtRVA(funcsRVA, numFuncs*4)
	if !ok {
		return fmt.Errorf("export address table not readable")
	}

	for i := uint32(0); i < numNames; i++ {
		if int(i*4+4) > len(names) || int(i*2+2) > len(ords) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(names[i*4:])
		ord := binary.LittleEndian.Uint16(ords[i*2:])
		if int(ord)*4+4 > len(funcs) {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(funcs[ord*4:])
		if funcRVA == 0 {
			continue
		}
		// A function RVA inside the export directory is a forwarder string, not code.
		if funcRVA >= dirRVA && funcRVA < dirRVA+dirSize {
			continue
		}
		name := p.readCString(nameRVA)
		if name != "" {
			p.exports[name] = funcRVA
		}
	}
	return nil
}

func (p *PEImage) readCString(rva uint32) string {
	buf, ok := p.readAtRVA(rva, 256)
	if !ok {
		return ""
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// CodeView reads the PE's RSDS debug record and returns the module's symbol
// identity as MemProcFS keys it: the GUID as 32 uppercase hex digits (Data1/2/3
// little-endian, Data4 verbatim — the symbol-server convention the runtime
// store key uses) plus the age. This is the (GUID, age) a build-time seed must
// carry so it matches the runtime GetModuleByName key exactly.
func (p *PEImage) CodeView() (guid string, age uint32, err error) {
	if p.debugRVA == 0 || p.debugSize == 0 {
		return "", 0, fmt.Errorf("no debug directory")
	}
	const entrySize = 28 // IMAGE_DEBUG_DIRECTORY
	dir, ok := p.readAtRVA(p.debugRVA, p.debugSize)
	if !ok || len(dir) < entrySize {
		return "", 0, fmt.Errorf("debug directory not readable")
	}
	for off := 0; off+entrySize <= len(dir); off += entrySize {
		e := dir[off:]
		if binary.LittleEndian.Uint32(e[12:]) != 2 { // Type == IMAGE_DEBUG_TYPE_CODEVIEW
			continue
		}
		size := binary.LittleEndian.Uint32(e[16:])
		rva := binary.LittleEndian.Uint32(e[20:])
		if rva == 0 || size < 24 {
			continue
		}
		rec, ok := p.readAtRVA(rva, size)
		if !ok || len(rec) < 24 || string(rec[:4]) != "RSDS" {
			continue
		}
		g := rec[4:20]
		guid = fmt.Sprintf("%08X%04X%04X%X",
			binary.LittleEndian.Uint32(g[0:4]),
			binary.LittleEndian.Uint16(g[4:6]),
			binary.LittleEndian.Uint16(g[6:8]),
			g[8:16]) // Data4: 8 bytes verbatim -> 16 hex digits
		return guid, binary.LittleEndian.Uint32(rec[20:24]), nil
	}
	return "", 0, fmt.Errorf("no RSDS CodeView record in debug directory")
}

// FunctionCode implements CodeSource: it returns a leading window of an exported
// function's bytes and the function's virtual address (ImageBase + RVA).
func (p *PEImage) FunctionCode(name string) ([]byte, uint64, error) {
	return p.FunctionCodeN(name, codeWindow)
}

// FunctionCodeN returns up to n leading bytes — the wider window global
// recovery needs (the referencing instruction can sit into the body).
func (p *PEImage) FunctionCodeN(name string, n int) ([]byte, uint64, error) {
	rva, ok := p.exports[name]
	if !ok {
		return nil, 0, fmt.Errorf("export %q not found", name)
	}
	code, ok := p.readAtRVA(rva, uint32(n))
	if !ok || len(code) == 0 {
		return nil, 0, fmt.Errorf("code for %q not readable at rva %#x", name, rva)
	}
	return code, p.imageBase + uint64(rva), nil
}
