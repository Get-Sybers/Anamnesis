// Package memprocfs is the ONLY native seam: the Engine interface abstracts the
// MemProcFS vmm library behind anamnesis's own domain structs, so the collectors
// never see purego and the binding is swappable. A memory image is opened once;
// each method answers one enumeration the collectors reshape into CAR records.
//
// The definitive-link identity is the process's _EPROCESS virtual address
// (Process.EPROCESS): the collectors stamp it as the process guid
// ("proc-<hex>") and as every spoke's OwnerOffset, exactly as the
// windows.anamnesis.* plugins did — so enrichment links by the kernel's own pointer,
// not the reused PID.
package memprocfs

import "strconv"

// Process is one process (MemProcFS GetProcessInfoAll + PEB/token reads).
type Process struct {
	PID            uint32
	PPID           uint32
	EPROCESS       uint64 // virtual address of _EPROCESS — the definitive identity
	DTB            uint64
	Name           string // short image name (<= 15 chars)
	Path           string // full image path (PEB ImagePathName)
	CommandLine    string
	ParentPath     string
	CreateTime     string // ISO-8601 UTC, "" if unknown
	Cwd            string
	EnvVars        string
	IntegrityLevel string
	SID            string
	User           string
	LogonID        string // token AuthenticationId LUID as hex ("0x...")
	SessionID      int
	DLLPaths       []string
}

// Module is one loaded module in a process (GetModuleList).
type Module struct {
	Base      uint64
	Size      uint64
	Name      string
	Path      string
	LoadTime  string
	LoadCount int
}

// Thread is one thread (GetThreadList + callstack).
type Thread struct {
	TID                uint32
	ETHREAD            uint64
	CreateTime         string
	ExitTime           string
	Win32StartAddress  uint64
	Win32StartPath     string
	Win32StartFunction string
	StartAddress       uint64
	StartPath          string
	StartFunction      string
	StackBase          uint64
	StackLimit         uint64
	UserStackBase      uint64
	UserStackLimit     uint64
}

// Handle is one kernel handle held by a process (GetHandleList). For File handles
// Name is the file path; for Process handles Target* identify the target process.
type Handle struct {
	HandleValue    uint64
	Type           string // "File", "Process", ...
	GrantedAccess  uint64
	Name           string
	ObjectVA       uint64 // the underlying object (FILE_OBJECT for files)
	TargetPID      uint32
	TargetName     string
	TargetEPROCESS uint64
}

// NetEntry is one network endpoint (GetNetList): a connection or a bound socket.
type NetEntry struct {
	Offset      uint64
	Proto       string // TCPv4/TCPv6/UDPv4/...
	LocalAddr   string
	LocalPort   int
	ForeignAddr string
	ForeignPort int
	State       string
	PID         uint32
	Owner       string
	Created     string
}

// Service is one Windows service (GetServiceList).
type Service struct {
	Offset         uint64
	Name           string
	PID            uint32
	Binary         string // running ImagePath (null when stopped)
	BinaryRegistry string // registry ImagePath (incl. arguments)
	State          string
	Type           string
	Start          string
	Display        string
	Dll            string
	Order          int
}

// Driver is one kernel driver (GetKDriverList).
type Driver struct {
	Offset uint64
	Name   string
	Path   string
	Base   uint64
	Size   uint64
}

// RegValue is one registry value under a curated key.
type RegValue struct {
	Hive      string
	Key       string
	ValueName string
	ValueType string
	ValueData string
	LastWrite string
}

// MFTRecord is one $MFT attribute row (forensic NTFS).
type MFTRecord struct {
	RecordNumber  int
	AttributeType string
	MFTType       string
	Filename      string
	Created       string
	Modified      string
	Updated       string
	Accessed      string
	Offset        uint64
	Permissions   string
}

// FileObject is one ownerless FILE_OBJECT (forensic file scan).
type FileObject struct {
	Offset uint64
	Name   string
}

// MalRegion is one suspicious VAD region (private, executable, non-image).
type MalRegion struct {
	PID           uint32
	Process       string
	StartVPN      uint64
	EndVPN        uint64
	Protection    string
	Tag           string
	CommitCharge  int
	PrivateMemory int
	Disasm        string
	Hexdump       string
}

// Engine is the native memory-analysis surface anamnesis needs. One image, opened
// once; every method is an enumeration. An implementation wraps MemProcFS.
type Engine interface {
	Processes() ([]Process, error)
	ActivePIDs() (map[uint32]bool, error) // the linked/active list (for the Hidden contrast)
	Modules(pid uint32) ([]Module, error)
	Threads(pid uint32) ([]Thread, error)
	Handles(pid uint32) ([]Handle, error)
	NetEntries() ([]NetEntry, error)
	Services() ([]Service, error)
	Drivers() ([]Driver, error)
	RegistryValues(targets []string) ([]RegValue, error)
	Info() (map[string]string, error) // Variable -> Value (windows.info)
	Banners() ([]string, error)
	MFT() ([]MFTRecord, error)
	FileScan() ([]FileObject, error)
	Malfind() ([]MalRegion, error)
	Close() error
}

// ProcGUID synthesizes the CAR process guid from an _EPROCESS virtual address —
// "proc-<hex>", the same convention the pipeline keys on.
func ProcGUID(eprocess uint64) string {
	return "proc-" + strconv.FormatUint(eprocess, 16)
}

// OpenOptions configures how the native engine opens a memory image.
//
// There is no symbol option: the engine is always offline. PDB symbols are a
// baked dependency of the container image (a pre-populated Symbols/ cache
// beside vmm.so, seeded at image build time); the engine only ever reads that
// cache, never the network.
type OpenOptions struct {
	// LibPath is the MemProcFS vmm shared library (vmm.so). Empty uses the
	// implementation default (env ANAMNESIS_VMM_LIB, else a baked-in path).
	LibPath string
	// Forensic enables MemProcFS forensic mode. Nothing consumes it yet (the
	// MFT / file-scan / malfind collectors are on-target stubs), and its
	// background plugin init deadlocks vmm.so 5.18 — an ObjFile↔Registry lock
	// inversion between FcNtfs2 and MFcAmcache/MFcRegistry initializers that
	// wedges every later map call (GetHandleList observed). Leave it off until
	// a consumer exists AND the open gates on forensic-init completion.
	Forensic bool
}

// Open is defined per build: the default build returns a clear "no native backend"
// error; the memprocfs-tagged build wires the MemProcFS vmm library. This lets the
// whole pipeline build and test with CGO_ENABLED=0 and no native library present.
