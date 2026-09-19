//go:build !memprocfs

package memprocfs

import "errors"

// ErrNoBackend is returned by the default build, which carries no native engine.
var ErrNoBackend = errors.New("flashback was built without the MemProcFS backend; " +
	"rebuild with `-tags memprocfs` and ensure the vmm native library is present " +
	"(FLASHBACK_VMM_LIB or --lib)")

// Open (default build) has no native backend.
func Open(imagePath string, opt OpenOptions) (Engine, error) {
	return nil, ErrNoBackend
}
