// Fuzz tests for the safeguard package. Path validation and entry validation
// process archive metadata from untrusted external sources and must never
// panic or produce inconsistent results regardless of input.
package safeguard

import (
	"os"
	"testing"

	"github.com/sbom-sentry/internal/config"
)

// FuzzValidatePath verifies that path safety checking never panics on
// arbitrary entry names. Path traversal detection is a critical security
// boundary — a panic or missed traversal is a vulnerability.
func FuzzValidatePath(f *testing.F) {
	seeds := []string{
		"safe/file.txt",
		"../escape",
		"../../etc/passwd",
		"/absolute/path",
		"",
		".",
		"..",
		"dir/../file",
		"a/b/c/d/e/f/g",
		"\x00null-byte",
		"safe\\windows\\path",
		"./relative",
		"dir/./file",
		"a/b/../../c",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, entryName string) {
		dir := t.TempDir()
		// Must not panic. Both nil and non-nil error are valid outcomes.
		err := ValidatePath(entryName, dir)
		_ = err
	})
}

// FuzzValidateEntry verifies that entry validation never panics on arbitrary
// header values. Resource limit checks involve integer arithmetic that must
// not overflow or panic.
func FuzzValidateEntry(f *testing.F) {
	f.Add("file.txt", int64(1024), int64(512), false, false, uint32(0o644))
	f.Add("bomb.bin", int64(1_000_000_000), int64(1), false, false, uint32(0o644))
	f.Add("link", int64(0), int64(0), false, true, uint32(0o755))
	f.Add("device", int64(0), int64(0), false, false, uint32(0o666|uint32(os.ModeDevice)))
	f.Add("dir/", int64(0), int64(0), true, false, uint32(0o755))
	f.Add("", int64(-1), int64(-1), false, false, uint32(0))
	f.Add("x", int64(^int64(0)>>1), int64(1), false, false, uint32(0o644)) // MaxInt64

	f.Fuzz(func(t *testing.T, name string, uncompSize int64, compSize int64, isDir bool, isSymlink bool, rawMode uint32) {
		limits := config.DefaultLimits()
		stats := &ExtractionStats{}
		header := EntryHeader{
			Name:             name,
			UncompressedSize: uncompSize,
			CompressedSize:   compSize,
			IsDir:            isDir,
			IsSymlink:        isSymlink,
			Mode:             os.FileMode(rawMode),
		}
		// Must not panic. Any error type is a valid result.
		err := ValidateEntry(header, limits, stats)
		_ = err
	})
}
