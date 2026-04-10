// Fuzz tests for the identify package. Archive format detection operates on
// untrusted external data and is an ideal fuzz target: any input that causes
// a panic or non-deterministic result is a bug.
package identify

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// FuzzIdentify verifies that format identification never panics on arbitrary
// byte sequences. The seed corpus covers every magic-byte prefix supported
// by the identify package.
func FuzzIdentify(f *testing.F) {
	// Seed with valid magic byte prefixes for each handled format.
	seeds := [][]byte{
		{'P', 'K', 0x03, 0x04},                           // ZIP
		{'P', 'K', 0x03, 0x04, 0, 0, 0, 0},               // ZIP (JAR-like)
		{0x1F, 0x8B},                                     // Gzip
		{'B', 'Z', 'h', '9'},                             // Bzip2
		{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00},             // XZ
		{0x28, 0xB5, 0x2F, 0xFD},                         // Zstd
		{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C},               // 7z
		{'M', 'S', 'C', 'F'},                             // CAB
		{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // MSI/OLE
		{'I', 'S', 'c', '('},                             // InstallShield
		{'R', 'a', 'r', '!', 0x1A, 0x07},                 // RAR
		make([]byte, 300),                                // All zeroes
		{0xFF, 0xFE, 0x00, 0x01},                         // Unknown / BOM-like
	}

	// TAR: ustar magic at offset 257.
	ustar := make([]byte, 300)
	copy(ustar[257:], "ustar")
	seeds = append(seeds, ustar)

	for _, s := range seeds {
		f.Add(s, "test.bin")
		f.Add(s, "test.tar.gz")
		f.Add(s, "test.jar")
	}

	f.Fuzz(func(t *testing.T, data []byte, filename string) {
		dir := t.TempDir()

		// Sanitize the filename to avoid directory traversal in the test itself.
		base := filepath.Base(filename)
		if base == "" || base == "." {
			base = "fuzz.bin"
		}

		path := filepath.Join(dir, base)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			// Filesystem write failure is not a bug in identify.
			t.Skip()
		}

		// Must not panic. The return value and error are both valid outcomes.
		info, err := Identify(context.Background(), path)
		_ = err
		// Verify the returned FormatInfo is self-consistent.
		if info.SyftNative && info.Extractable {
			t.Errorf("FormatInfo inconsistency: SyftNative and Extractable both true for %v", info.Format)
		}
	})
}
