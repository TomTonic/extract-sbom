package orchestrator

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// createMinimalZIP creates a minimal valid ZIP file for pipeline testing.
func createMinimalZIP(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	fw, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("test content")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	return path
}

// createZIPWithNestedZIP creates a ZIP that contains another ZIP inside it.
func createZIPWithNestedZIP(t *testing.T, dir string, outerName string) string {
	t.Helper()

	var innerBuf []byte
	{
		var b []byte
		innerW := zip.NewWriter(newBytesWriter(&b))
		fw, err := innerW.Create("inner-file.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("inner content")); err != nil {
			t.Fatal(err)
		}
		if err := innerW.Close(); err != nil {
			t.Fatal(err)
		}
		innerBuf = b
	}

	outerPath := filepath.Join(dir, outerName)
	f, err := os.Create(outerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)

	fw, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fw.Write([]byte("outer readme")); err != nil {
		t.Fatal(err)
	}

	fw2, err := w.Create("inner.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw2.Write(innerBuf); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return outerPath
}

// createJARWithManifestBytes creates a minimal JAR payload in memory.
func createJARWithManifestBytes(t *testing.T) []byte {
	t.Helper()

	var jarBuf []byte
	jarW := zip.NewWriter(newBytesWriter(&jarBuf))
	manifest, err := jarW.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manifest.Write([]byte("Manifest-Version: 1.0\n")); err != nil {
		t.Fatal(err)
	}
	classFile, err := jarW.Create("com/example/App.class")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := classFile.Write([]byte("CAFE")); err != nil {
		t.Fatal(err)
	}
	if err := jarW.Close(); err != nil {
		t.Fatal(err)
	}

	return jarBuf
}

// createZIPWithNestedZIPAndJAR creates a delivery ZIP containing an inner ZIP
// that itself contains a JAR with a manifest.
func createZIPWithNestedZIPAndJAR(t *testing.T, dir string, outerName string) string {
	t.Helper()

	jarBytes := createJARWithManifestBytes(t)

	var innerBuf []byte
	innerW := zip.NewWriter(newBytesWriter(&innerBuf))
	jarEntry, err := innerW.Create("lib/app.jar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = jarEntry.Write(jarBytes); err != nil {
		t.Fatal(err)
	}
	if closeErr := innerW.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	outerPath := filepath.Join(dir, outerName)
	f, err := os.Create(outerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	innerEntry, err := w.Create("inner.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = innerEntry.Write(innerBuf); err != nil {
		t.Fatal(err)
	}
	readmeEntry, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readmeEntry.Write([]byte("nested delivery")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return outerPath
}

// bytesWriter is a minimal io.Writer that accumulates into a slice pointer.
type bytesWriter struct{ buf *[]byte }

func newBytesWriter(buf *[]byte) *bytesWriter { return &bytesWriter{buf: buf} }
func (b *bytesWriter) Write(p []byte) (int, error) {
	*b.buf = append(*b.buf, p...)
	return len(p), nil
}
