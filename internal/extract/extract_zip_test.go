package extract

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestExtractZIPProducesExtractionTree(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()

	zipPath := createTestZIP(t, dir, "delivery.zip", map[string][]byte{
		"readme.txt":     []byte("Hello World"),
		"lib/helper.dll": []byte("MZ fake DLL content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), zipPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tree == nil {
		t.Fatal("extraction tree is nil")
	}

	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want Extracted", tree.Status)
	}

	if tree.EntriesCount != 2 {
		t.Errorf("EntriesCount = %d, want 2", tree.EntriesCount)
	}

	if tree.ExtractedDir == "" {
		t.Fatal("ExtractedDir is empty")
	}

	readmePath := filepath.Join(tree.ExtractedDir, "readme.txt")
	content, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("cannot read extracted readme.txt: %v", err)
	}
	if string(content) != "Hello World" {
		t.Errorf("readme.txt content = %q, want %q", string(content), "Hello World")
	}

	CleanupNode(tree)
}

func TestExtractUsesConfiguredWorkDir(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatalf("create work dir: %v", err)
	}

	zipPath := createTestZIP(t, dir, "delivery.zip", map[string][]byte{
		"readme.txt": []byte("Hello WorkDir"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.WorkDir = workDir
	cfg.Unsafe = true

	tree, err := Extract(context.Background(), zipPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.ExtractedDir == "" {
		t.Fatal("ExtractedDir is empty")
	}
	if filepath.Dir(tree.ExtractedDir) != workDir {
		t.Fatalf("ExtractedDir parent = %q, want %q", filepath.Dir(tree.ExtractedDir), workDir)
	}

	CleanupNode(tree)
}

func TestExtractZIPPathTraversalEntryIsNormalizedBy7Zip(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()

	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	fw, err := w.Create("normal.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, wErr := fw.Write([]byte("safe")); wErr != nil {
		t.Fatal(wErr)
	}

	hdr := &zip.FileHeader{Name: "../../../etc/passwd"}
	hdr.Method = zip.Store
	fw2, err := w.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, wErr := fw2.Write([]byte("evil")); wErr != nil {
		t.Fatal(wErr)
	}

	w.Close()
	f.Close()

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), zipPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("extraction tree is nil")
	}
	if tree.Status != StatusExtracted {
		t.Fatalf("root status = %v, want %v", tree.Status, StatusExtracted)
	}

	// We rely on 7-Zip path normalization for traversal-style entry names.
	normalized := filepath.Join(tree.ExtractedDir, "etc", "passwd")
	if _, statErr := os.Stat(normalized); statErr != nil {
		t.Fatalf("normalized path not found at %q: %v", normalized, statErr)
	}

	CleanupNode(tree)
}

func TestExtractZIPFileCountLimitPropagates(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()

	zipPath := createTestZIP(t, dir, "overflow.zip", map[string][]byte{
		"a.txt": []byte("aaa"),
		"b.txt": []byte("bbb"),
		"c.txt": []byte("ccc"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.Limits.MaxFiles = 2

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), zipPath, cfg, sb)
	if tree == nil {
		t.Fatal("tree must not be nil when limit fires")
	}
	if err == nil {
		t.Error("expected ResourceLimitError to propagate from extraction")
	}
	if _, ok := err.(*safeguard.ResourceLimitError); !ok {
		t.Errorf("expected *safeguard.ResourceLimitError, got %T: %v", err, err)
	}
	if tree.Status != StatusFailed {
		t.Errorf("node status = %v, want StatusFailed", tree.Status)
	}
}
