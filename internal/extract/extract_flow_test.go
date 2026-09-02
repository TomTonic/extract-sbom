package extract

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestExtractNestedZIPInZIPRecursesCorrectly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	innerPath := createTestZIP(t, dir, "inner.zip", map[string][]byte{
		"inner-file.txt": []byte("inner content"),
	})
	innerContent, err := os.ReadFile(innerPath)
	if err != nil {
		t.Fatal(err)
	}

	outerPath := createTestZIP(t, dir, "outer.zip", map[string][]byte{
		"inner.zip": innerContent,
		"readme.md": []byte("# Outer readme"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = outerPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), outerPath, cfg, sb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want Extracted", tree.Status)
	}

	if len(tree.Children) == 0 {
		t.Fatal("expected at least one child node for nested ZIP")
	}

	foundInner := false
	for _, child := range tree.Children {
		if filepath.Base(child.Path) == "inner.zip" {
			foundInner = true
			if child.Status != StatusExtracted {
				t.Errorf("inner ZIP status = %v, want Extracted", child.Status)
			}
		}
	}

	if !foundInner {
		t.Error("inner.zip child node not found")
	}

	CleanupNode(tree)
}

func TestExtractRespectsDepthLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	zipPath := createTestZIP(t, dir, "test.zip", map[string][]byte{
		"file.txt": []byte("content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.Limits.MaxDepth = 0

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), zipPath, cfg, sb)
	if tree == nil {
		t.Fatal("tree should not be nil even when depth is exceeded")
	}

	if err != nil {
		resourceLimitError := &safeguard.ResourceLimitError{}
		if !errors.As(err, &resourceLimitError) {
			t.Errorf("expected ResourceLimitError, got %T: %v", err, err)
		}
	}

	if tree.Status == StatusPending {
		t.Error("root node should not remain in pending status after extraction")
	}
}

func TestExtractHandlesContextCancellation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	zipPath := createTestZIP(t, dir, "test.zip", map[string][]byte{
		"file.txt": []byte("content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(ctx, zipPath, cfg, sb)
	if tree == nil {
		t.Fatal("tree should not be nil even with cancelled context")
	}
	if err == nil && tree.Status == StatusExtracted {
		t.Log("extraction completed despite cancelled context (timing-dependent, acceptable)")
	}
}

func TestExtensionFilterSkipsDocumentFormats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	oleHeader := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	xlsContent := make([]byte, 300)
	copy(xlsContent, oleHeader)

	zipPath := createTestZIP(t, dir, "delivery.zip", map[string][]byte{
		"DataModel_de.xls": xlsContent,
		"readme.txt":       []byte("Hello"),
		"document.xlsx":    []byte("fake xlsx content"),
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.SkipExtensions = []string{".xls", ".xlsx"}

	tree, err := Extract(context.Background(), zipPath, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil")
	}

	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want StatusExtracted", tree.Status)
	}

	var checkNoFailed func(n *ExtractionNode)
	checkNoFailed = func(n *ExtractionNode) {
		if n.Status == StatusFailed {
			t.Errorf("node %q has StatusFailed (StatusDetail=%q)", n.Path, n.StatusDetail)
		}
		for _, c := range n.Children {
			checkNoFailed(c)
		}
	}
	checkNoFailed(tree)

	CleanupNode(tree)
}

func TestIsSkippedExtension(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		skipList []string
		want     bool
	}{
		{"/path/file.xls", []string{".xls", ".xlsx"}, true},
		{"/path/file.XLS", []string{".xls", ".xlsx"}, true},
		{"/path/file.XLSX", []string{".xls", ".xlsx"}, true},
		{"/path/file.msi", []string{".xls", ".xlsx"}, false},
		{"/path/file.msi", []string{}, false},
		{"/path/file", []string{".xls"}, false},
		{"/path/file.xls", []string{".XLS"}, true},
	}

	for _, tt := range tests {
		got := isSkippedExtension(tt.path, tt.skipList)
		if got != tt.want {
			t.Errorf("isSkippedExtension(%q, %v) = %v, want %v", tt.path, tt.skipList, got, tt.want)
		}
	}
}

func TestExtractionNodeStatusStringReturnsReadableNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status ExtractionStatus
		want   string
	}{
		{StatusPending, "pending"},
		{StatusSyftNative, "syft-native"},
		{StatusExtracted, "extracted"},
		{StatusSkipped, "skipped"},
		{StatusFailed, "failed"},
		{StatusSecurityBlocked, "security-blocked"},
		{StatusToolMissing, "tool-missing"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCleanupNodeRemovesTemporaryDirectories(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	childDir, err := os.MkdirTemp(tmpDir, "child-*")
	if err != nil {
		t.Fatal(err)
	}

	node := &ExtractionNode{
		ExtractedDir: tmpDir,
		Children: []*ExtractionNode{
			{ExtractedDir: childDir},
		},
	}

	if err := os.WriteFile(filepath.Join(childDir, "test.txt"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	CleanupNode(node)

	if _, err := os.Stat(childDir); err == nil {
		t.Error("child temp dir still exists after cleanup")
	}
}

// TestExtractClassifiesSecurityViolationAsSecurityBlocked is a regression
// test for extractRecursive's security-error classification: it must use
// errors.As (not a raw type assertion) to recognize a *safeguard.HardSecurityError
// returned by the extraction pipeline, so that node.Status becomes
// StatusSecurityBlocked rather than being downgraded to a generic StatusFailed.
// A raw type assertion silently breaks this classification the moment the
// error gets wrapped anywhere between safeguard and extractRecursive.
func TestExtractClassifiesSecurityViolationAsSecurityBlocked(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	originalLookPath := lookPath
	lookPath = func(string) (string, error) {
		return "/usr/bin/fake-7zz", nil
	}
	t.Cleanup(func() { lookPath = originalLookPath })

	dir := t.TempDir()
	archivePath := createTestZIP(t, dir, "evil.zip", map[string][]byte{
		"payload.txt": []byte("payload"),
	})

	// Simulate 7-Zip producing a symlink that escapes the extraction
	// directory; safeguard.ValidatePostExtraction rejects this as a hard
	// security violation.
	sb := &recordingSandbox{run: func(_ string, _ []string, _ string, outputDir string) error {
		return os.Symlink("/etc/passwd", filepath.Join(outputDir, "escape-link"))
	}}

	cfg := config.DefaultConfig()
	cfg.InputPath = archivePath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	tree, err := Extract(context.Background(), archivePath, cfg, sb)
	if err == nil {
		t.Fatal("expected a security error to propagate from Extract")
	}

	hardSecurityError := &safeguard.HardSecurityError{}
	if !errors.As(err, &hardSecurityError) {
		t.Fatalf("error = %T, want *safeguard.HardSecurityError", err)
	}

	if tree.Status != StatusSecurityBlocked {
		t.Errorf("tree.Status = %v, want %v (detail: %s)", tree.Status, StatusSecurityBlocked, tree.StatusDetail)
	}
}

// TestFlattenCompressedTARIsBestEffortOnReadDirFailure locks in the
// intentional behavior behind flattenCompressedTAR's //nolint:nilerr: when
// the extracted directory cannot be read, flattening is silently skipped and
// the outer extraction result is kept as-is (nil error), rather than failing
// the whole extraction over a cosmetic path-flattening step.
func TestFlattenCompressedTARIsBestEffortOnReadDirFailure(t *testing.T) {
	t.Parallel()

	node := &ExtractionNode{
		ExtractedDir: filepath.Join(t.TempDir(), "does-not-exist"),
		Status:       StatusExtracted,
		EntriesCount: 3,
		TotalSize:    123,
	}

	err := flattenCompressedTAR(context.Background(), node, sandbox.NewPassthroughSandbox(), config.DefaultConfig())
	if err != nil {
		t.Fatalf("flattenCompressedTAR() = %v, want nil (best-effort)", err)
	}
	if node.EntriesCount != 3 || node.TotalSize != 123 {
		t.Errorf("node was mutated on ReadDir failure: entries=%d total=%d", node.EntriesCount, node.TotalSize)
	}
}

// TestFlattenCompressedTARSkipsWhenNotSingleTarFile verifies flattening is
// skipped (nil error, node unchanged) whenever the extracted directory does
// not contain exactly one .tar file — multiple entries, a directory entry,
// or a single non-.tar file all leave the outer result untouched.
func TestFlattenCompressedTARSkipsWhenNotSingleTarFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"multiple entries", func(t *testing.T, dir string) {
			t.Helper()
			mustWriteFile(t, filepath.Join(dir, "a.tar"), "a")
			mustWriteFile(t, filepath.Join(dir, "b.tar"), "b")
		}},
		{"single directory entry", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750); err != nil {
				t.Fatal(err)
			}
		}},
		{"single non-tar file", func(t *testing.T, dir string) {
			t.Helper()
			mustWriteFile(t, filepath.Join(dir, "readme.txt"), "not a tar")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			extractedDir := t.TempDir()
			tt.setup(t, extractedDir)

			node := &ExtractionNode{ExtractedDir: extractedDir, Status: StatusExtracted, EntriesCount: 7}

			err := flattenCompressedTAR(context.Background(), node, sandbox.NewPassthroughSandbox(), config.DefaultConfig())
			if err != nil {
				t.Fatalf("flattenCompressedTAR() = %v, want nil", err)
			}
			if node.ExtractedDir != extractedDir {
				t.Errorf("ExtractedDir changed to %q, want unchanged %q", node.ExtractedDir, extractedDir)
			}
			if node.EntriesCount != 7 {
				t.Errorf("EntriesCount = %d, want unchanged 7", node.EntriesCount)
			}
		})
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
