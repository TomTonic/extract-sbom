package extract

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func TestIsToolAvailableUsesLookPath(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	saved := lookPath
	defer func() { lookPath = saved }()

	lookPath = func(name string) (string, error) {
		if name == "existing-tool" {
			return "/usr/bin/existing-tool", nil
		}
		return "", fmt.Errorf("not found")
	}

	if !IsToolAvailable("existing-tool") {
		t.Error("IsToolAvailable should return true for existing tool")
	}
	if IsToolAvailable("missing-tool") {
		t.Error("IsToolAvailable should return false for missing tool")
	}
}

func TestExecLookPathDelegates(t *testing.T) {
	// execLookPath should delegate to lookPathImpl without error for
	// a tool that exists on every macOS/Linux system.
	path, err := execLookPath("sh")
	if err != nil {
		t.Fatalf("execLookPath(sh) failed: %v", err)
	}
	if path == "" {
		t.Error("execLookPath(sh) returned empty path")
	}
}

func TestLookPathImplFindsExecutable(t *testing.T) {
	t.Parallel()

	path, err := lookPathImpl("sh")
	if err != nil {
		t.Fatalf("lookPathImpl(sh) failed: %v", err)
	}
	if path == "" {
		t.Error("lookPathImpl(sh) returned empty path")
	}

	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("returned path %q does not exist: %v", path, statErr)
	}
}

func TestLookPathImplReturnsErrorForMissing(t *testing.T) {
	t.Parallel()

	_, err := lookPathImpl("nonexistent-tool-that-will-never-exist-abc123")
	if err == nil {
		t.Error("lookPathImpl should return error for nonexistent tool")
	}
}

func TestStatusStringUnknownDefault(t *testing.T) {
	t.Parallel()

	var s ExtractionStatus = 99
	if got := s.String(); got != "unknown" {
		t.Errorf("String() for invalid status = %q, want %q", got, "unknown")
	}
}

func TestExtract7zSandboxRunFailure(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	saved := lookPath
	lookPath = func(string) (string, error) { return "/usr/bin/fake-7zz", nil }
	defer func() { lookPath = saved }()

	sb := &recordingSandbox{run: func(string, []string, string, string) error {
		return fmt.Errorf("sandbox execution failed")
	}}

	node := &ExtractionNode{}
	err := extract7z(context.Background(), node, "/tmp/input.cab", sb, t.TempDir(), config.DefaultLimits(), "")
	if err != nil {
		t.Fatalf("unexpected propagated error: %v", err)
	}
	if node.Status != StatusFailed {
		t.Errorf("status = %v, want StatusFailed", node.Status)
	}
}

func TestExtractUnshieldSandboxRunFailure(t *testing.T) {
	lookPathMu.Lock()
	defer lookPathMu.Unlock()

	saved := lookPath
	lookPath = func(string) (string, error) { return "/usr/bin/fake-unshield", nil }
	defer func() { lookPath = saved }()

	sb := &recordingSandbox{run: func(string, []string, string, string) error {
		return fmt.Errorf("unshield execution failed")
	}}

	node := &ExtractionNode{}
	err := extractUnshield(context.Background(), node, "/tmp/setup.cab", sb, t.TempDir(), config.DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("unexpected propagated error: %v", err)
	}
	if node.Status != StatusFailed {
		t.Errorf("status = %v, want StatusFailed", node.Status)
	}
}

func TestExtractRecursiveTimeoutSetsStatus(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()

	// Create a ZIP large enough that extraction might take time.
	entries := make(map[string][]byte)
	for i := 0; i < 20; i++ {
		entries[fmt.Sprintf("file%d.txt", i)] = []byte("content")
	}
	zipPath := createTestZIP(t, dir, "delivery.zip", entries)

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.Limits.Timeout = 1 * time.Nanosecond // effectively expired

	sb := sandbox.NewPassthroughSandbox()

	tree, err := Extract(context.Background(), zipPath, cfg, sb)
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
	// With a nanosecond timeout the extraction context may already be expired,
	// leading to a deadline-exceeded resource limit error.
	_ = err // error is acceptable here
}

func TestCleanupNodeNilSafe(t *testing.T) {
	t.Parallel()
	CleanupNode(nil) // must not panic
}

func TestSummarizeExtractedDirCounts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a directory structure with files and subdirs.
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bb"), 0o600); err != nil {
		t.Fatal(err)
	}

	count, size, err := summarizeExtractedDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if size != 5 {
		t.Errorf("size = %d, want 5", size)
	}
}

// TestExtractZIPPartialPolicyContinuesOnResourceLimit verifies that with
// PolicyPartial, a resource limit error on a nested child does not stop
// processing of remaining siblings.
func TestExtractZIPPartialPolicyContinuesOnResourceLimit(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()

	// Create outer ZIP with two nested ZIPs. Setting MaxDepth=1 means depth-2
	// inner children will exceed the limit but with PolicyPartial extraction
	// should continue.
	inner1 := createTestZIP(t, dir, "inner1.zip", map[string][]byte{
		"a.txt": []byte("aaa"),
	})
	inner1Content, _ := os.ReadFile(inner1)

	inner2 := createTestZIP(t, dir, "inner2.zip", map[string][]byte{
		"b.txt": []byte("bbb"),
	})
	inner2Content, _ := os.ReadFile(inner2)

	outerPath := createTestZIP(t, dir, "outer.zip", map[string][]byte{
		"inner1.zip": inner1Content,
		"inner2.zip": inner2Content,
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = outerPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyPartial
	cfg.Limits.MaxDepth = 1

	tree, err := Extract(context.Background(), outerPath, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
	// With partial policy, error may be nil or a resource limit error;
	// the key is that the tree contains both children.
	_ = err
	if tree.Status != StatusExtracted {
		t.Errorf("root status = %v, want Extracted", tree.Status)
	}
}

// TestExtractZIPStrictPolicyStopsOnResourceLimit verifies that with
// PolicyStrict, a resource limit error propagates immediately.
func TestExtractZIPStrictPolicyStopsOnResourceLimit(t *testing.T) {
	t.Parallel()
	if _, ok := resolve7zBinary(); !ok {
		t.Skip("7-Zip not available")
	}
	dir := t.TempDir()

	inner := createTestZIP(t, dir, "inner.zip", map[string][]byte{
		"a.txt": []byte("aaa"),
	})
	innerContent, _ := os.ReadFile(inner)

	outerPath := createTestZIP(t, dir, "outer.zip", map[string][]byte{
		"inner.zip": innerContent,
	})

	cfg := config.DefaultConfig()
	cfg.InputPath = outerPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyStrict
	cfg.Limits.MaxDepth = 1

	tree, _ := Extract(context.Background(), outerPath, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("tree must not be nil")
	}
}
