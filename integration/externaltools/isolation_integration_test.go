package externaltools_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

func writeExecutable(t *testing.T, dir, name, scriptBody string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := "#!/bin/sh\nset -eu\n" + scriptBody + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write executable %s: %v", name, err)
	}
	// #nosec G302 -- test helper must be executable to mimic runtime tool invocation.
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatalf("chmod executable %s: %v", name, err)
	}
}

func prependPath(t *testing.T, dir string) {
	t.Helper()
	orig := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+orig)
}

func createCABInput(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "input.cab")
	content := []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write CAB input: %v", err)
	}
	return path
}

func createInstallShieldInput(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "data1.cab")
	content := []byte{'I', 'S', 'c', '(', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write InstallShield input: %v", err)
	}
	return path
}

func baseConfig(inputPath, outputDir string) config.Config {
	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = outputDir
	cfg.Unsafe = true
	return cfg
}

// Test7zzIntegrationMaxFilesLimit verifies that an externally extracted CAB
// subtree is blocked when the fake 7zz tool materializes too many files.
func Test7zzIntegrationMaxFilesLimit(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
[ "$1" = "x" ] || exit 41
outarg="$3"
case "$outarg" in
  -o*) outdir="${outarg#-o}" ;;
  *) exit 42 ;;
esac
mkdir -p "$outdir"
printf x > "$outdir/a.txt"
printf x > "$outdir/b.txt"
printf x > "$outdir/c.txt"
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)
	cfg.Limits.MaxFiles = 2

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("expected extraction tree")
	}

	var rle *safeguard.ResourceLimitError
	if !errors.As(err, &rle) || rle.Limit != "max-files" {
		t.Fatalf("expected max-files resource limit error, got: %v", err)
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
}

// Test7zzIntegrationMaxEntrySizeLimit verifies enforcement of max-entry-size
// for outputs created by external extractors.
func Test7zzIntegrationMaxEntrySizeLimit(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
[ "$1" = "x" ] || exit 51
outarg="$3"
case "$outarg" in
  -o*) outdir="${outarg#-o}" ;;
  *) exit 52 ;;
esac
mkdir -p "$outdir"
printf 12345 > "$outdir/large.bin"
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)
	cfg.Limits.MaxEntrySize = 4

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("expected extraction tree")
	}

	var rle *safeguard.ResourceLimitError
	if !errors.As(err, &rle) || rle.Limit != "max-entry-size" {
		t.Fatalf("expected max-entry-size resource limit error, got: %v", err)
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
}

// Test7zzIntegrationSymlinkBlocked verifies hard security enforcement for
// symlink materialization in external extraction output.
func Test7zzIntegrationSymlinkBlocked(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
[ "$1" = "x" ] || exit 61
outarg="$3"
case "$outarg" in
  -o*) outdir="${outarg#-o}" ;;
  *) exit 62 ;;
esac
mkdir -p "$outdir"
ln -s /etc/passwd "$outdir/escape-link"
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("expected extraction tree")
	}

	var hse *safeguard.HardSecurityError
	if !errors.As(err, &hse) || hse.Violation != "symlink" {
		t.Fatalf("expected symlink hard security error, got: %v", err)
	}
	if tree.Status != extract.StatusSecurityBlocked {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusSecurityBlocked)
	}
}

// Test7zzIntegrationSpecialFileBlocked verifies hard security enforcement for
// special-file materialization (named pipe) in external extraction output.
func Test7zzIntegrationSpecialFileBlocked(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
[ "$1" = "x" ] || exit 71
outarg="$3"
case "$outarg" in
  -o*) outdir="${outarg#-o}" ;;
  *) exit 72 ;;
esac
mkdir -p "$outdir"
mkfifo "$outdir/pipe"
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("expected extraction tree")
	}

	var hse *safeguard.HardSecurityError
	if !errors.As(err, &hse) || hse.Violation != "special-file" {
		t.Fatalf("expected special-file hard security error, got: %v", err)
	}
	if tree.Status != extract.StatusSecurityBlocked {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusSecurityBlocked)
	}
}

// Test7zzIntegrationToolMissingRecorded verifies the runtime behavior when 7zz
// is not present: extraction is recorded as tool-missing, not fatal.
func Test7zzIntegrationToolMissingRecorded(t *testing.T) {
	dir := t.TempDir()
	pathOnlyDir := filepath.Join(dir, "empty-path")
	if err := os.MkdirAll(pathOnlyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathOnlyDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Status != extract.StatusToolMissing {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusToolMissing)
	}
	if tree.Tool != "7zz" {
		t.Fatalf("tool = %q, want %q", tree.Tool, "7zz")
	}
}

// TestIsolationDeniedSandboxIsDetectable verifies that isolation denial is
// explicit and visible when external extraction is attempted without a usable
// sandbox backend.
func TestIsolationDeniedSandboxIsDetectable(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
[ "$1" = "x" ] || exit 81
outarg="$3"
outdir="${outarg#-o}"
mkdir -p "$outdir"
printf ok > "$outdir/file.txt"
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)
	cfg.Unsafe = false

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewDeniedSandbox())
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
	if !strings.Contains(tree.StatusDetail, "--unsafe") {
		t.Fatalf("status detail = %q, want mention of --unsafe opt-in", tree.StatusDetail)
	}
}

// TestUnshieldIntegrationCLIAndSuccess verifies that the unshield invocation
// matches runtime CLI expectations (-d DIR x CABFILE) and extraction succeeds.
func TestUnshieldIntegrationCLIAndSuccess(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "unshield", `
[ "$1" = "-d" ] || exit 91
outdir="$2"
[ "$3" = "x" ] || exit 92
infile="$4"
[ -f "$infile" ] || exit 93
mkdir -p "$outdir/subdir"
printf ok > "$outdir/subdir/result.bin"
`)
	prependPath(t, binDir)

	input := createInstallShieldInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Status != extract.StatusExtracted {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusExtracted)
	}
	if tree.Tool != "unshield" {
		t.Fatalf("tool = %q, want %q", tree.Tool, "unshield")
	}
	if tree.EntriesCount != 1 {
		t.Fatalf("entries = %d, want 1", tree.EntriesCount)
	}
}

// TestUnshieldIntegrationSymlinkBlocked verifies hard security enforcement for
// InstallShield extraction outputs.
func TestUnshieldIntegrationSymlinkBlocked(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "unshield", `
[ "$1" = "-d" ] || exit 101
outdir="$2"
[ "$3" = "x" ] || exit 102
mkdir -p "$outdir"
ln -s /etc/passwd "$outdir/link"
`)
	prependPath(t, binDir)

	input := createInstallShieldInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("expected extraction tree")
	}

	var hse *safeguard.HardSecurityError
	if !errors.As(err, &hse) || hse.Violation != "symlink" {
		t.Fatalf("expected symlink hard security error, got: %v", err)
	}
	if tree.Status != extract.StatusSecurityBlocked {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusSecurityBlocked)
	}
}

// TestUnshieldIntegrationMaxTotalSizeLimit verifies resource-limit enforcement
// on total extracted size for InstallShield external extraction.
func TestUnshieldIntegrationMaxTotalSizeLimit(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "unshield", `
[ "$1" = "-d" ] || exit 111
outdir="$2"
[ "$3" = "x" ] || exit 112
mkdir -p "$outdir"
printf 12345 > "$outdir/a.bin"
printf 12345 > "$outdir/b.bin"
`)
	prependPath(t, binDir)

	input := createInstallShieldInput(t, dir)
	cfg := baseConfig(input, dir)
	cfg.Limits.MaxTotalSize = 8

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if tree == nil {
		t.Fatal("expected extraction tree")
	}

	var rle *safeguard.ResourceLimitError
	if !errors.As(err, &rle) || rle.Limit != "max-total-size" {
		t.Fatalf("expected max-total-size resource limit error, got: %v", err)
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
}

// TestExternalToolCLIContractValidation verifies that malformed fake tool
// invocation is surfaced as extraction failure and recorded with status detail.
func TestExternalToolCLIContractValidation(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
echo "unexpected args: $*" >&2
exit 64
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
	if !strings.Contains(tree.StatusDetail, "7zz extraction failed") {
		t.Fatalf("status detail = %q, want extraction failure marker", tree.StatusDetail)
	}
	if !strings.Contains(tree.StatusDetail, "unexpected args") {
		t.Fatalf("status detail = %q, want propagated stderr detail", tree.StatusDetail)
	}
}

// TestExternalToolHardCrashIsRecorded verifies that a hard crash of an
// external extractor process (simulated by SIGKILL) is surfaced as an
// extraction failure with diagnostic context in StatusDetail.
func TestExternalToolHardCrashIsRecorded(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeExecutable(t, binDir, "7zz", `
echo "intentional crash" >&2
kill -9 $$
`)
	prependPath(t, binDir)

	input := createCABInput(t, dir)
	cfg := baseConfig(input, dir)

	tree, err := extract.Extract(context.Background(), input, cfg, sandbox.NewPassthroughSandbox())
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if tree.Status != extract.StatusFailed {
		t.Fatalf("status = %v, want %v", tree.Status, extract.StatusFailed)
	}
	if !strings.Contains(tree.StatusDetail, "7zz extraction failed") {
		t.Fatalf("status detail = %q, want extraction failure marker", tree.StatusDetail)
	}
	if !strings.Contains(tree.StatusDetail, "intentional crash") {
		t.Fatalf("status detail = %q, want stderr crash marker", tree.StatusDetail)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if code != 0 {
		fmt.Fprintf(os.Stderr, "integration externaltools suite failed with code %d\n", code)
	}
	os.Exit(code)
}
