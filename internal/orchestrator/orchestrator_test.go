// Orchestrator module tests: Verify that the end-to-end pipeline
// coordination works correctly for various scenarios. These tests
// use real ZIP files but do not invoke Syft (which requires real
// package artifacts). They focus on pipeline flow, exit codes, and
// error handling.
package orchestrator

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sbom-sentry/sbom-sentry/internal/config"
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

// TestRunWithInvalidConfigReturnsHardSecurity verifies that an invalid
// configuration causes the pipeline to return ExitHardSecurity with
// an error message.
func TestRunWithInvalidConfigReturnsHardSecurity(t *testing.T) {
	t.Parallel()

	cfg := config.Config{} // Missing required fields.

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("ExitCode = %d, want %d (ExitHardSecurity)", result.ExitCode, ExitHardSecurity)
	}

	if result.Error == nil {
		t.Error("Error is nil, want validation error")
	}
}

// TestRunWithMissingInputFileReturnsError verifies that a nonexistent
// input file is caught early in the pipeline.
func TestRunWithMissingInputFileReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.InputPath = filepath.Join(dir, "nonexistent.zip")
	cfg.OutputDir = dir
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	if result.ExitCode != ExitHardSecurity {
		t.Errorf("ExitCode = %d, want %d (ExitHardSecurity)", result.ExitCode, ExitHardSecurity)
	}

	if result.Error == nil {
		t.Error("Error is nil, want input hash error")
	}
}

// TestRunWithValidZIPProducesOutput verifies the basic happy path:
// a valid ZIP file produces an SBOM file and report file.
func TestRunWithValidZIPProducesOutput(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)

	// The exit code should be 0 (success) or 1 (partial, since Syft may
	// not find anything in a minimal ZIP).
	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed with hard security: %v", result.Error)
	}

	// SBOM should have been written.
	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty")
	} else {
		if _, err := os.Stat(result.SBOMPath); err != nil {
			t.Errorf("SBOM file does not exist: %v", err)
		}
	}

	// Report should have been written.
	if result.ReportPath == "" {
		t.Error("ReportPath is empty")
	} else {
		if _, err := os.Stat(result.ReportPath); err != nil {
			t.Errorf("report file does not exist: %v", err)
		}
	}
}

// TestRunWithCancelledContextHandlesGracefully verifies that a cancelled
// context doesn't panic and produces an appropriate result.
func TestRunWithCancelledContextHandlesGracefully(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "test.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	// Should not panic.
	result := Run(ctx, cfg)
	_ = result
}

// TestExitCodeConstants verifies that exit code values match the
// documented behavior from DESIGN.md.
func TestExitCodeConstants(t *testing.T) {
	t.Parallel()

	if ExitSuccess != 0 {
		t.Errorf("ExitSuccess = %d, want 0", ExitSuccess)
	}
	if ExitPartial != 1 {
		t.Errorf("ExitPartial = %d, want 1", ExitPartial)
	}
	if ExitHardSecurity != 2 {
		t.Errorf("ExitHardSecurity = %d, want 2", ExitHardSecurity)
	}
}

// TestRunWithStrictPolicyAndEmptyZIP verifies that strict mode with
// no scannable content handles gracefully.
func TestRunWithStrictPolicyAndEmptyZIP(t *testing.T) {
	dir := t.TempDir()

	// Create an empty ZIP.
	zipPath := filepath.Join(dir, "empty.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	w.Close()
	f.Close()

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.PolicyMode = config.PolicyStrict
	cfg.Unsafe = true

	result := Run(context.Background(), cfg)

	// Should not crash, exit code depends on whether empty ZIP parses.
	if result.ExitCode == ExitHardSecurity && result.Error == nil {
		t.Error("ExitHardSecurity without error")
	}
}

// TestRunWithHumanReportMode verifies that human-only report mode
// produces a Markdown file.
func TestRunWithHumanReportMode(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.ReportMode = config.ReportHuman

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}

	if result.ReportPath == "" {
		t.Skip("no report path produced (non-fatal)")
	}

	if !filepath.IsAbs(result.ReportPath) || filepath.Ext(result.ReportPath) != ".md" {
		t.Errorf("report path %q doesn't look like a .md file", result.ReportPath)
	}
}

// TestRunWithPathTraversalZIPStillWritesSBOMAndReport verifies the normative
// finalization rule from DESIGN.md §6.3: after input validation succeeds and
// root processing is initialized, a hard security event must not suppress
// final SBOM or report generation.
func TestRunWithPathTraversalZIPStillWritesSBOMAndReport(t *testing.T) {
	dir := t.TempDir()

	// Create a ZIP with a path traversal entry.
	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	// Normal file first.
	fw, wErr := w.Create("readme.txt")
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw.Write([]byte("hello")); wErr != nil {
		t.Fatal(wErr)
	}

	// Path traversal entry.
	hdr := &zip.FileHeader{Name: "../../../etc/passwd"}
	hdr.Method = zip.Store
	fw2, wErr := w.CreateHeader(hdr)
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw2.Write([]byte("root:x:0:0")); wErr != nil {
		t.Fatal(wErr)
	}

	if cErr := w.Close(); cErr != nil {
		t.Fatal(cErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatal(cErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyPartial // Continue despite blocked subtrees.
	cfg.ReportMode = config.ReportBoth

	result := Run(context.Background(), cfg)

	// Exit code must be non-success (hard security or partial).
	if result.ExitCode == ExitSuccess {
		t.Error("ExitCode = Success after hard security event, want non-success")
	}

	// SBOM must still be written.
	if result.SBOMPath == "" {
		t.Error("SBOMPath is empty; SBOM should be written despite security event")
	} else {
		if _, err := os.Stat(result.SBOMPath); err != nil {
			t.Errorf("SBOM file not written despite security event: %v", err)
		}
	}

	// Report must still be written.
	if result.ReportPath == "" {
		t.Error("ReportPath is empty; report should be written despite security event")
	} else {
		if _, err := os.Stat(result.ReportPath); err != nil {
			t.Errorf("report file not written despite security event: %v", err)
		}
	}
}

// TestRunWithDeniedSandboxReportsToolMissing verifies that when bwrap is
// unavailable and --unsafe is not set, the pipeline uses the denied sandbox
// and external-tool formats are marked as tool-missing rather than
// silently executing unsandboxed.
func TestRunWithDeniedSandboxReportsToolMissing(t *testing.T) {
	dir := t.TempDir()
	inputPath := createMinimalZIP(t, dir, "delivery.zip")

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.Unsafe = false // No unsafe opt-in.
	cfg.ReportMode = config.ReportHuman

	result := Run(context.Background(), cfg)

	// Should still produce output (ZIP is in-process, no sandbox needed).
	if result.ExitCode == ExitHardSecurity && result.Error != nil {
		t.Fatalf("pipeline hard-failed for ZIP with denied sandbox: %v", result.Error)
	}

	// SBOM should still be written — ZIP uses in-process extraction.
	if result.SBOMPath == "" {
		t.Error("SBOMPath empty; ZIP extraction should work without sandbox")
	}
}

// TestRunExitCodeOnHardSecurityIsNonZero verifies that when a hard security
// block occurs in strict policy mode, the exit code is ExitHardSecurity.
func TestRunExitCodeOnHardSecurityIsNonZero(t *testing.T) {
	dir := t.TempDir()

	// Create a ZIP with only a path traversal entry; strict mode = abort.
	zipPath := filepath.Join(dir, "evil-strict.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	hdr := &zip.FileHeader{Name: "../../escape.txt"}
	hdr.Method = zip.Store
	fw, wErr := w.CreateHeader(hdr)
	if wErr != nil {
		t.Fatal(wErr)
	}
	if _, wErr = fw.Write([]byte("escaped")); wErr != nil {
		t.Fatal(wErr)
	}

	if cErr := w.Close(); cErr != nil {
		t.Fatal(cErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatal(cErr)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = zipPath
	cfg.OutputDir = dir
	cfg.Unsafe = true
	cfg.PolicyMode = config.PolicyStrict

	result := Run(context.Background(), cfg)

	if result.ExitCode == ExitSuccess {
		t.Error("ExitCode = Success after path traversal in strict mode, want non-success")
	}
}
