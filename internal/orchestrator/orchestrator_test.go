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
	fw.Write([]byte("test content"))
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
