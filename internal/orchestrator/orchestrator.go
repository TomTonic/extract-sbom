// Package orchestrator coordinates the end-to-end processing pipeline of
// sbom-sentry. It validates configuration, computes input hashes, resolves
// the sandbox, performs extraction, scanning, SBOM assembly, and report
// generation in sequence. It owns the lifecycle of temporary directories
// and produces deterministic exit codes.
package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sbom-sentry/sbom-sentry/internal/assembly"
	"github.com/sbom-sentry/sbom-sentry/internal/config"
	"github.com/sbom-sentry/sbom-sentry/internal/extract"
	"github.com/sbom-sentry/sbom-sentry/internal/policy"
	"github.com/sbom-sentry/sbom-sentry/internal/report"
	"github.com/sbom-sentry/sbom-sentry/internal/sandbox"
	"github.com/sbom-sentry/sbom-sentry/internal/scan"
)

// ExitCode represents the process exit status.
type ExitCode int

const (
	// ExitSuccess indicates all subtrees were fully processed.
	ExitSuccess ExitCode = 0
	// ExitPartial indicates some subtrees were skipped or incomplete.
	ExitPartial ExitCode = 1
	// ExitHardSecurity indicates a hard security incident or fatal runtime failure.
	ExitHardSecurity ExitCode = 2
)

// Result holds the outcome of a complete sbom-sentry run.
type Result struct {
	ExitCode   ExitCode
	SBOMPath   string
	ReportPath string
	Error      error
}

// Run executes the complete sbom-sentry processing pipeline.
// It validates configuration, computes input hashes, resolves the sandbox,
// extracts archives recursively, invokes Syft for SBOM generation, assembles
// the consolidated SBOM, and generates the audit report.
//
// The pipeline is designed to always produce output when possible: even if
// hard security events occur after initialization, the SBOM and report are
// still written with affected subtrees marked incomplete.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - cfg: the validated run configuration
//
// Returns a Result containing the exit code, output paths, and any fatal error.
func Run(ctx context.Context, cfg config.Config) Result {
	startTime := time.Now()

	// Step 1: Validate configuration.
	if err := cfg.Validate(); err != nil {
		return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("configuration: %w", err)}
	}

	// Step 2: Compute input file hashes.
	inputSummary, err := report.ComputeInputSummary(cfg.InputPath)
	if err != nil {
		return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("input hash: %w", err)}
	}

	// Step 3: Resolve sandbox.
	sb := sandbox.Resolve(cfg)
	sandboxInfo := report.SandboxSummary{
		UnsafeOvr: cfg.Unsafe,
		Name:      sb.Name(),
		Available: sb.Available(),
	}

	// Step 4: Extract.
	policyEngine := policy.NewEngine(cfg.PolicyMode)

	tree, extractErr := extract.Extract(ctx, cfg.InputPath, cfg, sb)
	if extractErr != nil {
		// Record the policy decision.
		decision := policyEngine.Evaluate(policy.Violation{
			Type:     "extraction",
			NodePath: filepath.Base(cfg.InputPath),
			Error:    extractErr,
		})

		if decision.Action == policy.ActionAbort && tree == nil {
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("extraction: %w", extractErr)}
		}
	}

	// Step 5: Scan with Syft.
	var scans []scan.ScanResult
	if tree != nil {
		scans, err = scan.ScanAll(ctx, tree, cfg)
		if err != nil {
			// Non-fatal: proceed with whatever we have.
			policyEngine.Evaluate(policy.Violation{
				Type:     "scan",
				NodePath: "root",
				Error:    err,
			})
		}
	}

	// Step 6: Assemble SBOM.
	var sbomPath string
	if tree != nil {
		bom, asmErr := assembly.Assemble(tree, scans, cfg)
		if asmErr != nil {
			policyEngine.Evaluate(policy.Violation{
				Type:     "assembly",
				NodePath: "root",
				Error:    asmErr,
			})
		} else {
			// Write SBOM.
			inputBase := strings.TrimSuffix(filepath.Base(cfg.InputPath), filepath.Ext(cfg.InputPath))
			sbomPath = filepath.Join(cfg.OutputDir, inputBase+".cdx.json")
			if writeErr := assembly.WriteSBOM(bom, sbomPath); writeErr != nil {
				return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("write SBOM: %w", writeErr)}
			}
		}
	}

	// Step 7: Generate report.
	endTime := time.Now()
	reportData := report.ReportData{
		Input:           inputSummary,
		Config:          cfg,
		Tree:            tree,
		Scans:           scans,
		PolicyDecisions: policyEngine.Decisions(),
		SandboxInfo:     sandboxInfo,
		StartTime:       startTime,
		EndTime:         endTime,
		SBOMPath:        sbomPath,
	}

	inputBase := strings.TrimSuffix(filepath.Base(cfg.InputPath), filepath.Ext(cfg.InputPath))
	var reportPath string

	switch cfg.ReportMode {
	case config.ReportHuman, config.ReportBoth:
		reportPath = filepath.Join(cfg.OutputDir, inputBase+".report.md")
		f, ferr := os.Create(reportPath)
		if ferr != nil {
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("create report: %w", ferr)}
		}
		if werr := report.GenerateHuman(reportData, cfg.Language, f); werr != nil {
			_ = f.Close()
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("write report: %w", werr)}
		}
		if cerr := f.Close(); cerr != nil {
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("close report: %w", cerr)}
		}
	}

	switch cfg.ReportMode {
	case config.ReportMachine, config.ReportBoth:
		jsonPath := filepath.Join(cfg.OutputDir, inputBase+".report.json")
		f, ferr := os.Create(jsonPath)
		if ferr != nil {
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("create JSON report: %w", ferr)}
		}
		if werr := report.GenerateMachine(reportData, f); werr != nil {
			_ = f.Close()
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("write JSON report: %w", werr)}
		}
		if cerr := f.Close(); cerr != nil {
			return Result{ExitCode: ExitHardSecurity, Error: fmt.Errorf("close JSON report: %w", cerr)}
		}
		if reportPath == "" {
			reportPath = jsonPath
		}
	}

	// Step 8: Clean up temporary directories.
	if tree != nil {
		extract.CleanupNode(tree)
	}

	// Step 9: Determine exit code.
	exitCode := ExitSuccess
	if policyEngine.HasHardSecurityIncident() {
		exitCode = ExitHardSecurity
	} else if policyEngine.HasSkip() || policyEngine.HasAbort() {
		exitCode = ExitPartial
	}

	return Result{
		ExitCode:   exitCode,
		SBOMPath:   sbomPath,
		ReportPath: reportPath,
	}
}
