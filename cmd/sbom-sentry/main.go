// Package main provides the CLI entry point for sbom-sentry.
// sbom-sentry is a tool for standardized incoming inspection of software
// deliveries. Given a single delivery file, it produces a consolidated
// CycloneDX SBOM and a formal audit report.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/orchestrator"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(2)
	}
}

func rootCmd() *cobra.Command {
	cfg := config.DefaultConfig()

	var (
		policyStr string
		modeStr   string
		reportStr string
		rootProps []string
	)

	cmd := &cobra.Command{
		Use:   "sbom-sentry [flags] <input-file>",
		Short: "Standardized incoming inspection of software deliveries",
		Long: `sbom-sentry inspects a software delivery file and produces:
  1. A consolidated CycloneDX SBOM
  2. A formal audit report

It recursively extracts nested archives, invokes Syft for component
cataloging, and merges all findings into a single SBOM with full
delivery-path traceability.`,
		Version: version,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cfg.InputPath = args[0]

			// Parse enum flags.
			var err error
			cfg.PolicyMode, err = config.ParsePolicyMode(policyStr)
			if err != nil {
				return err
			}
			cfg.InterpretMode, err = config.ParseInterpretMode(modeStr)
			if err != nil {
				return err
			}
			cfg.ReportMode, err = config.ParseReportMode(reportStr)
			if err != nil {
				return err
			}

			// Parse root properties.
			for _, prop := range rootProps {
				k, v, ok := parseKeyValue(prop)
				if !ok {
					return fmt.Errorf("invalid --root-property format: %q (expected key=value)", prop)
				}
				if cfg.RootMetadata.Properties == nil {
					cfg.RootMetadata.Properties = make(map[string]string)
				}
				cfg.RootMetadata.Properties[k] = v
			}

			// Print unsafe warning.
			if cfg.Unsafe {
				fmt.Fprintln(os.Stderr, "WARNING: --unsafe mode is active. External extraction tools will run WITHOUT sandbox isolation.")
				fmt.Fprintln(os.Stderr, "This mode should only be used in controlled environments or for forensic analysis.")
				fmt.Fprintln(os.Stderr)
			}

			// Set up context with signal handling.
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			// Run the pipeline.
			result := orchestrator.Run(ctx, cfg)
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", result.Error)
			}

			if result.SBOMPath != "" {
				fmt.Fprintf(os.Stderr, "SBOM: %s\n", result.SBOMPath)
			}
			if result.ReportPath != "" {
				fmt.Fprintf(os.Stderr, "Report: %s\n", result.ReportPath)
			}

			os.Exit(int(result.ExitCode))
			return nil
		},
	}

	// CLI flags.
	cmd.Flags().StringVarP(&cfg.OutputDir, "output-dir", "o", ".", "Target directory for SBOM and report output")
	cmd.Flags().StringVar(&cfg.SBOMFormat, "format", "cyclonedx-json", "SBOM output format")
	cmd.Flags().StringVar(&policyStr, "policy", "strict", "Policy mode: strict (abort on limit) or partial (skip and continue)")
	cmd.Flags().StringVar(&modeStr, "mode", "installer-semantic", "Interpretation mode: physical or installer-semantic")
	cmd.Flags().StringVar(&reportStr, "report", "human", "Report output mode: human, machine, or both")
	cmd.Flags().StringVar(&cfg.Language, "language", "en", "Report language: en or de")
	cmd.Flags().StringVar(&cfg.RootMetadata.Manufacturer, "root-manufacturer", "", "Manufacturer/supplier for the SBOM root component")
	cmd.Flags().StringVar(&cfg.RootMetadata.Name, "root-name", "", "Software/product name for the SBOM root component")
	cmd.Flags().StringVar(&cfg.RootMetadata.Version, "root-version", "", "Version for the SBOM root component")
	cmd.Flags().StringVar(&cfg.RootMetadata.DeliveryDate, "root-delivery-date", "", "Delivery date (YYYY-MM-DD) for the SBOM root component")
	cmd.Flags().StringArrayVar(&rootProps, "root-property", nil, "Additional root metadata as key=value (repeatable)")
	cmd.Flags().BoolVar(&cfg.Unsafe, "unsafe", false, "Allow unsandboxed extraction (MUST never be silent)")
	cmd.Flags().IntVar(&cfg.Limits.MaxDepth, "max-depth", cfg.Limits.MaxDepth, "Maximum extraction recursion depth")
	cmd.Flags().IntVar(&cfg.Limits.MaxFiles, "max-files", cfg.Limits.MaxFiles, "Maximum total extracted file count")
	cmd.Flags().Int64Var(&cfg.Limits.MaxTotalSize, "max-size", cfg.Limits.MaxTotalSize, "Maximum total uncompressed size in bytes")
	cmd.Flags().Int64Var(&cfg.Limits.MaxEntrySize, "max-entry-size", cfg.Limits.MaxEntrySize, "Maximum single entry size in bytes")
	cmd.Flags().IntVar(&cfg.Limits.MaxRatio, "max-ratio", cfg.Limits.MaxRatio, "Maximum compression ratio per entry")
	cmd.Flags().DurationVar(&cfg.Limits.Timeout, "timeout", cfg.Limits.Timeout, "Per-extraction timeout")

	return cmd
}

// parseKeyValue splits "key=value" into its parts.
func parseKeyValue(s string) (string, string, bool) {
	idx := -1
	for i, c := range s {
		if c == '=' {
			idx = i
			break
		}
	}
	if idx < 0 || idx == 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
