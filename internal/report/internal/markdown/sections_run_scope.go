package markdown

import (
	"fmt"
	"io"
)

// writeRunScopeSection renders the "Run & Scope" block directly after the
// Summary so readers immediately know what was analysed, when, and under which
// configuration — without scrolling past the large appendix sections.
//
// Structure:
//
//	## Run & Scope
//	### Input File          (filename, hash, Run ID, timing)
//	### Configuration       (limit settings, generator)
//	### Sandbox             (sandbox status, unsafe override warning)
func writeRunScopeSection(w io.Writer, vm markdownReportViewModel) {
	t := vm.translations
	cfg := vm.report.Config
	sb := vm.report.Runtime.Sandbox

	writeAnchoredHeading(w, 2, t.runScopeSection, anchorRunScope)
	fmt.Fprintln(w, t.runScopeLead)
	fmt.Fprintln(w)

	// Input & run provenance subsection.
	writeAnchoredHeading(w, 3, t.inputSection, anchorInputFile)
	writeInputSection(w, vm.report, t)
	fmt.Fprintln(w)

	// Configuration snapshot subsection.
	writeAnchoredHeading(w, 3, t.configSection, anchorConfig)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, cfg.PolicyMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, cfg.InterpretMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.language, cfg.Language)
	fmt.Fprintf(w, "| grype | %v |\n", cfg.GrypeEnabled)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, cfg.Limits.MaxDepth)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, cfg.Limits.MaxFiles)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, cfg.Limits.MaxTotalSize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, cfg.Limits.MaxEntrySize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, cfg.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, cfg.Limits.Timeout)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(cfg.SkipExtensions))
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, vm.report.Generator.Display)
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, cfg.ProgressLevel)
	fmt.Fprintln(w)

	// Sandbox subsection.
	writeAnchoredHeading(w, 3, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, sb.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, sb.Available)
	if sb.UnsafeOverride {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)
}
