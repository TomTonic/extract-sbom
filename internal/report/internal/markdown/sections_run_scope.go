package markdown

import (
	"fmt"
	"io"
)

// Default values mirrored from config.DefaultConfig() / config.DefaultLimits().
// Kept here as constants to avoid a cross-package import in the renderer.
const (
	configDefaultPolicyMode    = "strict"
	configDefaultInterpretMode = "installer-semantic"
	configDefaultLanguage      = "en"
	configDefaultMaxDepth      = 6
	configDefaultMaxFiles      = 200000
	configDefaultMaxTotalSize  = int64(20 * 1024 * 1024 * 1024)
	configDefaultMaxEntrySize  = int64(2 * 1024 * 1024 * 1024)
	configDefaultMaxRatio      = 150
	configDefaultTimeout       = "1m0s"
)

func configMarkDefault(val, def string) string {
	if val == def {
		return val + " (default)"
	}
	return val
}

func configMarkDefaultBool(val, def bool) string {
	s := fmt.Sprintf("%v", val)
	if val == def {
		return s + " (default)"
	}
	return s
}

func configMarkDefaultInt(val, def int) string {
	if val == def {
		return fmt.Sprintf("%d (default)", val)
	}
	return fmt.Sprintf("%d", val)
}

func configMarkDefaultBytes(val, def int64, unit string) string {
	if val == def {
		return fmt.Sprintf("%d %s (default)", val, unit)
	}
	return fmt.Sprintf("%d %s", val, unit)
}

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
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, configMarkDefault(cfg.PolicyMode, configDefaultPolicyMode))
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, configMarkDefault(cfg.InterpretMode, configDefaultInterpretMode))
	fmt.Fprintf(w, "| %s | %s |\n", t.language, configMarkDefault(cfg.Language, configDefaultLanguage))
	fmt.Fprintf(w, "| grype | %s |\n", configMarkDefaultBool(cfg.GrypeEnabled, false))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxDepth, configMarkDefaultInt(cfg.Limits.MaxDepth, configDefaultMaxDepth))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxFiles, configMarkDefaultInt(cfg.Limits.MaxFiles, configDefaultMaxFiles))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxTotalSize, configMarkDefaultBytes(cfg.Limits.MaxTotalSize, configDefaultMaxTotalSize, t.unitBytes))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxEntrySize, configMarkDefaultBytes(cfg.Limits.MaxEntrySize, configDefaultMaxEntrySize, t.unitBytes))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxRatio, configMarkDefaultInt(cfg.Limits.MaxRatio, configDefaultMaxRatio))
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, configMarkDefault(cfg.Limits.Timeout, configDefaultTimeout))
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(cfg.SkipExtensions))
	fmt.Fprintln(w)

	// Sandbox subsection.
	writeAnchoredHeading(w, 3, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, sb.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, sb.Available)
	// Only warn when bwrap was actually present on this system but explicitly
	// bypassed via --unsafe. On platforms where bwrap is not available (macOS)
	// passthrough is the only mode and the WARNING would be misleading.
	if sb.UnsafeOverride && sb.BwrapFound {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)
}
