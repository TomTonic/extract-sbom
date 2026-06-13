package markdown

import (
	"fmt"
	"io"
	"slices"
)

// Default values mirrored from config.DefaultConfig() / config.DefaultLimits().
// Kept here as constants to avoid a cross-package import in the renderer.
const (
	configDefaultPolicyMode      = "partial"
	configDefaultInterpretMode   = "installer-semantic"
	configDefaultLanguage        = "en"
	configDefaultSBOMFormat      = "cyclonedx-json"
	configDefaultReportSelection = "markdown"
	configDefaultMaxDepth        = 6
	configDefaultMaxFiles        = 200000
	configDefaultMaxTotalSize    = int64(20 * 1024 * 1024 * 1024)
	configDefaultMaxEntrySize    = int64(2 * 1024 * 1024 * 1024)
	configDefaultMaxRatio        = 150
	configDefaultTimeout         = "1m0s"
)

// configDefaultSkipExtensions mirrors config.defaultSkipExtensions().
// Order must match exactly for slices.Equal comparison to work.
var configDefaultSkipExtensions = []string{
	".doc", ".dot",
	".xls", ".xlt", ".xla",
	".ppt", ".pot", ".pps", ".ppa",
	".vsd", ".vss", ".vst",
	".msg", ".pub", ".mdb",
	".docx", ".docm", ".dotx", ".dotm",
	".xlsx", ".xlsm", ".xltx", ".xltm",
	".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
	".vsdx", ".vsdm",
	".odt", ".ods", ".odp", ".odg", ".odf",
	".pdf",
}

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
//	### Configuration       (limit settings, output formats, safety flags)
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
	fmt.Fprintf(w, "| sbom-format | %s |\n", configMarkDefault(cfg.SBOMFormat, configDefaultSBOMFormat))
	fmt.Fprintf(w, "| report-selection | %s |\n", configMarkDefault(cfg.ReportSelection, configDefaultReportSelection))
	fmt.Fprintf(w, "| grype | %s |\n", configMarkDefaultBool(cfg.GrypeEnabled, false))
	fmt.Fprintf(w, "| unsafe | %s |\n", configMarkDefaultBool(cfg.Unsafe, false))
	fmt.Fprintf(w, "| parallel-scanners | %d |\n", cfg.ParallelScanners)
	fmt.Fprintf(w, "| %s | %s |\n", t.maxDepth, configMarkDefaultInt(cfg.Limits.MaxDepth, configDefaultMaxDepth))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxFiles, configMarkDefaultInt(cfg.Limits.MaxFiles, configDefaultMaxFiles))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxTotalSize, configMarkDefaultBytes(cfg.Limits.MaxTotalSize, configDefaultMaxTotalSize, t.unitBytes))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxEntrySize, configMarkDefaultBytes(cfg.Limits.MaxEntrySize, configDefaultMaxEntrySize, t.unitBytes))
	fmt.Fprintf(w, "| %s | %s |\n", t.maxRatio, configMarkDefaultInt(cfg.Limits.MaxRatio, configDefaultMaxRatio))
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, configMarkDefault(cfg.Limits.Timeout, configDefaultTimeout))
	skipExtsIsDefault := slices.Equal(cfg.SkipExtensions, configDefaultSkipExtensions)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(cfg.SkipExtensions, skipExtsIsDefault))
	fmt.Fprintln(w)

	// Sandbox subsection.
	//
	// There are three runtime states, distinguished by whether bwrap was found on
	// the host (BwrapFound) and whether --unsafe was passed (UnsafeOverride):
	//
	//   - BwrapFound:                 bwrap is always used when present, so the
	//                                 sandbox was active. --unsafe, if passed, had
	//                                 no effect.
	//   - !BwrapFound && Unsafe:      bwrap unavailable but the run was authorized
	//                                 with --unsafe and completed in passthrough.
	//   - !BwrapFound && !Unsafe:     bwrap unavailable and not overridden; the
	//                                 run could not extract tool-backed formats.
	writeAnchoredHeading(w, 3, t.sandboxSection, anchorSandbox)
	switch {
	case sb.BwrapFound:
		fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
		fmt.Fprintln(w, "|---|---|")
		fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, sb.Name)
		fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, sb.Available)
		fmt.Fprintf(w, "| %s | %s |\n", t.sandboxIsolationLabel, t.sandboxActiveValue)
		fmt.Fprintln(w)
		// When bwrap is available it is always used; a --unsafe flag is ignored.
		// Surface that so the reader is not misled into thinking isolation was off.
		if sb.UnsafeOverride {
			fmt.Fprintf(w, "%s\n\n", t.sandboxUnsafeIgnoredNote)
		}
	case sb.UnsafeOverride:
		fmt.Fprintf(w, "%s\n\n", t.sandboxNoBwrapUnsafe)
	default:
		fmt.Fprintf(w, "%s\n\n", t.sandboxNoBwrapDenied)
	}
}
