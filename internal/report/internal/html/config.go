package html

import (
	"fmt"
	"slices"
	"strings"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// The configMarkDefault* helpers mirror the Markdown renderer: a value equal to
// its default is annotated with " (default)" so readers can tell explicitly
// configured values from implicit ones.

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

func configSkipExtensionsDisplay(exts []string, isDefault bool) string {
	s := strings.Join(exts, ", ")
	if isDefault {
		return s + " (default)"
	}
	return s
}

// buildConfigRows assembles the Configuration table, mirroring the Markdown
// renderer's row set, order, and default markers. It takes the whole report so
// it can read the (package-private) config snapshot type via its exported field.
func buildConfigRows(report reportjson.ReportV2, t i18npkg.Bundle) []kv {
	cfg := report.Config
	skipDefault := slices.Equal(cfg.SkipExtensions, configDefaultSkipExtensions)
	return []kv{
		{t.PolicyMode, configMarkDefault(cfg.PolicyMode, configDefaultPolicyMode)},
		{t.InterpretMode, configMarkDefault(cfg.InterpretMode, configDefaultInterpretMode)},
		{t.Language, configMarkDefault(cfg.Language, configDefaultLanguage)},
		{"sbom-format", configMarkDefault(cfg.SBOMFormat, configDefaultSBOMFormat)},
		{"report-selection", configMarkDefault(cfg.ReportSelection, configDefaultReportSelection)},
		{"grype", configMarkDefaultBool(cfg.GrypeEnabled, false)},
		{"unsafe", configMarkDefaultBool(cfg.Unsafe, false)},
		{"parallel-scanners", fmt.Sprintf("%d", cfg.ParallelScanners)},
		{t.MaxDepth, configMarkDefaultInt(cfg.Limits.MaxDepth, configDefaultMaxDepth)},
		{t.MaxFiles, configMarkDefaultInt(cfg.Limits.MaxFiles, configDefaultMaxFiles)},
		{t.MaxTotalSize, configMarkDefaultBytes(cfg.Limits.MaxTotalSize, configDefaultMaxTotalSize, t.UnitBytes)},
		{t.MaxEntrySize, configMarkDefaultBytes(cfg.Limits.MaxEntrySize, configDefaultMaxEntrySize, t.UnitBytes)},
		{t.MaxRatio, configMarkDefaultInt(cfg.Limits.MaxRatio, configDefaultMaxRatio)},
		{t.Timeout, configMarkDefault(cfg.Limits.Timeout, configDefaultTimeout)},
		{t.SkipExtensions, configSkipExtensionsDisplay(cfg.SkipExtensions, skipDefault)},
	}
}
