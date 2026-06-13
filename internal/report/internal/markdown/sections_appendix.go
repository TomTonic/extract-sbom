package markdown

import (
	"fmt"
	"io"
	"sort"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func writeRootMetadata(w io.Writer, root *reportjson.BOMRootComponentV2, t translations) {
	fmt.Fprintln(w, "### Root Component Metadata")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "| %s | %s | %s |\n", t.Field, t.Value, t.Source)
	fmt.Fprintln(w, "|---|---|---|")

	if root == nil {
		return
	}
	if root.BOMRef != "" {
		fmt.Fprintf(w, "| %s | %s | %s |\n", t.ObjectID, escapeMarkdownCell(root.BOMRef), escapeMarkdownCell(t.Derived))
	}
	if root.Name != "" {
		fmt.Fprintf(w, "| %s | %s | %s |\n", t.PackageName, escapeMarkdownCell(root.Name), escapeMarkdownCell(t.Derived))
	}
	if root.Version != "" {
		fmt.Fprintf(w, "| %s | %s | %s |\n", t.Version, escapeMarkdownCell(root.Version), escapeMarkdownCell(t.Derived))
	}
	if len(root.ConfigProperties) > 0 {
		keys := make([]string, 0, len(root.ConfigProperties))
		for k := range root.ConfigProperties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "| %s | %s | %s |\n", escapeMarkdownCell(k), escapeMarkdownCell(root.ConfigProperties[k]), escapeMarkdownCell(t.SuppliedBy))
		}
	}
	fmt.Fprintln(w)
}

// writeInputSection renders the input fingerprint together with the run
// provenance (run id, start/end timestamps, duration) so an auditor can verify
// when, and against which artifact, the report was produced.
func writeInputSection(w io.Writer, report reportjson.ReportV2, t translations) {
	inp := report.Input
	run := report.Run

	fmt.Fprintf(w, "| %s | %s |\n", t.Field, t.Value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.Filename, inp.Filename)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.Filesize, inp.Size, t.UnitBytes)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", inp.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", inp.SHA512)
	if run.RunID != "" {
		fmt.Fprintf(w, "| %s | `%s` |\n", t.RunIDLabel, run.RunID)
	}
	if run.StartTime != "" {
		fmt.Fprintf(w, "| %s | %s |\n", t.RunStartedLabel, run.StartTime)
	}
	if run.EndTime != "" {
		fmt.Fprintf(w, "| %s | %s |\n", t.RunEndedLabel, run.EndTime)
	}
	if run.Duration != "" {
		fmt.Fprintf(w, "| %s | %s |\n", t.Duration, run.Duration)
	}
}

func reportSections(t translations) []reportSection {
	return []reportSection{
		{title: t.SummarySection, anchor: anchorSummary, level: 0},
		{title: t.SummaryAnalysisSection, anchor: anchorSummaryAnalysis, level: 1},
		{title: t.SummaryVulnSection, anchor: anchorSummaryVuln, level: 1},
		{title: t.RunScopeSection, anchor: anchorRunScope, level: 0},
		{title: t.InputSection, anchor: anchorInputFile, level: 1},
		{title: t.ConfigSection, anchor: anchorConfig, level: 1},
		{title: t.SandboxSection, anchor: anchorSandbox, level: 1},
		{title: t.MethodOverviewSection, anchor: anchorMethodOverview, level: 0},
		{title: t.ProcessingIssuesSection, anchor: anchorProcessingErrors, level: 0},
		{title: t.ResidualRiskSection, anchor: anchorResidualRisk, level: 0},
		{title: t.AppendixSection, anchor: anchorAppendix, level: 0},
		{title: t.ComponentIndexSection, anchor: anchorComponentIndex, level: 1},
		{title: t.ComponentIndexWithPURLSubsection, anchor: anchorComponentsWithPURL, level: 2},
		{title: t.ComponentIndexWithoutPURLSubsection, anchor: anchorComponentsWithoutPURL, level: 2},
		{title: t.ComponentNormalizationSection, anchor: anchorSuppression, level: 1},
		{title: t.SuppressionReasonFSArtifact, anchor: anchorSuppressionFSArtifacts, level: 2},
		{title: t.SuppressionReasonLowValueFile, anchor: anchorSuppressionLowValue, level: 2},
		{title: t.SuppressionReasonWeakDuplicate, anchor: anchorSuppressionWeakDups, level: 2},
		{title: t.SuppressionReasonPURLDuplicate, anchor: anchorSuppressionPURLDups, level: 2},
		{title: t.ExtensionFilterSection, anchor: anchorExtensionFilter, level: 1},
		{title: t.RootMetadataSection, anchor: anchorRootMetadata, level: 1},
		{title: t.PolicySection, anchor: anchorPolicy, level: 1},
		{title: t.ScanSection, anchor: anchorScan, level: 1},
		{title: t.ScanNoPackageIDsSection, anchor: anchorScanNoPackageIDs, level: 1},
		{title: t.ExtractionSection, anchor: anchorExtraction, level: 1},
	}
}

func writeAnchoredHeading(w io.Writer, level int, title, anchor string) {
	if anchor != "" && anchor != markdownHeadingAnchor(title) {
		fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchor)
	}
	fmt.Fprintf(w, "%s %s\n\n", strings.Repeat("#", level), title)
}

func writeSectionHeading(w io.Writer, title, anchor string) {
	writeAnchoredHeading(w, 2, title, anchor)
}

func writeTableOfContents(w io.Writer, sections []reportSection) {
	for _, section := range sections {
		indent := ""
		for i := 0; i < section.level; i++ {
			indent += "  "
		}
		fmt.Fprintf(w, "%s- [%s](#%s)\n", indent, section.title, section.anchor)
	}
}

func sectionLink(title, anchor string) string {
	return fmt.Sprintf("[%s](#%s)", title, anchor)
}

// componentAnchorLink renders label as a Markdown link to a package group's
// anchor in the Component Occurrence Index, or the plain label when no anchor is
// known. Group anchors are already slugified (e.g. "package-foo-1-0-0") and are
// used verbatim as the link fragment, keeping anchor handling consistent across
// the vulnerability and suppression renderers.
func componentAnchorLink(label, anchorID string) string {
	if anchorID == "" {
		return label
	}
	return fmt.Sprintf("[%s](#%s)", label, anchorID)
}

func scanApproachLink(label, anchor string) string {
	return fmt.Sprintf("[%s](%s#%s)", label, scanApproachGitHubURL, anchor)
}

func markdownHeadingAnchor(title string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(title) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == ' ':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
