package markdown

import (
	"fmt"
	"io"
	"strings"
)

func writeRootMetadata(w io.Writer, data ReportData, t translations) {
        fmt.Fprintln(w, "### Root Component Metadata")
        fmt.Fprintln(w)
        
        fmt.Fprintf(w, "| %s | %s | %s |\n", t.field, t.value, t.source)
        fmt.Fprintln(w, "|---|---|---|")
        
        if data.BOM == nil || data.BOM.Metadata == nil || data.BOM.Metadata.Component == nil {
                return
        }
        comp := data.BOM.Metadata.Component
        fmt.Fprintf(w, "| %s | %s | %s |\n", t.objectID, escapeMarkdownCell(comp.BOMRef), escapeMarkdownCell(t.derived))
        if comp.Name != "" { fmt.Fprintf(w, "| %s | %s | %s |\n", t.packageName, escapeMarkdownCell(comp.Name), escapeMarkdownCell(t.derived)) }
        if comp.Version != "" { fmt.Fprintf(w, "| %s | %s | %s |\n", t.version, escapeMarkdownCell(comp.Version), escapeMarkdownCell(t.derived)) }
        fmt.Fprintln(w)
}

func reportSections(t translations) []reportSection {
        return []reportSection{
                {title: t.summarySection, anchor: anchorSummary, level: 0},
                {title: t.summaryAnalysisSection, anchor: anchorSummaryAnalysis, level: 1},
                {title: t.summaryKeyFindingsSection, anchor: anchorSummaryKeyFindings, level: 1},
                {title: t.summaryVulnSection, anchor: anchorSummaryVuln, level: 1},
                {title: t.methodOverviewSection, anchor: anchorMethodOverview, level: 0},
                {title: t.processingIssuesSection, anchor: anchorProcessingErrors, level: 0},
                {title: t.residualRiskSection, anchor: anchorResidualRisk, level: 0},
                {title: t.appendixSection, anchor: anchorAppendix, level: 0},
                {title: t.componentIndexSection, anchor: anchorComponentIndex, level: 1},
                {title: t.componentNormalizationSection, anchor: anchorSuppression, level: 1},
                {title: t.inputSection, anchor: anchorInputFile, level: 1},
                {title: t.configSection, anchor: anchorConfig, level: 1},
                {title: t.rootMetadataSection, anchor: anchorRootMetadata, level: 1},
                {title: t.sandboxSection, anchor: anchorSandbox, level: 1},
                {title: t.policySection, anchor: anchorPolicy, level: 1},
                {title: t.scanSection, anchor: anchorScan, level: 1},
                {title: t.scanNoPackageIDsSection, anchor: anchorScanNoPackageIDs, level: 1},
                {title: t.extractionSection, anchor: anchorExtraction, level: 1},
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
