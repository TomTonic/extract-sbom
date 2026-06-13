package markdown

import (
	"fmt"
	"io"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeExtractionLog renders the extraction log projection as an indented Markdown list
// with status, tool, sandbox, duration, and archive metadata per node.
func writeExtractionLog(w io.Writer, rows []reportjson.ExtractionLogRowV2, t translations) {
	for i := range rows {
		row := &rows[i]
		indent := strings.Repeat("  ", row.Depth)
		fmt.Fprintf(w, "%s- **%s** [%s] %s=%s", indent, row.Path, row.Format, t.status, row.Status)
		if row.Tool != "" {
			fmt.Fprintf(w, " %s=%s", t.tool, row.Tool)
		}
		if row.SandboxUsed != "" {
			fmt.Fprintf(w, " %s=%s", t.extractionSandboxLabel, row.SandboxUsed)
		}
		if row.Duration != "" {
			fmt.Fprintf(w, " %s=%s", t.duration, row.Duration)
		}
		if meta := formatExtractionArchiveMeta(row.ArchiveMeta); meta != "" {
			fmt.Fprintf(w, " %s", meta)
		}
		if row.Detail != "" {
			fmt.Fprintf(w, " (%s)", row.Detail)
		}
		fmt.Fprintln(w)
	}
}

func formatExtractionArchiveMeta(meta *reportjson.ExtractionArchiveMetaV2) string {
	if meta == nil {
		return ""
	}
	parts := make([]string, 0, 7)
	if meta.Type != "" {
		parts = append(parts, "type="+meta.Type)
	}
	if len(meta.Methods) > 0 {
		parts = append(parts, "method="+strings.Join(meta.Methods, " / "))
	}
	if meta.HasEncryptedItem {
		parts = append(parts, "encrypted=yes")
	}
	if meta.PhysicalSize != "" {
		parts = append(parts, "physical-size="+meta.PhysicalSize)
	}
	if meta.HeadersSize != "" {
		parts = append(parts, "headers-size="+meta.HeadersSize)
	}
	if meta.Solid != "" {
		parts = append(parts, "solid="+meta.Solid)
	}
	if meta.Blocks != "" {
		parts = append(parts, "blocks="+meta.Blocks)
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// writeResidualRisk writes the explicit limitations statement required for
// auditability when extraction/scan coverage is partial.
func writeResidualRisk(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	fmt.Fprintln(w, t.residualRiskText)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s\n", t.residualRiskProfileLead)
	fmt.Fprintf(w, "- %s\n", t.residualRiskAbsenceHint)

	idx := proj.Summary.ComponentIndexStats

	var extFailed, extBlocked, extMissing int
	for i := range proj.ExtractionLog {
		switch proj.ExtractionLog[i].Status {
		case "failed":
			extFailed++
		case "security-blocked":
			extBlocked++
		case "tool-missing":
			extMissing++
		}
	}

	var scnErrors int
	for _, issue := range proj.Issues {
		if issue.Stage == "scan" {
			scnErrors++
		}
	}

	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskPURLCoverage,
		idx.IndexedWithPURL, idx.IndexedComponents, idx.IndexedWithoutPURL))

	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskEvidenceCoverage,
		idx.IndexedWithEvidencePath, idx.IndexedWithEvidenceSourceOnly, idx.IndexedWithoutEvidence))

	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskNoComponentTasks,
			len(proj.Summary.ScanNoPackagePaths),
			proj.Summary.ScanTasks,
			joinPathExamples(proj.Summary.ScanNoPackagePaths)))
	}
	if idx.FilteredLowValueFileArtifacts > 0 || idx.FilteredContainerNodes > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskFileArtifactCoverage,
			idx.FilteredLowValueFileArtifacts+idx.FilteredContainerNodes))
	}
	if len(proj.Summary.ExtensionFilteredPaths) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskExtensionFilter,
			len(proj.Summary.ExtensionFilteredPaths),
			sectionLink(t.extensionFilterSection, anchorExtensionFilter)))
	}
	if extFailed > 0 || extBlocked > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskExtractionGap,
			extFailed+extBlocked,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "failed", "security-blocked"))))
	}
	if extMissing > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskToolGap,
			extMissing,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "tool-missing"))))
	}
	if scnErrors > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskScanGap,
			scnErrors,
			joinPathExamples(scanIssuePaths(proj.Issues))))
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskMoreDetails, scanApproachLink(t.linkPackageDetectionReliability, "6-package-detection-reliability")))
}

func configSkipExtensionsDisplay(exts []string, isDefault bool) string {
	s := strings.Join(exts, ", ")
	if isDefault {
		return s + " (default)"
	}
	return s
}

// extractionPathsByStatus collects extraction-log node paths whose status is in
// the given set, for use as example lists in prose summaries.
func extractionPathsByStatus(rows []reportjson.ExtractionLogRowV2, statuses ...string) []string {
	want := make(map[string]struct{}, len(statuses))
	for _, s := range statuses {
		want[s] = struct{}{}
	}
	var out []string
	for i := range rows {
		if _, ok := want[rows[i].Status]; ok {
			out = append(out, rows[i].Path)
		}
	}
	return out
}

// scanIssuePaths returns the messages of scan-stage processing issues for use as
// example lists in prose summaries.
func scanIssuePaths(issues []reportjson.IssueRowV2) []string {
	var out []string
	for _, issue := range issues {
		if issue.Stage == "scan" {
			out = append(out, issue.Message)
		}
	}
	return out
}

// maxProseExamples bounds how many example paths appear in a prose summary line.
const maxProseExamples = 3

// joinPathExamples renders up to maxProseExamples backtick-quoted example paths,
// appending an ellipsis when more entries exist, for use in prose summaries.
func joinPathExamples(paths []string) string {
	if len(paths) == 0 {
		return "-"
	}
	n := len(paths)
	if n > maxProseExamples {
		n = maxProseExamples
	}
	quoted := make([]string, 0, n)
	for i := 0; i < n; i++ {
		quoted = append(quoted, "`"+paths[i]+"`")
	}
	out := strings.Join(quoted, ", ")
	if len(paths) > maxProseExamples {
		out += ", …"
	}
	return out
}
