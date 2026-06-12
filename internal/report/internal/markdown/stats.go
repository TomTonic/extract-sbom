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
	for _, row := range rows {
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
	for _, row := range proj.ExtractionLog {
		switch row.Status {
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

	v := t.noneValue
	if idx.IndexedComponents > 0 {
		v = fmt.Sprintf("%d", idx.IndexedWithPURL)
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskPURLCoverage, sectionLink(t.scanNoPackageIDsSection, anchorComponentsWithPURL), v))

	v = t.noneValue
	if idx.IndexedComponents > 0 {
		v = fmt.Sprintf("%d", idx.IndexedWithEvidencePath+idx.IndexedWithEvidenceSourceOnly)
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskEvidenceCoverage, v))

	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskNoComponentTasks, sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs), len(proj.Summary.ScanNoPackagePaths)))
	}
	if idx.FilteredLowValueFileArtifacts > 0 || idx.FilteredContainerNodes > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskFileArtifactCoverage, sectionLink(t.suppressionReasonLowValueFile, anchorSuppressionLowValue), idx.FilteredLowValueFileArtifacts+idx.FilteredContainerNodes))
	}
	if len(proj.Summary.ExtensionFilteredPaths) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskExtensionFilter, sectionLink(t.extensionFilterSection, anchorExtensionFilter), len(proj.Summary.ExtensionFilteredPaths)))
	}
	if extFailed > 0 || extBlocked > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskExtractionGap, extFailed+extBlocked))
	}
	if extMissing > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskToolGap, extMissing))
	}
	if scnErrors > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskScanGap, scnErrors))
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskMoreDetails, scanApproachLink(t.linkPackageDetectionReliability, "6-package-detection-reliability")))
}

func configSkipExtensionsDisplay(exts []string) string {
	return strings.Join(exts, ", ")
}
