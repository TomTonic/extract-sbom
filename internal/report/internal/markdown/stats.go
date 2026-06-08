package markdown

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeExtractionTree renders the extraction tree as an indented Markdown list
// with status, tool, and timing metadata per node.
func writeExtractionTree(w io.Writer, node *extract.ExtractionNode, depth int, t translations) {
	if node == nil {
		return
	}

	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(w, "%s- **%s** [%s] %s=%s", indent, node.Path, node.Format.Format, t.status, node.Status)

	if node.Tool != "" {
		fmt.Fprintf(w, " %s=%s", t.tool, node.Tool)
	}
	if node.SandboxUsed != "" {
		fmt.Fprintf(w, " %s=%s", t.extractionSandboxLabel, node.SandboxUsed)
	}
	if node.Duration > 0 {
		fmt.Fprintf(w, " %s=%s", t.duration, node.Duration.Round(time.Millisecond))
	}
	if meta := formatArchiveMetaForLog(node); meta != "" {
		fmt.Fprintf(w, " %s", meta)
	}
	if node.StatusDetail != "" {
		fmt.Fprintf(w, " (%s)", node.StatusDetail)
	}
	fmt.Fprintln(w)

	for _, child := range node.Children {
		writeExtractionTree(w, child, depth+1, t)
	}
}

func formatArchiveMetaForLog(node *extract.ExtractionNode) string {
	if node == nil || node.ArchiveMeta == nil {
		return ""
	}
	meta := node.ArchiveMeta
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
func writeResidualRisk(w io.Writer, data ReportData, proj reportjson.ProjectionsV2, t translations) {
        fmt.Fprintln(w, t.residualRiskText)
        fmt.Fprintln(w)
        fmt.Fprintf(w, "- %s\n", t.residualRiskProfileLead)
        fmt.Fprintf(w, "- %s\n", t.residualRiskAbsenceHint)
        
        idx := proj.Summary.ComponentIndexStats
        
        var extFailed, extBlocked, extMissing int
        for _, row := range proj.ExtractionLog {
        	switch row.Status {
        	case "failed": extFailed++
        	case "blocked": extBlocked++
        	case "tool_missing": extMissing++
        	}
        }
        
        var scnErrors int
        // Assuming scan errors are also in proj.Issues which we could check, or we don't bother for residual risk (usually it's extracting gap we care about)
        // Let's count them from Issues
        for _, issue := range proj.Issues {
        	if issue.Stage == "scan" {
        		scnErrors++
        	}
        }
        
        // Output PURLLine
        v := t.noneValue
        if idx.IndexedComponents > 0 { v = fmt.Sprintf("%d", idx.IndexedWithPURL) }
        fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskPURLCoverage, sectionLink(t.scanNoPackageIDsSection, anchorComponentsWithPURL), v))

        v = t.noneValue
        if idx.IndexedComponents > 0 { v = fmt.Sprintf("%d", idx.IndexedWithEvidencePath + idx.IndexedWithEvidenceSourceOnly) }
        fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskEvidenceCoverage, v))
        
        if len(proj.Summary.ScanNoPackagePaths) > 0 {
                fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskNoComponentTasks, sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs), len(proj.Summary.ScanNoPackagePaths)))
        }
        if idx.FilteredLowValueFileArtifacts > 0 || idx.FilteredContainerNodes > 0 {
                fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.residualRiskFileArtifactCoverage, sectionLink(t.suppressionReasonLowValueFile, anchorSuppressionLowValue), idx.FilteredLowValueFileArtifacts + idx.FilteredContainerNodes))
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
