package markdown

import (
	"fmt"
	"io"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writePolicyDecisions lists policy-engine decisions captured during runtime.
func writePolicyDecisions(w io.Writer, decisions []reportjson.PolicyDecisionRowV2, t translations) {
	if len(decisions) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noPolicyDecisions)
		return
	}
	for _, d := range decisions {
		fmt.Fprintf(w, "- **%s** %s `%s`: %s -> %s\n", d.Trigger, t.policyDecisionAt, d.NodePath, d.Detail, d.Action)
	}
}

// writeProcessingIssues prints a bounded table of pipeline/extraction/scan
// issues for auditable troubleshooting.
func writeProcessingIssues(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	var extractionIssues []reportjson.ExtractionLogRowV2
	for i := range proj.ExtractionLog {
		switch proj.ExtractionLog[i].Status {
		case "failed", "security-blocked", "tool-missing":
			extractionIssues = append(extractionIssues, proj.ExtractionLog[i])
		}
	}

	if len(proj.Issues) == 0 && len(extractionIssues) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noProcessingIssues)
		return
	}

	fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
		t.processingSourceHeader, t.processingLocationHeader, t.processingClassHeader,
		t.processingStatusHeader, t.processingDetectedHeader, t.processingToolHeader,
		t.processingArchiveTypeHeader, t.processingArchiveMethodHeader,
		t.processingEncryptedHeader, t.processingPhysicalSizeHeader, t.processingDetailHeader)
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|---|---|---|")

	for _, issue := range proj.Issues {
		fmt.Fprintf(w, "| %s | %s | %s | - | - | - | - | - | - | - | %s |\n",
			escapeMarkdownCell(t.processingPipelineLabel),
			escapeMarkdownCell(issue.Stage),
			escapeMarkdownCell(t.processingPipelineLabel+"-error"),
			escapeMarkdownCell(issue.Message))
	}
	for i := range extractionIssues {
		row := &extractionIssues[i]
		class := extractionStatusClass(row.Status, t)
		archiveType, archiveMethod, encrypted, physicalSize := extractionArchiveCols(row)
		detected := ""
		if row.Depth > 0 {
			detected = fmt.Sprintf("%d", row.Depth)
		}
		fmt.Fprintf(w, "| extraction | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escapeMarkdownCell(row.Path),
			escapeMarkdownCell(class),
			escapeMarkdownCell(row.ResolutionStatus),
			escapeMarkdownCell(detected),
			escapeMarkdownCell(row.Tool),
			escapeMarkdownCell(archiveType),
			escapeMarkdownCell(archiveMethod),
			escapeMarkdownCell(encrypted),
			escapeMarkdownCell(physicalSize),
			escapeMarkdownCell(row.Detail))
	}
}

func extractionStatusClass(status string, t translations) string {
	switch status {
	case "failed":
		return t.processingExtractionFailedLabel
	case "security-blocked":
		return t.processingSecurityBlockedLabel
	case "tool-missing":
		return t.processingToolMissingLabel
	default:
		return status
	}
}

func extractionArchiveCols(row *reportjson.ExtractionLogRowV2) (archiveType, archiveMethod, encrypted, physicalSize string) {
	if row.ArchiveMeta == nil {
		return "-", "-", "-", "-"
	}
	m := row.ArchiveMeta
	archiveType = m.Type
	if archiveType == "" {
		archiveType = "-"
	}
	archiveMethod = strings.Join(m.Methods, ", ")
	if archiveMethod == "" {
		archiveMethod = "-"
	}
	if m.HasEncryptedItem {
		encrypted = "true"
	} else {
		encrypted = "false"
	}
	physicalSize = m.PhysicalSize
	if physicalSize == "" {
		physicalSize = "-"
	}
	return
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
