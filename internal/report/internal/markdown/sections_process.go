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
		fmt.Fprintf(w, "- %s\n", t.NoPolicyDecisions)
		return
	}
	for _, d := range decisions {
		fmt.Fprintf(w, "- **%s** %s `%s`: %s -> %s\n", d.Trigger, t.PolicyDecisionAt, d.NodePath, d.Detail, d.Action)
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
		fmt.Fprintf(w, "- %s\n", t.NoProcessingIssues)
		return
	}

	fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
		t.ProcessingSourceHeader, t.ProcessingLocationHeader, t.ProcessingClassHeader,
		t.ProcessingStatusHeader, t.ProcessingDetectedHeader, t.ProcessingToolHeader,
		t.ProcessingArchiveTypeHeader, t.ProcessingArchiveMethodHeader,
		t.ProcessingEncryptedHeader, t.ProcessingPhysicalSizeHeader, t.ProcessingDetailHeader)
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|---|---|---|")

	for _, issue := range proj.Issues {
		fmt.Fprintf(w, "| %s | %s | %s | - | - | - | - | - | - | - | %s |\n",
			escapeMarkdownCell(t.ProcessingPipelineLabel),
			escapeMarkdownCell(issue.Stage),
			escapeMarkdownCell(t.ProcessingPipelineLabel+"-error"),
			escapeMarkdownCell(issue.Message))
	}
	for i := range extractionIssues {
		row := &extractionIssues[i]
		class := extractionStatusClass(row.Status, row.Detail, t)
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

func extractionStatusClass(status, detail string, t translations) string {
	switch status {
	case "failed":
		lower := strings.ToLower(detail)
		switch {
		case strings.Contains(lower, "per-extraction timeout"):
			return t.ProcessingTimeoutLabel
		case strings.Contains(lower, "no matching password"):
			return t.ProcessingPasswordRequiredLabel
		case strings.Contains(lower, "can not open the file as archive") ||
			strings.Contains(lower, "is not archive") ||
			strings.Contains(lower, "does not match the detected archive format"):
			return t.ProcessingFormatMismatchLabel
		case strings.Contains(lower, "unexpected end of archive") ||
			strings.Contains(lower, "headers error") ||
			strings.Contains(lower, "unconfirmed start of archive") ||
			strings.Contains(lower, "truncated/corrupt") ||
			strings.Contains(lower, "invalid tar header"):
			return t.ProcessingCorruptLabel
		default:
			return t.ProcessingExtractionFailedLabel
		}
	case "security-blocked":
		return t.ProcessingSecurityBlockedLabel
	case "tool-missing":
		return t.ProcessingToolMissingLabel
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

// escapeMarkdownText escapes angle brackets in user-supplied strings that are
// rendered directly into Markdown headings or inline prose (not table cells).
// Use escapeMarkdownCell for table values instead.
func escapeMarkdownText(value string) string {
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	return value
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
