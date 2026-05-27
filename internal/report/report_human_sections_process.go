package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
)

// writePolicyDecisions lists policy-engine decisions captured during runtime.
func writePolicyDecisions(w io.Writer, decisions []policy.Decision, t translations) {
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
func writeProcessingIssues(w io.Writer, data ReportData, ext extractionStats, scn scanStats, t translations) {
	entries := collectProcessingEntries(data)

	fmt.Fprintf(w, "- %s: %d\n", t.processingPipelineLabel, len(data.ProcessingIssues))
	fmt.Fprintf(w, "- %s: %d\n", t.processingExtractionFailedLabel, ext.Failed)
	fmt.Fprintf(w, "- %s: %d\n", t.processingSecurityBlockedLabel, ext.SecurityBlocked)
	fmt.Fprintf(w, "- %s: %d\n", t.processingToolMissingLabel, ext.ToolMissing)
	fmt.Fprintf(w, "- %s: %d\n", t.processingScanErrorsLabel, scn.Errors)

	if len(entries) == 0 {
		fmt.Fprintf(w, "\n- %s\n", t.noProcessingIssues)
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintf(
		w,
		"| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
		t.processingSourceHeader,
		t.processingLocationHeader,
		t.processingClassHeader,
		t.processingStatusHeader,
		t.processingDetectedHeader,
		t.processingToolHeader,
		t.processingArchiveTypeHeader,
		t.processingArchiveMethodHeader,
		t.processingEncryptedHeader,
		t.processingPhysicalSizeHeader,
		t.processingDetailHeader,
	)
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|---|---|---|")

	maxRows := 25
	for i := range entries {
		entry := &entries[i]
		if i >= maxRows {
			remaining := len(entries) - maxRows
			fmt.Fprintf(w, "| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | %s |\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, remaining))
			break
		}
		fmt.Fprintf(
			w,
			"| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escapeMarkdownCell(entry.Source),
			escapeMarkdownCell(entry.Location),
			escapeMarkdownCell(entry.Classification),
			escapeMarkdownCell(entry.Status),
			escapeMarkdownCell(entry.DetectedFormat),
			escapeMarkdownCell(entry.Tool),
			escapeMarkdownCell(entry.ArchiveType),
			escapeMarkdownCell(entry.ArchiveMethod),
			escapeMarkdownCell(entry.Encrypted),
			escapeMarkdownCell(entry.PhysicalSize),
			escapeMarkdownCell(entry.Detail),
		)
	}
}

// collectProcessingEntries flattens processing issues from pipeline, extraction,
// and scan phases into a deterministically sorted table model.
func collectProcessingEntries(data ReportData) []processingEntry {
	entries := make([]processingEntry, 0, len(data.ProcessingIssues)+len(data.Scans))

	for _, issue := range data.ProcessingIssues {
		entries = append(entries, processingEntry{
			Source:         "pipeline",
			Location:       issue.Stage,
			Classification: "pipeline-error",
			Detail:         issue.Message,
		})
	}

	var walk func(node *extract.ExtractionNode)
	walk = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}
		if node.Status == extract.StatusFailed || node.Status == extract.StatusToolMissing || node.Status == extract.StatusSecurityBlocked {
			detail := node.StatusDetail
			if detail == "" {
				detail = "status=" + node.Status.String()
			}
			metaType := ""
			metaMethod := ""
			metaEncrypted := ""
			metaPhysicalSize := ""
			if node.ArchiveMeta != nil {
				metaType = node.ArchiveMeta.Type
				if len(node.ArchiveMeta.Methods) > 0 {
					metaMethod = strings.Join(node.ArchiveMeta.Methods, " / ")
				}
				if node.ArchiveMeta.HasEncryptedItem {
					metaEncrypted = "yes"
				}
				metaPhysicalSize = node.ArchiveMeta.PhysicalSize
			}
			entries = append(entries, processingEntry{
				Source:         "extraction",
				Location:       node.Path,
				Classification: classifyExtractionIssue(node),
				Status:         node.Status.String(),
				DetectedFormat: node.Format.Format.String(),
				Tool:           node.Tool,
				ArchiveType:    metaType,
				ArchiveMethod:  metaMethod,
				Encrypted:      metaEncrypted,
				PhysicalSize:   metaPhysicalSize,
				Detail:         compactExtractionDetail(detail),
			})
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(data.Tree)

	for _, sr := range data.Scans {
		if sr.Error == nil {
			continue
		}
		entries = append(entries, processingEntry{
			Source:         "scan",
			Location:       sr.NodePath,
			Classification: "scan-error",
			Tool:           "syft",
			Detail:         sr.Error.Error(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		if entries[i].Classification != entries[j].Classification {
			return entries[i].Classification < entries[j].Classification
		}
		return entries[i].Detail < entries[j].Detail
	})

	return entries
}

func classifyExtractionIssue(node *extract.ExtractionNode) string {
	if node.Status == extract.StatusToolMissing {
		return "tool-missing"
	}
	if node.Status == extract.StatusSecurityBlocked {
		return "security-blocked"
	}
	lower := strings.ToLower(node.StatusDetail)
	switch {
	case strings.Contains(lower, "wrong password") || strings.Contains(lower, "encrypted archive"):
		return "password-required"
	case strings.Contains(lower, "timeout"):
		return "timeout"
	case strings.Contains(lower, "invalid tar header") || strings.Contains(lower, "headers error") || strings.Contains(lower, "unconfirmed start of archive") || strings.Contains(lower, "unexpected end of archive"):
		return "archive-corrupt-or-truncated"
	case strings.Contains(lower, "not a valid zip") || strings.Contains(lower, "can not open the file as archive") || strings.Contains(lower, "cannot open the file as") || strings.Contains(lower, "is not archive"):
		return "format-mismatch-or-invalid-archive"
	default:
		return "extraction-failed"
	}
}

func compactExtractionDetail(detail string) string {
	trimmed := strings.TrimSpace(detail)
	if idx := strings.Index(trimmed, ": "); idx != -1 {
		prefix := trimmed[:idx]
		if strings.Contains(prefix, " extraction failed") {
			trimmed = strings.TrimSpace(trimmed[idx+2:])
		}
	}
	return trimmed
}

// escapeMarkdownCell sanitizes table-cell content for Markdown output.
func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
