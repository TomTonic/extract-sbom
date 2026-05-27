package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// vulnerabilityRequested reports whether vulnerability enrichment actually ran.
func vulnerabilityRequested(v *vulnscan.Result) bool {
	return v != nil && v.Requested && v.State != vulnscan.StateNotRequested
}

// writeAnchoredHeading writes one Markdown heading and emits a separate HTML
// anchor only when the requested anchor differs from the heading's natural slug.
func writeAnchoredHeading(w io.Writer, level int, title, anchor string) {
	if anchor != "" && anchor != markdownHeadingAnchor(title) {
		fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", anchor)
	}
	fmt.Fprintf(w, "%s %s\n\n", strings.Repeat("#", level), title)
}

// writeSectionHeading writes one anchored level-2 section heading.
//
//nolint:unused // Retained for legacy root helpers until remaining human tests move.
func writeSectionHeading(w io.Writer, title, anchor string) {
	writeAnchoredHeading(w, 2, title, anchor)
}

// sectionLink builds an in-document anchor link.
//
//nolint:unused // Retained for legacy root helpers until remaining human tests move.
func sectionLink(title, anchor string) string {
	return fmt.Sprintf("[%s](#%s)", title, anchor)
}

// scanApproachLink builds a link to a specific SCAN_APPROACH section.
//
//nolint:unused // Retained for legacy root helpers until remaining human tests move.
func scanApproachLink(label, anchor string) string {
	return fmt.Sprintf("[%s](%s#%s)", label, scanApproachGitHubURL, anchor)
}

// markdownHeadingAnchor approximates the auto-generated Markdown heading slug.
func markdownHeadingAnchor(title string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(title) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		case r == ' ' || r == '-':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// collectSuppressionStats groups suppression records by suppression reason.
func collectSuppressionStats(suppressions []assembly.SuppressionRecord) suppressionStats {
	stats := suppressionStats{}
	for i := range suppressions {
		switch suppressions[i].Reason {
		case assembly.SuppressionFSArtifact:
			stats.FSArtifacts++
		case assembly.SuppressionLowValueFile:
			stats.LowValueFiles++
		case assembly.SuppressionWeakDuplicate:
			stats.WeakDuplicate++
		case assembly.SuppressionPURLDuplicate:
			stats.PURLDuplicate++
		}
	}
	return stats
}

// escapeMarkdownCell sanitizes table-cell content for Markdown output.
func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

// collectProcessingEntries flattens processing issues from pipeline,
// extraction, and scan phases into a deterministically sorted table model.
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
