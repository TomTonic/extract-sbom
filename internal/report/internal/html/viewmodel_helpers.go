package html

import (
	"strings"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

const maxProseExamples = 3

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

func scanIssuePaths(issues []reportjson.IssueRowV2) []string {
	var out []string
	for _, issue := range issues {
		if issue.Stage == "scan" {
			out = append(out, issue.Message)
		}
	}
	return out
}

func countExtractionStatuses(rows []reportjson.ExtractionLogRowV2) (failed, missing int) {
	for i := range rows {
		switch rows[i].Status {
		case "failed", "security-blocked":
			failed++
		case "tool-missing":
			missing++
		}
	}
	return failed, missing
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

func extractionStatusClass(status, detail string, t i18npkg.Bundle) string {
	switch status {
	case "failed":
		lower := strings.ToLower(detail)
		switch {
		case strings.Contains(lower, "per-extraction timeout"):
			return t.ProcessingTimeoutLabel
		case strings.Contains(lower, "no matching password"):
			return t.ProcessingPasswordRequiredLabel
		case strings.Contains(lower, "can not open the file as archive"),
			strings.Contains(lower, "is not archive"),
			strings.Contains(lower, "does not match the detected archive format"):
			return t.ProcessingFormatMismatchLabel
		case strings.Contains(lower, "unexpected end of archive"),
			strings.Contains(lower, "headers error"),
			strings.Contains(lower, "unconfirmed start of archive"),
			strings.Contains(lower, "truncated/corrupt"),
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
	return archiveType, archiveMethod, encrypted, physicalSize
}
