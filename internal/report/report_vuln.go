package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

type vulnerabilitySummaryRow struct {
	Severity        string
	VulnerabilityID string
	ComponentID     string
	Package         string
}

func writeVulnerabilitySummary(w io.Writer, data ReportData, occurrences []componentOccurrence) {
	if data.Vulnerabilities == nil {
		fmt.Fprintln(w, "- Vulnerability enrichment: not requested")
		return
	}

	v := data.Vulnerabilities
	fmt.Fprintf(w, "- Vulnerability enrichment state: `%s`\n", v.State)
	if v.GrypeVersion != "" {
		fmt.Fprintf(w, "- Grype version: `%s`\n", v.GrypeVersion)
	}
	if v.DBSchemaVersion != "" || v.DBBuilt != "" || v.DBUpdated != "" {
		fmt.Fprintf(w, "- Grype DB: schema=`%s` built=`%s` updated=`%s`\n", emptyDash(v.DBSchemaVersion), emptyDash(v.DBBuilt), emptyDash(v.DBUpdated))
	}
	if len(v.Errors) > 0 {
		fmt.Fprintf(w, "- Vulnerability enrichment issues: %d\n", len(v.Errors))
	}

	rows := buildVulnerabilitySummaryRows(v, occurrences)
	if len(rows) == 0 {
		fmt.Fprintln(w, "- Vulnerability findings: no matched vulnerabilities")
		return
	}

	fmt.Fprintln(w, "\nVulnerability summary (highest severity first):")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Vulnerability | Component | Package |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for i := range rows {
		anchor := occurrenceAnchorID(rows[i].ComponentID)
		fmt.Fprintf(w, "| %s | %s | [%s](#%s) | %s |\n",
			strings.ToUpper(rows[i].Severity),
			rows[i].VulnerabilityID,
			rows[i].ComponentID,
			anchor,
			escapeMarkdownCell(rows[i].Package),
		)
	}
}

func buildVulnerabilitySummaryRows(v *vulnscan.Result, occurrences []componentOccurrence) []vulnerabilitySummaryRow {
	if v == nil || len(v.MatchesByBOMRef) == 0 {
		return nil
	}
	packageByID := map[string]string{}
	for i := range occurrences {
		packageByID[occurrences[i].ObjectID] = occurrences[i].PackageName
	}

	rows := make([]vulnerabilitySummaryRow, 0)
	for compID, matches := range v.MatchesByBOMRef {
		for i := range matches {
			rows = append(rows, vulnerabilitySummaryRow{
				Severity:        normalizeSeverity(matches[i].Severity),
				VulnerabilityID: matches[i].VulnerabilityID,
				ComponentID:     compID,
				Package:         packageByID[compID],
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if severityRank(rows[i].Severity) != severityRank(rows[j].Severity) {
			return severityRank(rows[i].Severity) < severityRank(rows[j].Severity)
		}
		if rows[i].VulnerabilityID != rows[j].VulnerabilityID {
			return rows[i].VulnerabilityID < rows[j].VulnerabilityID
		}
		return rows[i].ComponentID < rows[j].ComponentID
	})
	return rows
}

func writeOccurrenceVulnerabilityBlock(w io.Writer, occ componentOccurrence, v *vulnscan.Result) {
	if v == nil || v.State == vulnscan.StateNotRequested {
		return
	}
	matches := v.MatchesByBOMRef[occ.ObjectID]
	if len(matches) > 0 {
		fmt.Fprintf(w, "- Vulnerability status: `found` (%d)\n", len(matches))
		for i := range matches {
			m := matches[i]
			fmt.Fprintf(w, "  - `%s` (%s)", m.VulnerabilityID, strings.ToUpper(normalizeSeverity(m.Severity)))
			if m.Namespace != "" {
				fmt.Fprintf(w, " namespace=`%s`", m.Namespace)
			}
			if m.MatchType != "" {
				fmt.Fprintf(w, " match=`%s`", m.MatchType)
			}
			if m.Matcher != "" {
				fmt.Fprintf(w, " matcher=`%s`", m.Matcher)
			}
			fmt.Fprintln(w)
			if m.DataSource != "" {
				fmt.Fprintf(w, "    - Source: %s\n", m.DataSource)
			}
			if m.FixState != "" || len(m.FixVersions) > 0 {
				fmt.Fprintf(w, "    - Fix: state=`%s` versions=`%s`\n", emptyDash(m.FixState), strings.Join(m.FixVersions, ", "))
			}
			for _, u := range m.URLs {
				fmt.Fprintf(w, "    - Reference: %s\n", u)
			}
		}
		return
	}

	if v.State == vulnscan.StateUnavailable || v.State == vulnscan.StateCompletedWithErrors {
		fmt.Fprintln(w, "- Vulnerability status: `not-assessable` (enrichment unavailable or incomplete)")
		return
	}
	if occ.PURL == "" && occ.CPE == "" {
		fmt.Fprintln(w, "- Vulnerability status: `not-assessable` (no PURL/CPE)")
		return
	}
	fmt.Fprintln(w, "- Vulnerability status: `none`")
}

func normalizeSeverity(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "critical", "high", "medium", "low", "negligible", "unknown":
		return s
	default:
		if s == "" {
			return "unknown"
		}
		return s
	}
}

func severityRank(raw string) int {
	s := normalizeSeverity(raw)
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "negligible":
		return 4
	default:
		return 5
	}
}

func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}
