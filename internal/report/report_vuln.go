package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// vulnerabilitySummaryRow holds one grype-inspired vulnerability table row.
type vulnerabilitySummaryRow struct {
	ComponentID     string
	Name            string
	Installed       string
	FixedIn         string
	Type            string
	VulnerabilityID string
	Severity        string
	EPSS            *float64
	EPSSPercentile  *float64
	Risk            *float64
	KEV             bool
}

// writeVulnerabilitySummary renders the vulnerability enrichment section to w,
// including state, grype version, and a per-severity summary table.
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
	uniqueVulns := map[string]struct{}{}
	affectedComponents := map[string]struct{}{}
	for i := range rows {
		uniqueVulns[rows[i].VulnerabilityID] = struct{}{}
		affectedComponents[rows[i].ComponentID] = struct{}{}
	}
	fmt.Fprintf(w, "- Vulnerability findings: matches=%d unique-vulnerabilities=%d affected-components=%d\n", len(rows), len(uniqueVulns), len(affectedComponents))
	if len(rows) == 0 {
		fmt.Fprintln(w, "- Vulnerability findings: no matched vulnerabilities")
		return
	}

	fmt.Fprintln(w, "\nVulnerability summary (grype-inspired view):")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Name | Installed | Fixed In | Type | Vulnerability | Severity | EPSS | Risk |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for i := range rows {
		anchor := occurrenceAnchorID(rows[i].ComponentID)
		name := escapeMarkdownCell(rows[i].Name)
		if rows[i].ComponentID != "" {
			name = fmt.Sprintf("[%s](#%s)", name, anchor)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			name,
			emptyDash(rows[i].Installed),
			emptyDash(rows[i].FixedIn),
			emptyDash(rows[i].Type),
			rows[i].VulnerabilityID,
			strings.ToUpper(rows[i].Severity),
			formatEPSS(rows[i].EPSS, rows[i].EPSSPercentile),
			formatRisk(rows[i].Risk, rows[i].KEV),
		)
	}
}

// buildVulnerabilitySummaryRows builds the sorted vulnerability rows from the
// grype result, correlating matches to component occurrences by bom-ref.
func buildVulnerabilitySummaryRows(v *vulnscan.Result, occurrences []componentOccurrence) []vulnerabilitySummaryRow {
	if v == nil || len(v.MatchesByBOMRef) == 0 {
		return nil
	}
	byID := map[string]componentOccurrence{}
	for i := range occurrences {
		byID[occurrences[i].ObjectID] = occurrences[i]
	}

	rows := make([]vulnerabilitySummaryRow, 0)
	for compID, matches := range v.MatchesByBOMRef {
		occ := byID[compID]
		for i := range matches {
			name := strings.TrimSpace(matches[i].ArtifactName)
			if name == "" {
				name = strings.TrimSpace(occ.PackageName)
			}
			installed := strings.TrimSpace(matches[i].ArtifactVersion)
			if installed == "" {
				installed = strings.TrimSpace(occ.Version)
			}
			rows = append(rows, vulnerabilitySummaryRow{
				ComponentID:     compID,
				Name:            name,
				Installed:       installed,
				FixedIn:         strings.Join(matches[i].FixVersions, ", "),
				Type:            matches[i].ArtifactType,
				VulnerabilityID: matches[i].VulnerabilityID,
				Severity:        normalizeSeverity(matches[i].Severity),
				EPSS:            matches[i].EPSS,
				EPSSPercentile:  matches[i].EPSSPercentile,
				Risk:            matches[i].Risk,
				KEV:             matches[i].KEV != nil && *matches[i].KEV,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		leftRisk := 0.0
		rightRisk := 0.0
		if rows[i].Risk != nil {
			leftRisk = *rows[i].Risk
		}
		if rows[j].Risk != nil {
			rightRisk = *rows[j].Risk
		}
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}
		if severityRank(rows[i].Severity) != severityRank(rows[j].Severity) {
			return severityRank(rows[i].Severity) < severityRank(rows[j].Severity)
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		if rows[i].VulnerabilityID != rows[j].VulnerabilityID {
			return rows[i].VulnerabilityID < rows[j].VulnerabilityID
		}
		return rows[i].ComponentID < rows[j].ComponentID
	})
	return rows
}

// writeOccurrenceVulnerabilityBlock renders the per-component vulnerability
// detail block within the component occurrence index section.
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
			if m.ArtifactType != "" {
				fmt.Fprintf(w, " type=`%s`", m.ArtifactType)
			}
			if m.Risk != nil {
				fmt.Fprintf(w, " risk=`%s`", formatNumber(*m.Risk))
			}
			if m.KEV != nil && *m.KEV {
				fmt.Fprintf(w, " kev=`yes`")
			}
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
			if m.EPSS != nil {
				fmt.Fprintf(w, "    - EPSS: %s\n", formatEPSS(m.EPSS, m.EPSSPercentile))
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

// normalizeSeverity lowercases and trims raw, returning "unknown" for empty input.
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

// severityRank returns a numeric sort key for raw severity (0=critical … 5=unknown).
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

// emptyDash returns v unchanged, or "-" when v is empty.
func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

// formatEPSS formats EPSS and percentile values as human-readable text.
func formatEPSS(epss *float64, percentile *float64) string {
	if epss == nil {
		return "-"
	}
	p := fmt.Sprintf("%.1f%%", (*epss)*100)
	if percentile == nil {
		return p
	}
	return fmt.Sprintf("%s (%sth)", p, formatNumber((*percentile)*100))
}

// formatRisk formats risk values and appends KEV when flagged.
func formatRisk(risk *float64, kev bool) string {
	if risk == nil {
		if kev {
			return "KEV"
		}
		return "-"
	}
	if kev {
		return fmt.Sprintf("%s KEV", formatNumber(*risk))
	}
	return formatNumber(*risk)
}

// formatNumber renders v with a single decimal place.
func formatNumber(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}
