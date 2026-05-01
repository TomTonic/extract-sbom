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
	VulnerabilityID string
	Severity        string
	CVSSScore       *float64
	CVSSVersion     string
	CVSSVector      string
	Description     string
	EPSS            *float64
	EPSSPercentile  *float64
	Risk            *float64
	KEV             bool
}

// writeVulnerabilitySummary renders the vulnerability enrichment section to w,
// including state, grype version, and a per-severity summary table.
func writeVulnerabilitySummary(w io.Writer, data ReportData, occurrences []componentOccurrence, t translations) {
	if data.Vulnerabilities == nil {
		fmt.Fprintf(w, "- %s\n", t.vulnEnrichmentNotRequested)
		return
	}

	v := data.Vulnerabilities
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnEnrichmentStateTemplate, v.State))
	if v.GrypeVersion != "" {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnGrypeVersionTemplate, v.GrypeVersion))
	}
	if v.DBSchemaVersion != "" || v.DBBuilt != "" || v.DBUpdated != "" {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnGrypeDBTemplate, emptyDash(v.DBSchemaVersion), emptyDash(v.DBBuilt), emptyDash(v.DBUpdated)))
	}
	if len(v.Errors) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnEnrichmentIssuesTemplate, len(v.Errors)))
	}

	rows := buildVulnerabilitySummaryRows(v, occurrences)
	uniqueVulns := map[string]struct{}{}
	affectedComponents := map[string]struct{}{}
	for i := range rows {
		uniqueVulns[rows[i].VulnerabilityID] = struct{}{}
		affectedComponents[rows[i].ComponentID] = struct{}{}
	}
	fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnFindingsTemplate, len(rows), len(uniqueVulns), len(affectedComponents)))
	if len(rows) == 0 {
		fmt.Fprintf(w, "- %s\n", t.vulnNoMatchedFindings)
		return
	}

	fmt.Fprintf(w, "\n%s\n", t.vulnSummaryHeading)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
		t.vulnTableName,
		t.vulnTableInstalled,
		t.vulnTableFixedIn,
		t.vulnTableVulnerability,
		t.vulnTableSeverity,
		t.vulnTableEPSS,
		t.vulnTableRisk,
		t.vulnTableKEV,
	)
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
			rows[i].VulnerabilityID,
			formatSeverity(rows[i].Severity, rows[i].CVSSScore),
			formatEPSS(rows[i].EPSS, rows[i].EPSSPercentile),
			formatRisk(rows[i].Risk),
			formatKEV(rows[i].KEV, t),
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
	seen := map[string]struct{}{}
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
			key := strings.Join([]string{
				compID,
				name,
				installed,
				strings.TrimSpace(matches[i].VulnerabilityID),
				normalizeSeverity(matches[i].Severity),
				strings.Join(matches[i].FixVersions, ", "),
			}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			rows = append(rows, vulnerabilitySummaryRow{
				ComponentID:     compID,
				Name:            name,
				Installed:       installed,
				FixedIn:         strings.Join(matches[i].FixVersions, ", "),
				VulnerabilityID: matches[i].VulnerabilityID,
				Severity:        normalizeSeverity(matches[i].Severity),
				CVSSScore:       matches[i].CVSSScore,
				CVSSVersion:     matches[i].CVSSVersion,
				CVSSVector:      matches[i].CVSSVector,
				Description:     matches[i].Description,
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
		if rows[i].KEV != rows[j].KEV {
			return rows[i].KEV
		}
		leftEPSSPct := 0.0
		rightEPSSPct := 0.0
		if rows[i].EPSSPercentile != nil {
			leftEPSSPct = *rows[i].EPSSPercentile
		}
		if rows[j].EPSSPercentile != nil {
			rightEPSSPct = *rows[j].EPSSPercentile
		}
		if leftEPSSPct != rightEPSSPct {
			return leftEPSSPct > rightEPSSPct
		}
		leftEPSS := 0.0
		rightEPSS := 0.0
		if rows[i].EPSS != nil {
			leftEPSS = *rows[i].EPSS
		}
		if rows[j].EPSS != nil {
			rightEPSS = *rows[j].EPSS
		}
		if leftEPSS != rightEPSS {
			return leftEPSS > rightEPSS
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
func writeOccurrenceVulnerabilityBlock(w io.Writer, occ componentOccurrence, v *vulnscan.Result, t translations) {
	if v == nil || v.State == vulnscan.StateNotRequested {
		return
	}
	matches := v.MatchesByBOMRef[occ.ObjectID]
	if len(matches) > 0 {
		fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnStatusFoundTemplate, len(matches)))
		for i := range matches {
			m := matches[i]
			fmt.Fprintf(w, "  - `%s` (%s)", m.VulnerabilityID, strings.ToUpper(normalizeSeverity(m.Severity)))
			if m.ArtifactType != "" {
				fmt.Fprintf(w, " type=`%s`", m.ArtifactType)
			}
			if m.Risk != nil {
				fmt.Fprintf(w, " risk=`%s`", formatNumber(*m.Risk))
			}
			fmt.Fprintf(w, " kev=`%s`", formatKEV(m.KEV != nil && *m.KEV, t))
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
				fmt.Fprintf(w, "    - %s\n", fmt.Sprintf(t.vulnDetailSourceTemplate, m.DataSource))
			}
			if m.FixState != "" || len(m.FixVersions) > 0 {
				fmt.Fprintf(w, "    - %s\n", fmt.Sprintf(t.vulnDetailFixTemplate, emptyDash(m.FixState), strings.Join(m.FixVersions, ", ")))
			}
			if m.CVSSVector != "" || m.CVSSVersion != "" || m.CVSSScore != nil {
				fmt.Fprintf(w, "    - %s\n", fmt.Sprintf(t.vulnDetailCVSSTemplate, emptyDash(m.CVSSVersion), formatRisk(m.CVSSScore), emptyDash(m.CVSSVector)))
			} else {
				fmt.Fprintf(w, "    - %s\n", t.vulnDetailCVSSNone)
			}
			if strings.TrimSpace(m.Description) != "" {
				fmt.Fprintf(w, "    - %s\n", fmt.Sprintf(t.vulnDetailDescriptionTemplate, strings.TrimSpace(m.Description)))
			} else {
				fmt.Fprintf(w, "    - %s\n", t.vulnDetailDescriptionNone)
			}
			if m.EPSS != nil {
				fmt.Fprintf(w, "    - %s\n", fmt.Sprintf(t.vulnDetailEPSSTemplate, formatEPSS(m.EPSS, m.EPSSPercentile)))
			}
			for _, u := range m.URLs {
				fmt.Fprintf(w, "    - %s\n", fmt.Sprintf(t.vulnDetailReferenceTemplate, u))
			}
		}
		return
	}

	if v.State == vulnscan.StateUnavailable || v.State == vulnscan.StateCompletedWithErrors {
		fmt.Fprintf(w, "- %s\n", t.vulnStatusNotAssessableUnavailable)
		return
	}
	if occ.PURL == "" && occ.CPE == "" {
		fmt.Fprintf(w, "- %s\n", t.vulnStatusNotAssessableNoID)
		return
	}
	fmt.Fprintf(w, "- %s\n", t.vulnStatusNone)
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
	return fmt.Sprintf("%s (%s)", p, formatPercentileRank((*percentile)*100))
}

// formatRisk formats risk values.
func formatRisk(risk *float64) string {
	if risk == nil {
		return "-"
	}
	return formatNumber(*risk)
}

// formatKEV formats the KEV indicator used by grype-like output.
func formatKEV(kev bool, t translations) string {
	if kev {
		return t.vulnKEVYes
	}
	return t.vulnKEVNo
}

// formatNumber renders v with a single decimal place.
func formatNumber(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// formatSeverity renders severity and appends CVSS score in parentheses.
func formatSeverity(severity string, cvss *float64) string {
	if cvss == nil {
		return strings.ToUpper(normalizeSeverity(severity))
	}
	return fmt.Sprintf("%s (%s)", strings.ToUpper(normalizeSeverity(severity)), formatNumber(*cvss))
}

// formatPercentileRank renders percentile values as ordinal ranks, e.g. 99th.
func formatPercentileRank(pct float64) string {
	whole := int(pct + 0.5)
	if whole <= 0 {
		return "0th"
	}
	if whole%100 >= 11 && whole%100 <= 13 {
		return fmt.Sprintf("%dth", whole)
	}
	switch whole % 10 {
	case 1:
		return fmt.Sprintf("%dst", whole)
	case 2:
		return fmt.Sprintf("%dnd", whole)
	case 3:
		return fmt.Sprintf("%drd", whole)
	default:
		return fmt.Sprintf("%dth", whole)
	}
}
