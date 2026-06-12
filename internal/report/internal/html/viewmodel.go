package html

import (
	"strings"
	"time"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func buildReportData(data ReportData, language string) htmlReportData {
	report := reportjson.BuildV2Report(data)
	proj := report.Projections

	var total, extracted, failed, skipped int
	for _, row := range proj.ExtractionLog {
		total++
		switch row.Status {
		case "extracted", "syft-native":
			extracted++
		case "failed", "security-blocked":
			failed++
		case "skipped", "tool-missing":
			skipped++
		}
	}

	vulns := buildHTMLVulnRows(proj.Vulnerabilities)

	issues := make([]htmlIssue, len(proj.Issues))
	for i, iss := range proj.Issues {
		issues[i] = htmlIssue{Stage: iss.Stage, Message: iss.Message}
	}

	nodes := buildHTMLExtrNodes(proj.ExtractionLog)

	return htmlReportData{
		M:                   messagesFor(language),
		Generated:           time.Now().Format("2006-01-02 15:04:05"),
		Generator:           report.Generator.Display,
		Tools:               buildHTMLToolVersions(report),
		InputFile:           report.Input.Filename,
		InputSize:           report.Input.Size,
		InputSHA256:         report.Input.SHA256,
		Duration:            report.Run.Duration,
		SBOMPath:            report.Raw.ArtifactPaths.SBOMPath,
		SandboxName:         report.Runtime.Sandbox.Name,
		Language:            language,
		ExtractionTotal:     total,
		ExtractionExtracted: extracted,
		ExtractionFailed:    failed,
		ExtractionSkipped:   skipped,
		ComponentCount:      proj.Summary.Components,
		VulnCount:           len(vulns),
		IssueCount:          len(issues),
		VulnState:           proj.Summary.VulnerabilityEnrichmentState,
		Vulns:               vulns,
		Issues:              issues,
		ExtrNodes:           nodes,
	}
}

func buildHTMLVulnRows(rows []reportjson.VulnerabilityRowV2) []htmlVuln {
	out := make([]htmlVuln, 0, len(rows))
	for _, row := range rows {
		desc := row.Description
		if len([]rune(desc)) > 120 {
			desc = string([]rune(desc)[:120]) + "…"
		}
		out = append(out, htmlVuln{
			ID:          row.VulnerabilityID,
			Severity:    row.Severity,
			SeverityCSS: severityCSSClass(row.Severity),
			Package:     row.Name,
			Version:     row.Installed,
			Description: desc,
		})
	}
	return out
}

func buildHTMLExtrNodes(rows []reportjson.ExtractionLogRowV2) []htmlNode {
	out := make([]htmlNode, 0, len(rows))
	for _, row := range rows {
		depth := row.Depth
		if depth > 5 {
			depth = 5
		}
		out = append(out, htmlNode{
			Depth:  depth,
			Path:   row.Path,
			Status: row.Status,
			Format: row.Format,
			Tool:   row.Tool,
			Detail: row.Detail,
		})
	}
	return out
}

func buildHTMLToolVersions(report reportjson.ReportV2) string {
	tv := report.Runtime.ToolVersions
	var parts []string
	if tv.Grype != "" {
		entry := tv.Grype
		if tv.GrypeDB != "" {
			entry += " (" + tv.GrypeDB + ")"
		}
		parts = append(parts, entry)
	}
	if tv.SevenZip != "" {
		parts = append(parts, tv.SevenZip)
	}
	if tv.Unshield != "" {
		parts = append(parts, tv.Unshield)
	}
	if tv.Unsquashfs != "" {
		parts = append(parts, tv.Unsquashfs)
	}
	return strings.Join(parts, " | ")
}

func severityCSSClass(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown-sev"
	}
}
