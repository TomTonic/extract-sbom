package report

import (
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

func buildHTMLReportData(data ReportData, language string) htmlReportData {
	extStats := collectExtractionStats(data.Tree)

	compCount := 0
	if data.BOM != nil && data.BOM.Components != nil {
		compCount = len(*data.BOM.Components)
	}

	vulns := collectHTMLVulns(data)

	var issues []htmlIssue
	for _, iss := range data.ProcessingIssues {
		issues = append(issues, htmlIssue(iss))
	}

	var nodes []htmlNode
	flattenExtractionNodes(data.Tree, 0, &nodes)

	return htmlReportData{
		M:                   htmlMessagesFor(language),
		Generated:           time.Now().Format("2006-01-02 15:04:05"),
		Generator:           data.Generator.String(),
		Tools:               htmlToolVersions(data.ToolVersions),
		InputFile:           data.Input.Filename,
		InputSize:           data.Input.Size,
		InputSHA256:         data.Input.SHA256,
		Duration:            data.EndTime.Sub(data.StartTime).Round(time.Millisecond).String(),
		SBOMPath:            data.SBOMPath,
		SandboxName:         data.SandboxInfo.Name,
		Language:            language,
		ExtractionTotal:     extStats.Total,
		ExtractionExtracted: extStats.Extracted,
		ExtractionFailed:    extStats.Failed,
		ExtractionSkipped:   extStats.Skipped + extStats.ToolMissing,
		ComponentCount:      compCount,
		VulnCount:           len(vulns),
		IssueCount:          len(issues),
		VulnState:           htmlVulnState(data.Vulnerabilities),
		Vulns:               vulns,
		Issues:              issues,
		ExtrNodes:           nodes,
	}
}

type extractionStats struct {
	Total            int
	Extracted        int
	Failed           int
	Skipped          int
	ToolMissing      int
	SecurityBlocked  int
	Pending          int
	SyftNative       int
	Other            int
	TotalFileEntries int
}

func collectExtractionStats(node *extract.ExtractionNode) extractionStats {
	stats := extractionStats{}

	var walk func(n *extract.ExtractionNode)
	walk = func(n *extract.ExtractionNode) {
		if n == nil {
			return
		}

		stats.Total++
		switch n.Status {
		case extract.StatusExtracted:
			stats.Extracted++
			stats.TotalFileEntries += n.EntriesCount
		case extract.StatusSyftNative:
			stats.SyftNative++
		case extract.StatusFailed:
			stats.Failed++
		case extract.StatusSkipped:
			stats.Skipped++
		case extract.StatusToolMissing:
			stats.ToolMissing++
		case extract.StatusSecurityBlocked:
			stats.SecurityBlocked++
		case extract.StatusPending:
			stats.Pending++
		default:
			stats.Other++
		}

		for _, child := range n.Children {
			walk(child)
		}
	}

	walk(node)
	return stats
}

// htmlVulnState classifies the vulnerability-enrichment outcome for the HTML
// summary. It exists so the report can distinguish "no vulnerabilities found"
// from "enrichment was not requested" or "Grype was unavailable" — the same
// audit distinction the Markdown report preserves. A plain "0" would conflate
// all three. Returns one of "not-requested", "unavailable", or "assessed".
func htmlVulnState(v *vulnscan.Result) string {
	if v == nil || !v.Requested || v.State == vulnscan.StateNotRequested {
		return "not-requested"
	}
	if v.State == vulnscan.StateUnavailable {
		return "unavailable"
	}
	return "assessed"
}

// htmlToolVersions joins the detected external-tool version strings into a
// single " | "-separated line for the summary table. An empty result means no
// external tool reported a version during this run.
func htmlToolVersions(tv ToolVersions) string {
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
