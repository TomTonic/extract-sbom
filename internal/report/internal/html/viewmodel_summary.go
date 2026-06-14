package html

import (
	"fmt"
	htmltmpl "html/template"
	"strings"

	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func buildHeaderMeta(report reportjson.ReportV2, t i18npkg.Bundle) htmltmpl.HTML {
	gen := report.Generator
	generatedAt := report.Run.EndTime
	if generatedAt == "" {
		generatedAt = gen.Time
	}
	genLink := ""
	if gen.Version != "" {
		genLink = fmt.Sprintf("[%s](https://github.com/TomTonic/extract-sbom/releases/tag/%s)", gen.Version, gen.Version)
	}
	return md(t.ReportHeaderGeneratorVersionTemplate, generatedAt, genLink, emptyDash(gen.Revision))
}

func buildToolsLine(report reportjson.ReportV2, t i18npkg.Bundle) htmltmpl.HTML {
	rt := report.Runtime.ToolVersions
	gp := report.Projections.Summary.GrypeProvenance
	var parts []string
	if rt.SevenZip != "" {
		parts = append(parts, rt.SevenZip)
	}
	if rt.Unshield != "" {
		parts = append(parts, rt.Unshield)
	}
	if rt.Unsquashfs != "" {
		parts = append(parts, rt.Unsquashfs)
	}
	if rt.Grype != "" {
		parts = append(parts, rt.Grype)
	} else if gp.Version != "" {
		parts = append(parts, "grype "+gp.Version)
	}
	line := strings.Join(parts, " | ")
	if gp.DBSchema != "" || gp.DBBuilt != "" || gp.DBUpdated != "" {
		db := fmt.Sprintf(t.VulnGrypeDBTemplate, emptyDash(gp.DBSchema), emptyDash(gp.DBBuilt), emptyDash(gp.DBUpdated))
		if line != "" {
			line += " — " + db
		} else {
			line = db
		}
	}
	if line == "" {
		return ""
	}
	return md("%s %s", t.ReportHeaderToolsLabel, line)
}

// buildAnalysisOverview mirrors markdown.writeAnalysisOverview: same sentences,
// same fmt arguments, same inline links — rendered to HTML paragraphs.
func buildAnalysisOverview(proj reportjson.ProjectionsV2, t i18npkg.Bundle) []htmltmpl.HTML {
	idx := proj.Summary.ComponentIndexStats
	var paras []htmltmpl.HTML

	composition := fmt.Sprintf(t.OverviewCompositionTemplate, proj.Summary.Nodes, anchorExtraction, proj.Summary.ArchiveCount, proj.Summary.FileCount)
	inventory := fmt.Sprintf(t.OverviewInventoryTemplate, anchorSuppression, idx.IndexedComponents, anchorComponentIndex, proj.Summary.PackageGroups)
	purl := fmt.Sprintf(t.OverviewPURLTemplate, idx.IndexedWithPURL, anchorComponentsWithPURL, idx.IndexedWithoutPURL, anchorComponentsWithoutPURL)
	paras = append(paras, i18npkg.RenderInlineHTML(composition+" "+inventory+" "+purl))

	var result []string
	switch {
	case !proj.Summary.VulnerabilityRequested:
		result = append(result, t.FindingVulnNotRequested)
	case proj.Summary.Vulnerabilities > 0:
		result = append(result, fmt.Sprintf(t.OverviewVulnMatchesTemplate,
			proj.Summary.Vulnerabilities, proj.Summary.AffectedPackageCount, proj.Summary.UniqueVulnerabilityCount,
			sectionLink(t.SummaryVulnSection, anchorSummaryVuln)))
	default:
		result = append(result, t.OverviewVulnNone)
	}
	extFailed, extMissing := countExtractionStatuses(proj.ExtractionLog)
	if extFailed > 0 {
		result = append(result, fmt.Sprintf(t.FindingExtractionStatusFailureTemplate, extFailed))
	} else {
		result = append(result, t.FindingExtractionStatusSuccessTemplate)
	}
	paras = append(paras, i18npkg.RenderInlineHTML(strings.Join(result, " ")))

	var caveats []string
	if extMissing > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingToolMissingTemplate, extMissing,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "tool-missing"))))
	}
	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingNoPackageIdentityTemplate, len(proj.Summary.ScanNoPackagePaths),
			sectionLink(t.ScanNoPackageIDsSection, anchorScanNoPackageIDs), joinPathExamples(proj.Summary.ScanNoPackagePaths)))
	}
	if proj.Summary.PolicyDecisions > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingPolicyDecisionsTemplate, proj.Summary.PolicyDecisions,
			sectionLink(t.PolicySection, anchorPolicy)))
	}
	if len(proj.Issues) > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingProcessingIssuesTemplate, len(proj.Issues),
			sectionLink(t.ProcessingIssuesSection, anchorProcessingErrors)))
	}
	if len(caveats) > 0 {
		paras = append(paras, i18npkg.RenderInlineHTML(strings.Join(caveats, " ")))
	}

	paras = append(paras, md(t.SummaryAnalysisMethodRef, sectionLink(t.MethodOverviewSection, anchorMethodOverview)))
	return paras
}

func buildVulnSection(proj reportjson.ProjectionsV2, t i18npkg.Bundle) vulnSection {
	v := vulnSection{
		Heading:   t.SummaryVulnSection,
		Anchor:    anchorSummaryVuln,
		Requested: proj.Summary.VulnerabilityRequested,
	}
	if !v.Requested {
		v.SummaryLine = t.VulnEnrichmentNotRequested
		return v
	}
	v.StateLine = md(t.VulnEnrichmentStateTemplate, proj.Summary.VulnerabilityEnrichmentState)
	if len(proj.Vulnerabilities) == 0 {
		v.FindingLine = i18npkg.RenderInlineHTML(t.VulnNoMatchedFindings)
	} else {
		v.FindingLine = md(t.VulnFindingsTemplate,
			len(proj.Vulnerabilities), proj.Summary.UniqueVulnerabilityCount, proj.Summary.AffectedPackageCount)
	}
	v.Headers = []string{
		t.VulnTableVulnerability, t.VulnTableSeverity, t.VulnTableName, t.VulnTableInstalled,
		t.VulnTableFixedIn, t.VulnTableEPSS, t.VulnTableRisk, t.VulnTableKEV, t.VulnTableDescription,
	}
	for i := range proj.Vulnerabilities {
		row := &proj.Vulnerabilities[i]
		v.Rows = append(v.Rows, vulnRow{
			ID:           row.VulnerabilityID,
			Severity:     formatSeverity(row.Severity, row.CVSSScore),
			SeverityCSS:  severityCSSClass(domain.NormalizeSeverity(row.Severity)),
			SeverityRank: severitySortRank(domain.NormalizeSeverity(row.Severity)),
			Name:         emptyDash(row.Name),
			NameAnchor:   row.PackageAnchorID,
			Installed:    emptyDash(row.Installed),
			FixedIn:      emptyDash(row.FixedIn),
			EPSS:         formatEPSS(row.EPSS, row.EPSSPercentile),
			Risk:         formatRisk(row.Risk),
			KEV:          formatKEV(row.KEV, t),
			Description:  truncateText(row.Description, vulnDescriptionMaxRunes),
		})
	}
	return v
}
