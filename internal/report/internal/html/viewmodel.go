package html

import (
	"fmt"
	htmltmpl "html/template"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// buildPage assembles the complete HTML report view model from the report
// snapshot. It mirrors the Markdown renderer's content (sharing the i18n
// catalog) while organizing it for HTML presentation.
func buildPage(data ReportData, language string) page {
	report := reportjson.BuildV2Report(data)
	proj := report.Projections
	t := i18npkg.For(language)

	p := page{
		Lang:       language,
		Title:      t.Title,
		Meta:       buildHeaderMeta(report, t),
		Tools:      buildToolsLine(report, t),
		TOCHeading: t.TableOfContentsSection,
		EndNote:    t.EndOfReport,

		SummaryHeading:  t.SummarySection,
		SummaryAnchor:   anchorSummary,
		AnalysisHeading: t.SummaryAnalysisSection,
		AnalysisAnchor:  anchorSummaryAnalysis,

		RunScopeHeading: t.RunScopeSection,
		RunScopeAnchor:  anchorRunScope,
		RunScopeLead:    t.RunScopeLead,
		InputHeading:    t.InputSection,
		InputAnchor:     anchorInputFile,
		ConfigHeading:   t.ConfigSection,
		ConfigAnchor:    anchorConfig,
		SandboxHeading:  t.SandboxSection,
		SandboxAnchor:   anchorSandbox,

		ResidualHeading: t.ResidualRiskSection,
		ResidualAnchor:  anchorResidualRisk,
		ResidualText:    t.ResidualRiskText,

		AppendixHeading: t.AppendixSection,
		AppendixAnchor:  anchorAppendix,
		AppendixLead:    t.AppendixLead,
	}

	if proj.Summary.VulnerabilityRequested {
		p.SummaryLead = i18npkg.RenderInlineHTML(t.SummaryLead)
	} else {
		p.SummaryLead = i18npkg.RenderInlineHTML(t.SummaryLeadNoVuln)
	}

	p.AnalysisParas = buildAnalysisOverview(proj, t)
	p.Vuln = buildVulnSection(proj, t)
	p.InputRows = buildInputRows(report, t)
	p.ConfigRows = buildConfigRows(report, t)
	p.Sandbox = buildSandbox(report, t)
	p.Method = buildMethod(t)
	p.Processing = buildProcessing(proj, t)
	p.ResidualBullets = buildResidualBullets(proj, t)
	p.ComponentIndex = buildComponentIndex(proj, t)
	p.Normalization = buildNormalization(proj.SuppressionGroups, t)
	p.ExtensionFilter = buildExtensionFilter(report.Config.SkipExtensions, proj, t)
	p.RootMetadata = buildRootMetadata(proj.Summary.RootComponent, t)
	p.Policy = buildPolicy(proj.PolicyDecisions, t)
	p.ScanLog = buildScanLog(proj, t)
	p.Extraction = buildExtraction(proj.ExtractionLog, t)
	p.TOC = buildTOC(t)

	return p
}

// md renders a printf-formatted Markdown fragment as inline HTML.
func md(format string, args ...any) htmltmpl.HTML {
	return i18npkg.RenderInlineHTML(fmt.Sprintf(format, args...))
}

// sectionLink and scanApproachLink mirror the Markdown helpers so the shared
// prose templates compose identically before inline-HTML conversion.
func sectionLink(title, anchor string) string {
	return fmt.Sprintf("[%s](#%s)", title, anchor)
}

func scanApproachLink(label, frag string) string {
	return fmt.Sprintf("[%s](%s#%s)", label, scanApproachGitHubURL, frag)
}

func buildTOC(t i18npkg.Bundle) []tocItem {
	return []tocItem{
		{t.SummarySection, anchorSummary, 0},
		{t.SummaryAnalysisSection, anchorSummaryAnalysis, 1},
		{t.SummaryVulnSection, anchorSummaryVuln, 1},
		{t.RunScopeSection, anchorRunScope, 0},
		{t.InputSection, anchorInputFile, 1},
		{t.ConfigSection, anchorConfig, 1},
		{t.SandboxSection, anchorSandbox, 1},
		{t.MethodOverviewSection, anchorMethodOverview, 0},
		{t.ProcessingIssuesSection, anchorProcessingErrors, 0},
		{t.ResidualRiskSection, anchorResidualRisk, 0},
		{t.AppendixSection, anchorAppendix, 0},
		{t.ComponentIndexSection, anchorComponentIndex, 1},
		{t.ComponentIndexWithPURLSubsection, anchorComponentsWithPURL, 2},
		{t.ComponentIndexWithoutPURLSubsection, anchorComponentsWithoutPURL, 2},
		{t.ComponentNormalizationSection, anchorSuppression, 1},
		{t.SuppressionReasonFSArtifact, anchorSuppressionFS, 2},
		{t.SuppressionReasonLowValueFile, anchorSuppressionLowValue, 2},
		{t.SuppressionReasonWeakDuplicate, anchorSuppressionWeakDups, 2},
		{t.SuppressionReasonPURLDuplicate, anchorSuppressionPURLDups, 2},
		{t.ExtensionFilterSection, anchorExtensionFilter, 1},
		{t.RootMetadataSection, anchorRootMetadata, 1},
		{t.PolicySection, anchorPolicy, 1},
		{t.ScanSection, anchorScan, 1},
		{t.ScanNoPackageIDsSection, anchorScanNoPackageIDs, 1},
		{t.ExtractionSection, anchorExtraction, 1},
	}
}
