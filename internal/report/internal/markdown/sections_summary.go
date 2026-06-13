package markdown

import (
	"fmt"
	"io"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeMethodOverview writes a concise explanation of pipeline method.
// The lead paragraph links to the full SCAN_APPROACH.md document; individual
// deep links are embedded inline in the relevant bullets.
func writeMethodOverview(w io.Writer, t translations) {
	docLink := fmt.Sprintf("[SCAN_APPROACH.md](%s)", scanApproachGitHubURL)
	fmt.Fprintf(w, "%s\n", fmt.Sprintf(t.methodLead, docLink))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s — %s, %s\n",
		t.methodBulletTwoPhases,
		scanApproachLink(t.linkTwoPhases, "3-two-phases"),
		scanApproachLink(t.linkScanDetail, "7-how-the-scan-phase-works-in-detail"))
	fmt.Fprintf(w, "- %s\n", t.methodBulletEvidence)
	fmt.Fprintf(w, "- %s — %s, %s\n",
		t.methodBulletDedup,
		scanApproachLink(t.linkDeduplication, "81-how-deduplication-works"),
		scanApproachLink(t.linkFinalSBOMBuild, "8-how-the-final-sbom-is-built"))
	fmt.Fprintf(w, "- %s\n", t.methodBulletTrust)
	fmt.Fprintln(w)
}

// writeSummary renders the executive summary with sub-sections for the analysis
// overview and the vulnerability summary. The overview is the most important
// paragraph of the whole report: it folds the headline facts into flowing prose
// with inline deep links to the sections that substantiate each claim.
func writeSummary(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	if proj.Summary.VulnerabilityRequested {
		fmt.Fprintln(w, t.summaryLead)
	} else {
		fmt.Fprintln(w, t.summaryLeadNoVuln)
	}
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryAnalysisSection, anchorSummaryAnalysis)
	writeAnalysisOverview(w, proj, t)

	writeAnchoredHeading(w, 3, t.summaryVulnSection, anchorSummaryVuln)
	writeVulnerabilitySummary(w, proj, t)
}

// writeAnalysisOverview renders the headline narrative as flowing prose. It is
// composed of four paragraphs:
//
//  1. Inventory: what was examined, what survived normalization, and PURL
//     coverage — each fact carrying an inline deep link to its evidence section.
//  2. Result: the vulnerability-scan outcome and the extraction status.
//  3. Caveats: any conditional limitations (missing tools, unidentified
//     content, policy decisions, processing issues), only when present.
//  4. Method reference: a pointer to the methodology section.
func writeAnalysisOverview(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	idx := proj.Summary.ComponentIndexStats

	// Paragraph 1 — the inventory narrative (the most important paragraph).
	composition := fmt.Sprintf(t.overviewCompositionTemplate,
		proj.Summary.Nodes,
		anchorExtraction,
		proj.Summary.ArchiveCount,
		proj.Summary.FileCount)
	inventory := fmt.Sprintf(t.overviewInventoryTemplate,
		anchorSuppression,
		idx.IndexedComponents,
		anchorComponentIndex,
		proj.Summary.PackageGroups)
	purl := fmt.Sprintf(t.overviewPURLTemplate,
		idx.IndexedWithPURL,
		anchorComponentsWithPURL,
		idx.IndexedWithoutPURL,
		anchorComponentsWithoutPURL)
	fmt.Fprintf(w, "%s %s %s\n\n", composition, inventory, purl)

	// Paragraph 2 — the result narrative (vulnerability outcome + extraction).
	var resultSentences []string
	switch {
	case !proj.Summary.VulnerabilityRequested:
		resultSentences = append(resultSentences, t.findingVulnNotRequested)
	case proj.Summary.Vulnerabilities > 0:
		resultSentences = append(resultSentences, fmt.Sprintf(t.overviewVulnMatchesTemplate,
			proj.Summary.Vulnerabilities,
			proj.Summary.AffectedPackageCount,
			proj.Summary.UniqueVulnerabilityCount,
			sectionLink(t.summaryVulnSection, anchorSummaryVuln)))
	default:
		resultSentences = append(resultSentences, t.overviewVulnNone)
	}

	var extFailed, extMissing int
	for i := range proj.ExtractionLog {
		switch proj.ExtractionLog[i].Status {
		case "failed", "security-blocked":
			extFailed++
		case "tool-missing":
			extMissing++
		}
	}
	if extFailed > 0 {
		resultSentences = append(resultSentences, fmt.Sprintf(t.findingExtractionStatusFailureTemplate, extFailed))
	} else {
		resultSentences = append(resultSentences, t.findingExtractionStatusSuccessTemplate)
	}
	fmt.Fprintf(w, "%s\n\n", strings.Join(resultSentences, " "))

	// Paragraph 3 — conditional caveats, only emitted when at least one applies.
	var caveats []string
	if extMissing > 0 {
		caveats = append(caveats, fmt.Sprintf(t.findingToolMissingTemplate,
			extMissing,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "tool-missing"))))
	}
	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		caveats = append(caveats, fmt.Sprintf(t.findingNoPackageIdentityTemplate,
			len(proj.Summary.ScanNoPackagePaths),
			sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs),
			joinPathExamples(proj.Summary.ScanNoPackagePaths)))
	}
	if proj.Summary.PolicyDecisions > 0 {
		caveats = append(caveats, fmt.Sprintf(t.findingPolicyDecisionsTemplate,
			proj.Summary.PolicyDecisions,
			sectionLink(t.policySection, anchorPolicy)))
	}
	if len(proj.Issues) > 0 {
		caveats = append(caveats, fmt.Sprintf(t.findingProcessingIssuesTemplate,
			len(proj.Issues),
			sectionLink(t.processingIssuesSection, anchorProcessingErrors)))
	}
	if len(caveats) > 0 {
		fmt.Fprintf(w, "%s\n\n", strings.Join(caveats, " "))
	}

	// Paragraph 4 — methodology pointer.
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.summaryAnalysisMethodRef, sectionLink(t.methodOverviewSection, anchorMethodOverview)))
}
