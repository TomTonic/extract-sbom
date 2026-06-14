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
	fmt.Fprintf(w, "%s\n", fmt.Sprintf(t.MethodLead, docLink))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s — %s, %s\n",
		t.MethodBulletTwoPhases,
		scanApproachLink(t.LinkTwoPhases, "3-two-mandatory-phases-plus-one-optional-enrichment-phase"),
		scanApproachLink(t.LinkScanDetail, "7-how-the-scan-phase-works-in-detail"))
	fmt.Fprintf(w, "- %s\n", t.MethodBulletEvidence)
	fmt.Fprintf(w, "- %s — %s, %s\n",
		t.MethodBulletDedup,
		scanApproachLink(t.LinkDeduplication, "81-how-deduplication-works"),
		scanApproachLink(t.LinkFinalSBOMBuild, "8-how-the-final-sbom-is-built"))
	fmt.Fprintf(w, "- %s\n", t.MethodBulletTrust)
	fmt.Fprintln(w)
}

// writeSummary renders the executive summary with sub-sections for the analysis
// overview and the vulnerability summary. The overview is the most important
// paragraph of the whole report: it folds the headline facts into flowing prose
// with inline deep links to the sections that substantiate each claim.
func writeSummary(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	if proj.Summary.VulnerabilityRequested {
		fmt.Fprintln(w, t.SummaryLead)
	} else {
		fmt.Fprintln(w, t.SummaryLeadNoVuln)
	}
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.SummaryAnalysisSection, anchorSummaryAnalysis)
	writeAnalysisOverview(w, proj, t)

	writeAnchoredHeading(w, 3, t.SummaryVulnSection, anchorSummaryVuln)
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
	composition := fmt.Sprintf(t.OverviewCompositionTemplate,
		proj.Summary.Nodes,
		anchorExtraction,
		proj.Summary.ArchiveCount,
		proj.Summary.FileCount)
	inventory := fmt.Sprintf(t.OverviewInventoryTemplate,
		anchorSuppression,
		idx.IndexedComponents,
		anchorComponentIndex,
		proj.Summary.PackageGroups)
	purl := fmt.Sprintf(t.OverviewPURLTemplate,
		idx.IndexedWithPURL,
		anchorComponentsWithPURL,
		idx.IndexedWithoutPURL,
		anchorComponentsWithoutPURL)
	fmt.Fprintf(w, "%s %s %s\n\n", composition, inventory, purl)

	// Paragraph 2 — the result narrative (vulnerability outcome + extraction).
	var resultSentences []string
	switch {
	case !proj.Summary.VulnerabilityRequested:
		resultSentences = append(resultSentences, t.FindingVulnNotRequested)
	case proj.Summary.Vulnerabilities > 0:
		resultSentences = append(resultSentences, fmt.Sprintf(t.OverviewVulnMatchesTemplate,
			proj.Summary.Vulnerabilities,
			proj.Summary.AffectedPackageCount,
			proj.Summary.UniqueVulnerabilityCount,
			sectionLink(t.SummaryVulnSection, anchorSummaryVuln)))
	default:
		resultSentences = append(resultSentences, t.OverviewVulnNone)
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
		resultSentences = append(resultSentences, fmt.Sprintf(t.FindingExtractionStatusFailureTemplate, extFailed))
	} else {
		resultSentences = append(resultSentences, t.FindingExtractionStatusSuccessTemplate)
	}
	fmt.Fprintf(w, "%s\n\n", strings.Join(resultSentences, " "))

	// Paragraph 3 — conditional caveats, only emitted when at least one applies.
	var caveats []string
	if extMissing > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingToolMissingTemplate,
			extMissing,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "tool-missing"))))
	}
	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingNoPackageIdentityTemplate,
			len(proj.Summary.ScanNoPackagePaths),
			sectionLink(t.ScanNoPackageIDsSection, anchorScanNoPackageIDs),
			joinPathExamples(proj.Summary.ScanNoPackagePaths)))
	}
	if proj.Summary.PolicyDecisions > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingPolicyDecisionsTemplate,
			proj.Summary.PolicyDecisions,
			sectionLink(t.PolicySection, anchorPolicy)))
	}
	if len(proj.Issues) > 0 {
		caveats = append(caveats, fmt.Sprintf(t.FindingProcessingIssuesTemplate,
			len(proj.Issues),
			sectionLink(t.ProcessingIssuesSection, anchorProcessingErrors)))
	}
	if len(caveats) > 0 {
		fmt.Fprintf(w, "%s\n\n", strings.Join(caveats, " "))
	}

	// Paragraph 4 — methodology pointer.
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.SummaryAnalysisMethodRef, sectionLink(t.MethodOverviewSection, anchorMethodOverview)))
}
