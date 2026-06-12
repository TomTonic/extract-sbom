package markdown

import (
	"fmt"
	"io"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeMethodOverview writes a concise explanation of pipeline method and
// links to the detailed scan-approach document.
func writeMethodOverview(w io.Writer, t translations) {
	fmt.Fprintln(w, t.methodLead)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- %s\n", t.methodBulletTwoPhases)
	fmt.Fprintf(w, "- %s\n", t.methodBulletEvidence)
	fmt.Fprintf(w, "- %s\n", t.methodBulletDedup)
	fmt.Fprintf(w, "- %s\n", t.methodBulletTrust)
	fmt.Fprintln(w)
	fmt.Fprintf(
		w,
		"%s %s, %s, %s, %s, %s\n",
		t.methodMoreDetails,
		scanApproachLink(t.linkTwoPhases, "3-two-phases"),
		scanApproachLink(t.linkScanDetail, "7-how-the-scan-phase-works-in-detail"),
		scanApproachLink(t.linkFinalSBOMBuild, "8-how-the-final-sbom-is-built"),
		scanApproachLink(t.linkDeduplication, "81-how-deduplication-works"),
		scanApproachLink(t.linkPackageDetectionReliability, "6-package-detection-reliability"),
	)
}

// writeSummary renders the executive summary with sub-sections for analysis
// overview, key findings, and vulnerability summary.
func writeSummary(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	if proj.Summary.VulnerabilityRequested {
		fmt.Fprintln(w, t.summaryLead)
	} else {
		fmt.Fprintln(w, t.summaryLeadNoVuln)
	}
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryAnalysisSection, anchorSummaryAnalysis)

	analysis := fmt.Sprintf(t.summaryAnalysisProseTemplate,
		proj.Summary.Nodes,
		proj.Summary.ComponentIndexStats.IndexedComponents,
		proj.Summary.ComponentIndexStats.IndexedWithPURL,
		proj.Summary.ComponentIndexStats.IndexedWithoutPURL)
	fmt.Fprintf(w, "%s\n\n", analysis)
	fmt.Fprintf(w, "%s\n", fmt.Sprintf(t.summaryAnalysisMethodRef, sectionLink(t.methodOverviewSection, anchorMethodOverview)))
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, t.summaryKeyFindingsSection, anchorSummaryKeyFindings)

	foundVulnStr := t.findingVulnNoMatches
	if proj.Summary.Vulnerabilities > 0 {
		foundVulnStr = fmt.Sprintf(t.findingVulnMatchesTemplate,
			proj.Summary.Vulnerabilities,
			proj.Summary.AffectedPackageCount,
			proj.Summary.UniqueVulnerabilityCount,
			sectionLink(t.summaryVulnSection, anchorSummaryVuln))
	}
	fmt.Fprintf(w, "- %s\n\n", foundVulnStr)

	fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingDeliveryCompositionTemplate,
		proj.Summary.ArchiveCount,
		proj.Summary.FileCount,
		proj.Summary.ComponentIndexStats.IndexedComponents,
		proj.Summary.PackageGroups))

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
		fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingExtractionStatusFailureTemplate, extFailed))
	} else {
		fmt.Fprintf(w, "- %s\n\n", t.findingExtractionStatusSuccessTemplate)
	}

	if extMissing > 0 {
		fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingToolMissingTemplate,
			extMissing,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "tool-missing"))))
	}

	idx := proj.Summary.ComponentIndexStats
	fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingPURLCoverageTemplate,
		idx.IndexedWithPURL,
		idx.IndexedComponents,
		anchorComponentsWithPURL,
		idx.IndexedWithoutPURL,
		anchorComponentsWithoutPURL))

	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingNoPackageIdentityTemplate,
			len(proj.Summary.ScanNoPackagePaths),
			sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs),
			joinPathExamples(proj.Summary.ScanNoPackagePaths)))
	}

	if proj.Summary.PolicyDecisions > 0 {
		fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingPolicyDecisionsTemplate,
			proj.Summary.PolicyDecisions,
			sectionLink(t.policySection, anchorPolicy)))
	}

	if len(proj.Issues) > 0 {
		fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingProcessingIssuesTemplate,
			len(proj.Issues),
			sectionLink(t.processingIssuesSection, anchorProcessingErrors)))
	}

	writeAnchoredHeading(w, 3, t.summaryVulnSection, anchorSummaryVuln)
	writeVulnerabilitySummary(w, proj, t)
}
