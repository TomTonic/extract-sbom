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
func writeSummary(w io.Writer, data ReportData, proj reportjson.ProjectionsV2, t translations) {
        if data.Vulnerabilities != nil && data.Vulnerabilities.Requested {
                fmt.Fprintln(w, t.summaryLead)
        } else {
                fmt.Fprintln(w, t.summaryLeadNoVuln)
        }
        fmt.Fprintln(w)

        writeAnchoredHeading(w, 3, t.summaryAnalysisSection, anchorSummaryAnalysis)
        
        analysis := fmt.Sprintf(t.summaryAnalysisProseTemplate, proj.Summary.Nodes, proj.Summary.ScanTasks, proj.Summary.ComponentIndexStats.IndexedComponents, proj.Summary.PackageGroups)
        fmt.Fprintf(w, "%s\n\n", analysis)
        fmt.Fprintf(w, "%s\n", fmt.Sprintf(t.summaryAnalysisMethodRef, sectionLink(t.methodOverviewSection, anchorMethodOverview)))
        fmt.Fprintln(w)

        writeAnchoredHeading(w, 3, t.summaryKeyFindingsSection, anchorSummaryKeyFindings)
        
        foundVulnStr := t.findingVulnNoMatches
        if proj.Summary.Vulnerabilities > 0 { foundVulnStr = fmt.Sprintf(t.findingVulnMatchesTemplate, proj.Summary.Vulnerabilities, sectionLink(t.summaryVulnSection, anchorSummaryVuln)) }
        fmt.Fprintf(w, "- %s\n\n", foundVulnStr)
        
        fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingDeliveryCompositionTemplate, proj.Summary.PackageGroups, proj.Summary.ComponentIndexStats.IndexedComponents))
        
        var extFailed, extMissing int
        for _, r := range proj.ExtractionLog {
        	if r.Status == "failed" || r.Status == "blocked" { extFailed++ }
        	if r.Status == "tool_missing" { extMissing++ }
        }
        if extFailed > 0 { fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingExtractionStatusFailureTemplate, extFailed)) } else { fmt.Fprintf(w, "- %s\n\n", t.findingExtractionStatusSuccessTemplate) }
        
        if extMissing > 0 { fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingToolMissingTemplate, extMissing)) }
        
        idx := proj.Summary.ComponentIndexStats
        val := t.noneValue
        if idx.IndexedComponents > 0 { val = fmt.Sprintf("%d", idx.IndexedWithPURL) }
        fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingPURLCoverageTemplate, anchorComponentsWithPURL, val))
        
        if len(proj.Summary.ScanNoPackagePaths) > 0 { fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingNoPackageIdentityTemplate, sectionLink(t.scanNoPackageIDsSection, anchorScanNoPackageIDs), len(proj.Summary.ScanNoPackagePaths))) }
        
        if proj.Summary.PolicyDecisions > 0 { fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingPolicyDecisionsTemplate, sectionLink(t.policySection, anchorPolicy), proj.Summary.PolicyDecisions)) }
        
        if len(proj.Issues) > 0 { fmt.Fprintf(w, "- %s\n\n", fmt.Sprintf(t.findingProcessingIssuesTemplate, sectionLink(t.processingIssuesSection, anchorProcessingErrors), len(proj.Issues))) }

        writeAnchoredHeading(w, 3, t.summaryVulnSection, anchorSummaryVuln)
        writeVulnerabilitySummary(w, data, proj, t)
}