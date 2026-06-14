package html

import (
	"fmt"
	htmltmpl "html/template"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func buildInputRows(report reportjson.ReportV2, t i18npkg.Bundle) []kv {
	inp := report.Input
	run := report.Run
	rows := []kv{
		{t.Filename, inp.Filename},
		{t.Filesize, fmt.Sprintf("%d %s", inp.Size, t.UnitBytes)},
		{"SHA-256", inp.SHA256},
		{"SHA-512", inp.SHA512},
	}
	if run.RunID != "" {
		rows = append(rows, kv{t.RunIDLabel, run.RunID})
	}
	if run.StartTime != "" {
		rows = append(rows, kv{t.RunStartedLabel, run.StartTime})
	}
	if run.EndTime != "" {
		rows = append(rows, kv{t.RunEndedLabel, run.EndTime})
	}
	if run.Duration != "" {
		rows = append(rows, kv{t.Duration, run.Duration})
	}
	return rows
}

// buildSandbox mirrors the Markdown renderer's three-state sandbox logic. It
// takes the whole report so it can read the package-private sandbox snapshot
// type via its exported field.
func buildSandbox(report reportjson.ReportV2, t i18npkg.Bundle) sandboxSection {
	sb := report.Runtime.Sandbox
	switch {
	case sb.BwrapFound:
		s := sandboxSection{Rows: []kv{
			{t.SandboxName, sb.Name},
			{t.SandboxAvail, fmt.Sprintf("%v", sb.Available)},
			{t.SandboxIsolationLabel, t.SandboxActiveValue},
		}}
		if sb.UnsafeOverride {
			s.Note = i18npkg.RenderInlineHTML(t.SandboxUnsafeIgnoredNote)
		}
		return s
	case sb.UnsafeOverride:
		return sandboxSection{Prose: i18npkg.RenderInlineHTML(t.SandboxNoBwrapUnsafe)}
	default:
		return sandboxSection{Prose: i18npkg.RenderInlineHTML(t.SandboxNoBwrapDenied)}
	}
}

func buildMethod(t i18npkg.Bundle) methodSection {
	docLink := fmt.Sprintf("[SCAN_APPROACH.md](%s)", scanApproachGitHubURL)
	return methodSection{
		Heading: t.MethodOverviewSection,
		Anchor:  anchorMethodOverview,
		Lead:    md(t.MethodLead, docLink),
		Bullets: []htmltmpl.HTML{
			md("%s — %s, %s", t.MethodBulletTwoPhases,
				scanApproachLink(t.LinkTwoPhases, "3-two-mandatory-phases-plus-one-optional-enrichment-phase"),
				scanApproachLink(t.LinkScanDetail, "7-how-the-scan-phase-works-in-detail")),
			i18npkg.RenderInlineHTML(t.MethodBulletEvidence),
			md("%s — %s, %s", t.MethodBulletDedup,
				scanApproachLink(t.LinkDeduplication, "81-how-deduplication-works"),
				scanApproachLink(t.LinkFinalSBOMBuild, "8-how-the-final-sbom-is-built")),
			i18npkg.RenderInlineHTML(t.MethodBulletTrust),
		},
	}
}

func buildProcessing(proj reportjson.ProjectionsV2, t i18npkg.Bundle) processingSection {
	s := processingSection{Heading: t.ProcessingIssuesSection, Anchor: anchorProcessingErrors, EmptyText: t.NoProcessingIssues}

	var extractionIssues []reportjson.ExtractionLogRowV2
	for i := range proj.ExtractionLog {
		switch proj.ExtractionLog[i].Status {
		case "failed", "security-blocked", "tool-missing":
			extractionIssues = append(extractionIssues, proj.ExtractionLog[i])
		}
	}
	if len(proj.Issues) == 0 && len(extractionIssues) == 0 {
		s.Empty = true
		return s
	}
	s.Headers = []string{
		t.ProcessingSourceHeader, t.ProcessingLocationHeader, t.ProcessingClassHeader,
		t.ProcessingStatusHeader, t.ProcessingDetectedHeader, t.ProcessingToolHeader,
		t.ProcessingArchiveTypeHeader, t.ProcessingArchiveMethodHeader,
		t.ProcessingEncryptedHeader, t.ProcessingPhysicalSizeHeader, t.ProcessingDetailHeader,
	}
	for _, issue := range proj.Issues {
		s.Rows = append(s.Rows, []string{
			t.ProcessingPipelineLabel, issue.Stage, t.ProcessingPipelineLabel + "-error",
			"-", "-", "-", "-", "-", "-", "-", issue.Message,
		})
	}
	for i := range extractionIssues {
		row := &extractionIssues[i]
		class := extractionStatusClass(row.Status, row.Detail, t)
		at, am, enc, ps := extractionArchiveCols(row)
		detected := ""
		if row.Depth > 0 {
			detected = fmt.Sprintf("%d", row.Depth)
		}
		s.Rows = append(s.Rows, []string{
			"extraction", row.Path, class, row.ResolutionStatus, detected, row.Tool, at, am, enc, ps, row.Detail,
		})
	}
	return s
}

func buildResidualBullets(proj reportjson.ProjectionsV2, t i18npkg.Bundle) []htmltmpl.HTML {
	idx := proj.Summary.ComponentIndexStats
	var b []htmltmpl.HTML
	add := func(s string) { b = append(b, i18npkg.RenderInlineHTML(s)) }

	add(t.ResidualRiskProfileLead)
	add(t.ResidualRiskAbsenceHint)

	var extFailed, extBlocked, extMissing int
	for i := range proj.ExtractionLog {
		switch proj.ExtractionLog[i].Status {
		case "failed":
			extFailed++
		case "security-blocked":
			extBlocked++
		case "tool-missing":
			extMissing++
		}
	}
	scnErrors := 0
	for _, issue := range proj.Issues {
		if issue.Stage == "scan" {
			scnErrors++
		}
	}

	add(fmt.Sprintf(t.ResidualRiskPURLCoverage, idx.IndexedWithPURL, idx.IndexedComponents, idx.IndexedWithoutPURL))
	add(fmt.Sprintf(t.ResidualRiskEvidenceCoverage, idx.IndexedWithEvidencePath, idx.IndexedWithEvidenceSourceOnly, idx.IndexedWithoutEvidence))
	if len(proj.Summary.ScanNoPackagePaths) > 0 {
		add(fmt.Sprintf(t.ResidualRiskNoComponentTasks, len(proj.Summary.ScanNoPackagePaths), proj.Summary.ScanTasks,
			joinPathExamples(proj.Summary.ScanNoPackagePaths)))
	}
	if idx.FilteredLowValueFileArtifacts > 0 || idx.FilteredContainerNodes > 0 {
		add(fmt.Sprintf(t.ResidualRiskFileArtifactCoverage, idx.FilteredLowValueFileArtifacts+idx.FilteredContainerNodes))
	}
	if len(proj.Summary.ExtensionFilteredPaths) > 0 {
		add(fmt.Sprintf(t.ResidualRiskExtensionFilter, len(proj.Summary.ExtensionFilteredPaths),
			sectionLink(t.ExtensionFilterSection, anchorExtensionFilter)))
	}
	if extFailed > 0 || extBlocked > 0 {
		add(fmt.Sprintf(t.ResidualRiskExtractionGap, extFailed+extBlocked,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "failed", "security-blocked"))))
	}
	if extMissing > 0 {
		add(fmt.Sprintf(t.ResidualRiskToolGap, extMissing,
			joinPathExamples(extractionPathsByStatus(proj.ExtractionLog, "tool-missing"))))
	}
	if scnErrors > 0 {
		add(fmt.Sprintf(t.ResidualRiskScanGap, scnErrors, joinPathExamples(scanIssuePaths(proj.Issues))))
	}
	add(fmt.Sprintf(t.ResidualRiskMoreDetails, scanApproachLink(t.LinkPackageDetectionReliability, "6-package-detection-reliability")))
	return b
}
