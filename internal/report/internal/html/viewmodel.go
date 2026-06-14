package html

import (
	"fmt"
	htmltmpl "html/template"
	"sort"
	"strings"

	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
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
			ID:          row.VulnerabilityID,
			Severity:    formatSeverity(row.Severity, row.CVSSScore),
			SeverityCSS: severityCSSClass(domain.NormalizeSeverity(row.Severity)),
			Name:        emptyDash(row.Name),
			NameAnchor:  row.PackageAnchorID,
			Installed:   emptyDash(row.Installed),
			FixedIn:     emptyDash(row.FixedIn),
			EPSS:        formatEPSS(row.EPSS, row.EPSSPercentile),
			Risk:        formatRisk(row.Risk),
			KEV:         formatKEV(row.KEV, t),
			Description: truncateText(row.Description, vulnDescriptionMaxRunes),
		})
	}
	return v
}

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

func buildComponentIndex(proj reportjson.ProjectionsV2, t i18npkg.Bundle) componentIndexSection {
	s := componentIndexSection{
		Heading:           t.ComponentIndexSection,
		Anchor:            anchorComponentIndex,
		Lead:              i18npkg.RenderInlineHTML(t.ComponentIndexLead),
		EmptyText:         t.NoIndexedComponents,
		WithPURLAnchor:    anchorComponentsWithPURL,
		WithoutPURLAnchor: anchorComponentsWithoutPURL,
	}
	if len(proj.ComponentIndex) == 0 {
		s.Empty = true
		return s
	}
	enrichmentDone := proj.Summary.VulnerabilityEnrichmentState == "completed"

	var withPURL, withoutPURL []reportjson.PackageOccurrenceGroupV2
	for i := range proj.ComponentIndex {
		if len(proj.ComponentIndex[i].PURLs) > 0 {
			withPURL = append(withPURL, proj.ComponentIndex[i])
		} else {
			withoutPURL = append(withoutPURL, proj.ComponentIndex[i])
		}
	}
	sortGroups(withPURL)
	sortGroups(withoutPURL)

	s.WithPURLTitle = fmt.Sprintf("%s (%d)", t.ComponentIndexWithPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithPURL)
	s.WithoutPURLTitle = fmt.Sprintf("%s (%d)", t.ComponentIndexWithoutPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithoutPURL)
	for i := range withPURL {
		s.WithPURL = append(s.WithPURL, buildGroup(withPURL[i], t, enrichmentDone))
	}
	for i := range withoutPURL {
		s.WithoutPURL = append(s.WithoutPURL, buildGroup(withoutPURL[i], t, enrichmentDone))
	}
	return s
}

func sortGroups(g []reportjson.PackageOccurrenceGroupV2) {
	sort.Slice(g, func(i, j int) bool {
		ni, nj := strings.ToLower(g[i].PackageName), strings.ToLower(g[j].PackageName)
		if ni != nj {
			return ni < nj
		}
		return strings.ToLower(g[i].Version) < strings.ToLower(g[j].Version)
	})
}

func buildGroup(group reportjson.PackageOccurrenceGroupV2, t i18npkg.Bundle, enrichmentDone bool) packageGroup {
	title := strings.TrimSpace(group.PackageName)
	if title == "" {
		title = t.NoneValue
	}
	if strings.TrimSpace(group.Version) != "" {
		title += " " + group.Version
	}
	pg := packageGroup{
		AnchorID: group.AnchorID,
		Title:    title,
		Name:     valueOrDash(group.PackageName),
		Version:  group.Version,
		PURLs:    group.PURLs,
		Labels: occurrenceLabels{
			ComponentID:  t.ComponentIDLabel,
			DeliveryPath: t.DeliveryPath,
			EvidencePath: t.EvidencePath,
			FoundBy:      t.FoundBy,
		},
	}

	perOccurrenceVuln := false
	if enrichmentDone && len(group.Occurrences) > 0 {
		allFound, anyFound := true, false
		for i := range group.Occurrences {
			if group.Occurrences[i].VulnCount > 0 {
				anyFound = true
			} else {
				allFound = false
			}
		}
		if allFound && anyFound {
			pg.VulnLine = fmt.Sprintf(t.VulnStatusFoundTemplate, group.VulnUniqueCount)
		} else if anyFound {
			perOccurrenceVuln = true
		}
	}

	for i := range group.Occurrences {
		occ := &group.Occurrences[i]
		o := occurrence{
			AnchorID:      domain.OccurrenceAnchorID(occ.ObjectID),
			ObjectID:      occ.ObjectID,
			DeliveryPaths: occ.DeliveryPaths,
			FoundBy:       emptyDash(occ.FoundBy),
		}
		switch {
		case len(occ.EvidencePaths) > 0:
			o.Evidence = occ.EvidencePaths
		case occ.EvidenceSource != "":
			o.Evidence = []string{occ.EvidenceSource}
		default:
			o.Evidence = []string{t.NoEvidenceRecorded}
		}
		if perOccurrenceVuln {
			if occ.VulnCount > 0 {
				o.VulnLine = fmt.Sprintf(t.VulnStatusFoundTemplate, occ.VulnCount)
			} else {
				o.VulnLine = t.VulnStatusNone
			}
		}
		pg.Occurrences = append(pg.Occurrences, o)
	}
	return pg
}

func buildNormalization(groups reportjson.SuppressionGroupsV2, t i18npkg.Bundle) normalizationSection {
	total := len(groups.FSArtifacts) + len(groups.LowValue) + len(groups.WeakDups) + len(groups.PURLDups)
	s := normalizationSection{
		Heading:   t.ComponentNormalizationSection,
		Anchor:    anchorSuppression,
		Lead:      i18npkg.RenderInlineHTML(t.ComponentNormalizationLead),
		EmptyText: t.NoSuppressions,
		Empty:     total == 0,
		SummaryTable: normalizationSummaryTable{
			Headers: []string{t.ReasonLabel, t.CountLabel, t.DescriptionLabel},
			Rows: []normalizationSummaryRow{
				{t.SuppressionReasonFSArtifact, fmt.Sprintf("%d", len(groups.FSArtifacts)), t.SuppressionDescriptionFSArtifact},
				{t.SuppressionReasonLowValueFile, fmt.Sprintf("%d", len(groups.LowValue)), t.SuppressionDescriptionLowValueFile},
				{t.SuppressionReasonWeakDuplicate, fmt.Sprintf("%d", len(groups.WeakDups)), t.SuppressionDescriptionWeakDuplicate},
				{t.SuppressionReasonPURLDuplicate, fmt.Sprintf("%d", len(groups.PURLDups)), t.SuppressionDescriptionPURLDuplicate},
			},
		},
	}
	s.Groups = []suppressionGroup{
		buildSuppressionGroup(t.SuppressionReasonFSArtifact, anchorSuppressionFS, groups.FSArtifacts, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalFS), i18npkg.RenderInlineHTML(t.SuppressionOperationalFSFollowUp)),
		buildSuppressionGroup(t.SuppressionReasonLowValueFile, anchorSuppressionLowValue, groups.LowValue, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalLowValue)),
		buildSuppressionGroup(t.SuppressionReasonWeakDuplicate, anchorSuppressionWeakDups, groups.WeakDups, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalWeakDup)),
		buildSuppressionGroup(t.SuppressionReasonPURLDuplicate, anchorSuppressionPURLDups, groups.PURLDups, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalPURLDup)),
	}
	return s
}

func buildSuppressionGroup(reason, anchor string, rows []reportjson.SuppressionRowV2, t i18npkg.Bundle, operational ...htmltmpl.HTML) suppressionGroup {
	g := suppressionGroup{
		AnchorID:    anchor,
		Title:       fmt.Sprintf("%s (%d)", reason, len(rows)),
		Operational: operational,
		Headers:     []string{t.SuppressionTableDeliveryPath, t.SuppressionTableComponentName, t.SuppressionTableSuppressedBy},
	}
	for i := range rows {
		if i >= suppressionTableMaxRows {
			g.Truncated = fmt.Sprintf(t.AdditionalEntriesOmittedTemplate, len(rows)-suppressionTableMaxRows)
			break
		}
		row := &rows[i]
		name := row.ComponentName
		if name == "" {
			name = "-"
		}
		g.Rows = append(g.Rows, buildSuppRow(row, name, t))
	}
	return g
}

// buildSuppRow models the "suppressed by" cell. KeptName/KeptAnchor are plain
// strings auto-escaped by the template. Reason is a trusted i18n prose string
// that may contain inline Markdown links, so it is rendered to HTML here.
func buildSuppRow(row *reportjson.SuppressionRowV2, name string, t i18npkg.Bundle) suppRow {
	sr := suppRow{DeliveryPath: row.DeliveryPath, Name: name}
	if row.ResolutionStatus == "resolved" && row.KeptComponentName != "" {
		sr.KeptName = row.KeptComponentName
		sr.KeptAnchor = row.KeptAnchorID
		return sr
	}
	sr.Reason = i18npkg.RenderInlineHTML(t.SuppressedByNoIndexedMatch)
	return sr
}

func buildExtensionFilter(skipExtensions []string, proj reportjson.ProjectionsV2, t i18npkg.Bundle) extensionFilterSection {
	s := extensionFilterSection{
		Heading:         t.ExtensionFilterSection,
		Anchor:          anchorExtensionFilter,
		Lead:            t.ExtensionFilterLead,
		ExtensionsLabel: t.ExtensionFilterExtensionsLabel,
		SkippedLabel:    t.ExtensionFilterSkippedLabel,
		EmptyText:       t.NoExtensionFilteredFiles,
	}
	if len(skipExtensions) == 0 {
		s.Empty = true
		return s
	}
	exts := append([]string(nil), skipExtensions...)
	sort.Strings(exts)
	quoted := make([]string, len(exts))
	for i, e := range exts {
		quoted[i] = "`" + e + "`"
	}
	s.Extensions = strings.Join(quoted, ", ")
	paths := append([]string(nil), proj.Summary.ExtensionFilteredPaths...)
	sort.Strings(paths)
	s.SkippedPaths = paths
	return s
}

func buildRootMetadata(root *reportjson.BOMRootComponentV2, t i18npkg.Bundle) rootMetadataSection {
	s := rootMetadataSection{
		Heading: t.RootMetadataSection,
		Anchor:  anchorRootMetadata,
		Headers: []string{t.Field, t.Value, t.Source},
	}
	if root == nil {
		return s
	}
	if root.BOMRef != "" {
		s.Rows = append(s.Rows, []string{t.ObjectID, root.BOMRef, t.Derived})
	}
	if root.Name != "" {
		s.Rows = append(s.Rows, []string{t.PackageName, root.Name, t.Derived})
	}
	if root.Version != "" {
		s.Rows = append(s.Rows, []string{t.Version, root.Version, t.Derived})
	}
	if len(root.ConfigProperties) > 0 {
		keys := make([]string, 0, len(root.ConfigProperties))
		for k := range root.ConfigProperties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s.Rows = append(s.Rows, []string{k, root.ConfigProperties[k], t.SuppliedBy})
		}
	}
	return s
}

func buildPolicy(decisions []reportjson.PolicyDecisionRowV2, t i18npkg.Bundle) policySection {
	s := policySection{Heading: t.PolicySection, Anchor: anchorPolicy, EmptyText: t.NoPolicyDecisions}
	if len(decisions) == 0 {
		s.Empty = true
		return s
	}
	s.Headers = []string{"Trigger", t.DeliveryPath, t.ProcessingDetailHeader, "Action"}
	for _, d := range decisions {
		s.Rows = append(s.Rows, []string{d.Trigger, d.NodePath, d.Detail, d.Action})
	}
	return s
}

func buildScanLog(proj reportjson.ProjectionsV2, t i18npkg.Bundle) scanLogSection {
	s := scanLogSection{
		Heading:        t.ScanSection,
		Anchor:         anchorScan,
		Lead:           t.ScanSectionLead,
		Headers:        []string{t.DeliveryPath, t.ComponentsFound, t.ScanTaskEvidenceLabel},
		NoPkgHeading:   t.ScanNoPackageIDsSection,
		NoPkgAnchor:    anchorScanNoPackageIDs,
		NoPkgEmptyText: t.NoScanNoPackageIDs,
	}
	for i := range proj.Scans {
		row := &proj.Scans[i]
		sr := scanRow{NodePath: row.NodePath}
		switch {
		case row.Error != "":
			sr.Error = row.Error
		case row.ComponentCount > 0:
			sr.Count = fmt.Sprintf("%d", row.ComponentCount)
			sr.Evidence = row.EvidencePaths
		default:
			sr.Count = t.NoComponents
		}
		s.Rows = append(s.Rows, sr)
	}
	if len(proj.Summary.ScanNoPackagePaths) == 0 {
		s.NoPkgEmpty = true
	} else {
		s.NoPkgLead = fmt.Sprintf(t.ScanNoPackageIDsLead, len(proj.Summary.ScanNoPackagePaths))
		s.NoPkgPaths = proj.Summary.ScanNoPackagePaths
	}
	return s
}

func buildExtraction(rows []reportjson.ExtractionLogRowV2, t i18npkg.Bundle) extractionSection {
	s := extractionSection{
		Heading: t.ExtractionSection,
		Anchor:  anchorExtraction,
		Headers: []string{"Path", "Format", t.Status, t.Tool, t.ExtractionSandboxLabel, t.ProcessingDetailHeader},
	}
	for i := range rows {
		row := &rows[i]
		depth := row.Depth
		if depth > 5 {
			depth = 5
		}
		detail := row.Detail
		if meta := formatExtractionArchiveMeta(row.ArchiveMeta); meta != "" {
			if detail != "" {
				detail = meta + " " + detail
			} else {
				detail = meta
			}
		}
		shortPath := row.Path
		if idx := strings.LastIndex(row.Path, "/"); idx >= 0 {
			shortPath = row.Path[idx+1:]
		}
		s.Rows = append(s.Rows, extractionRow{
			Depth:     depth,
			Path:      row.Path,
			ShortPath: shortPath,
			Format:    row.Format,
			Status:    row.Status,
			Tool:      row.Tool,
			Sandbox:   row.SandboxUsed,
			Detail:    detail,
		})
	}
	return s
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

// --- small shared helpers (mirroring the Markdown stats/process helpers) ---

const maxProseExamples = 3

func joinPathExamples(paths []string) string {
	if len(paths) == 0 {
		return "-"
	}
	n := len(paths)
	if n > maxProseExamples {
		n = maxProseExamples
	}
	quoted := make([]string, 0, n)
	for i := 0; i < n; i++ {
		quoted = append(quoted, "`"+paths[i]+"`")
	}
	out := strings.Join(quoted, ", ")
	if len(paths) > maxProseExamples {
		out += ", …"
	}
	return out
}

func extractionPathsByStatus(rows []reportjson.ExtractionLogRowV2, statuses ...string) []string {
	want := make(map[string]struct{}, len(statuses))
	for _, s := range statuses {
		want[s] = struct{}{}
	}
	var out []string
	for i := range rows {
		if _, ok := want[rows[i].Status]; ok {
			out = append(out, rows[i].Path)
		}
	}
	return out
}

func scanIssuePaths(issues []reportjson.IssueRowV2) []string {
	var out []string
	for _, issue := range issues {
		if issue.Stage == "scan" {
			out = append(out, issue.Message)
		}
	}
	return out
}

func countExtractionStatuses(rows []reportjson.ExtractionLogRowV2) (failed, missing int) {
	for i := range rows {
		switch rows[i].Status {
		case "failed", "security-blocked":
			failed++
		case "tool-missing":
			missing++
		}
	}
	return failed, missing
}

func formatExtractionArchiveMeta(meta *reportjson.ExtractionArchiveMetaV2) string {
	if meta == nil {
		return ""
	}
	parts := make([]string, 0, 7)
	if meta.Type != "" {
		parts = append(parts, "type="+meta.Type)
	}
	if len(meta.Methods) > 0 {
		parts = append(parts, "method="+strings.Join(meta.Methods, " / "))
	}
	if meta.HasEncryptedItem {
		parts = append(parts, "encrypted=yes")
	}
	if meta.PhysicalSize != "" {
		parts = append(parts, "physical-size="+meta.PhysicalSize)
	}
	if meta.HeadersSize != "" {
		parts = append(parts, "headers-size="+meta.HeadersSize)
	}
	if meta.Solid != "" {
		parts = append(parts, "solid="+meta.Solid)
	}
	if meta.Blocks != "" {
		parts = append(parts, "blocks="+meta.Blocks)
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, " ") + "}"
}

func extractionStatusClass(status, detail string, t i18npkg.Bundle) string {
	switch status {
	case "failed":
		lower := strings.ToLower(detail)
		switch {
		case strings.Contains(lower, "per-extraction timeout"):
			return t.ProcessingTimeoutLabel
		case strings.Contains(lower, "no matching password"):
			return t.ProcessingPasswordRequiredLabel
		case strings.Contains(lower, "can not open the file as archive"),
			strings.Contains(lower, "is not archive"),
			strings.Contains(lower, "does not match the detected archive format"):
			return t.ProcessingFormatMismatchLabel
		case strings.Contains(lower, "unexpected end of archive"),
			strings.Contains(lower, "headers error"),
			strings.Contains(lower, "unconfirmed start of archive"),
			strings.Contains(lower, "truncated/corrupt"),
			strings.Contains(lower, "invalid tar header"):
			return t.ProcessingCorruptLabel
		default:
			return t.ProcessingExtractionFailedLabel
		}
	case "security-blocked":
		return t.ProcessingSecurityBlockedLabel
	case "tool-missing":
		return t.ProcessingToolMissingLabel
	default:
		return status
	}
}

func extractionArchiveCols(row *reportjson.ExtractionLogRowV2) (archiveType, archiveMethod, encrypted, physicalSize string) {
	if row.ArchiveMeta == nil {
		return "-", "-", "-", "-"
	}
	m := row.ArchiveMeta
	archiveType = m.Type
	if archiveType == "" {
		archiveType = "-"
	}
	archiveMethod = strings.Join(m.Methods, ", ")
	if archiveMethod == "" {
		archiveMethod = "-"
	}
	if m.HasEncryptedItem {
		encrypted = "true"
	} else {
		encrypted = "false"
	}
	physicalSize = m.PhysicalSize
	if physicalSize == "" {
		physicalSize = "-"
	}
	return archiveType, archiveMethod, encrypted, physicalSize
}
