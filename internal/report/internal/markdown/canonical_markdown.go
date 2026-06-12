package markdown

import (
	"fmt"
	"io"
	"strings"
)

// renderCanonicalHumanMarkdown writes the deterministic canonical Markdown
// report content from a precomputed view model.
func renderCanonicalHumanMarkdown(w io.Writer, vm markdownReportViewModel) error {
	t := vm.translations
	sections := vm.sections
	proj := vm.report.Projections

	fmt.Fprint(w, buildHumanHeaderBlock(vm))
	fmt.Fprintf(w, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(w, sections)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, proj, t)
	fmt.Fprintln(w)

	writeRunScopeSection(w, vm)

	writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
	writeMethodOverview(w, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
	writeProcessingIssues(w, proj, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
	writeResidualRisk(w, proj, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.appendixSection, anchorAppendix)
	fmt.Fprintln(w, t.appendixLead)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
	writeComponentOccurrenceIndex(w, proj, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
	writeSuppressionReport(w, proj.SuppressionGroups, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
	writeExtensionFilterSection(w, vm.report.Config.SkipExtensions, proj, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
	writeRootMetadata(w, proj.Summary.RootComponent, t)

	// Policy decisions.
	writeSectionHeading(w, t.policySection, anchorPolicy)
	writePolicyDecisions(w, proj.PolicyDecisions, t)
	fmt.Fprintln(w)

	// Scan results.
	writeSectionHeading(w, t.scanSection, anchorScan)
	fmt.Fprintln(w, t.scanSectionLead)
	fmt.Fprintln(w)
	for _, row := range proj.Scans {
		switch {
		case row.Error != "":
			fmt.Fprintf(w, "- **%s**: %s %s\n", row.NodePath, t.scanError, row.Error)
		case row.ComponentCount > 0:
			fmt.Fprintf(w, "- **%s**: %d %s\n", row.NodePath, row.ComponentCount, t.componentsFound)
			for _, ep := range row.EvidencePaths {
				fmt.Fprintf(w, "  - %s: `%s`\n", t.scanTaskEvidenceLabel, ep)
			}
		default:
			fmt.Fprintf(w, "- **%s**: %s\n", row.NodePath, t.noComponents)
		}
	}
	fmt.Fprintln(w)
	writeScanNoPackageIdentitiesSubsection(w, proj, t)
	fmt.Fprintln(w)

	// Extraction log.
	writeSectionHeading(w, t.extractionSection, anchorExtraction)
	writeExtractionLog(w, proj.ExtractionLog, t)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", t.endOfReport)
	return nil
}

func buildHumanHeaderBlock(vm markdownReportViewModel) string {
	t := vm.translations
	gen := vm.report.Generator
	run := vm.report.Run

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", t.title)

	genLink := ""
	if gen.Version != "" {
		genLink = "[" + gen.Version + "](https://github.com/TomTonic/extract-sbom/releases/tag/" + gen.Version + ")"
	}
	// "Report generated" must reflect when the analysis actually ran, not when
	// the binary was built; "based on" carries the build revision for traceability.
	generatedAt := run.EndTime
	if generatedAt == "" {
		generatedAt = gen.Time
	}
	fmt.Fprintf(&b, "%s\n\n", fmt.Sprintf(t.reportHeaderGeneratorVersionTemplate, generatedAt, genLink, emptyDash(gen.Revision)))

	if tools := buildToolProvenanceLine(vm); tools != "" {
		fmt.Fprintf(&b, "%s %s\n\n", t.reportHeaderToolsLabel, tools)
	}
	return b.String()
}

// buildToolProvenanceLine renders a single line listing the versions of every
// external tool used, including Grype scanner and vulnerability-database
// provenance, so the scan can be reproduced and audited.
func buildToolProvenanceLine(vm markdownReportViewModel) string {
	rt := vm.report.Runtime.ToolVersions
	gp := vm.report.Projections.Summary.GrypeProvenance
	t := vm.translations

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
	// rt.Grype is set by the orchestrator as "grype <version>" (already labelled).
	// Fall back to gp.Version (bare number) only when the runtime field is absent.
	if rt.Grype != "" {
		parts = append(parts, rt.Grype)
	} else if gp.Version != "" {
		parts = append(parts, "grype "+gp.Version)
	}

	line := strings.Join(parts, " | ")
	if gp.DBSchema != "" || gp.DBBuilt != "" || gp.DBUpdated != "" {
		db := fmt.Sprintf(t.vulnGrypeDBTemplate, emptyDash(gp.DBSchema), emptyDash(gp.DBBuilt), emptyDash(gp.DBUpdated))
		if line != "" {
			line += " — " + db
		} else {
			line = db
		}
	}
	return line
}
