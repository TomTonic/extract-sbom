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
	cfg := vm.report.Config
	inp := vm.report.Input
	sb := vm.report.Runtime.Sandbox

	fmt.Fprint(w, buildHumanHeaderBlock(vm))
	fmt.Fprintf(w, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(w, sections)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, proj, t)
	fmt.Fprintln(w)

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

	// Input identification.
	writeSectionHeading(w, t.inputSection, anchorInputFile)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, inp.Filename)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, inp.Size, t.unitBytes)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", inp.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", inp.SHA512)
	fmt.Fprintln(w)

	// Configuration snapshot.
	writeSectionHeading(w, t.configSection, anchorConfig)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, cfg.PolicyMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, cfg.InterpretMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.language, cfg.Language)
	fmt.Fprintf(w, "| grype | %v |\n", cfg.GrypeEnabled)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, cfg.Limits.MaxDepth)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, cfg.Limits.MaxFiles)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, cfg.Limits.MaxTotalSize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, cfg.Limits.MaxEntrySize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, cfg.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, cfg.Limits.Timeout)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(cfg.SkipExtensions))
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, vm.report.Generator.Display)
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, cfg.ProgressLevel)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
	writeExtensionFilterSection(w, cfg.SkipExtensions, proj, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
	writeRootMetadata(w, proj.Summary.RootComponent, t)

	// Sandbox information.
	writeSectionHeading(w, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, sb.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, sb.Available)
	if sb.UnsafeOverride {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)

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
	rt := vm.report.Runtime.ToolVersions

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", t.title)

	genLink := ""
	if gen.Version != "" {
		genLink = "[" + gen.Version + "](https://github.com/TomTonic/extract-sbom/releases/tag/" + gen.Version + ")"
	}
	fmt.Fprintf(&b, "%s\n\n", fmt.Sprintf(t.reportHeaderGeneratorVersionTemplate, gen.Time, genLink, ""))

	if rt.Grype != "" {
		fmt.Fprintf(&b, "%s %s\n\n", t.reportHeaderToolsLabel, rt.Grype)
	}
	return b.String()
}
