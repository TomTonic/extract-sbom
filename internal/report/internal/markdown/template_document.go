package markdown

import (
	"bytes"
	"fmt"
	"io"
	texttemplate "text/template"
)

// humanTemplateSections contains pre-rendered Markdown blocks for each major
// section so optional document templates can reorder or selectively include
// report content.
type humanTemplateSections struct {
	Summary                string
	MethodOverview         string
	ProcessingIssues       string
	ResidualRisk           string
	Appendix               string
	ComponentIndex         string
	ComponentNormalization string
	Input                  string
	Configuration          string
	ExtensionFilter        string
	RootMetadata           string
	Sandbox                string
	Policy                 string
	Scan                   string
	Extraction             string
}

// humanTemplateDocumentModel is the template input for
// GenerateMarkdownWithTemplateDocument.
type humanTemplateDocumentModel struct {
	Header          string
	TableOfContents string
	Sections        humanTemplateSections
	EndOfReport     string
	Report          ReportData
	Language        string
}

func executeMarkdownDocumentTemplate(w io.Writer, model humanTemplateDocumentModel, documentTemplate string) error {
	tpl, err := texttemplate.New("human-document").Parse(documentTemplate)
	if err != nil {
		return fmt.Errorf("report: parse human document template: %w", err)
	}
	if err := tpl.Execute(w, model); err != nil {
		return fmt.Errorf("report: execute human document template: %w", err)
	}
	return nil
}

func buildMarkdownTemplateDocumentModel(vm markdownReportViewModel) humanTemplateDocumentModel {
	t := vm.translations

	var toc bytes.Buffer
	fmt.Fprintf(&toc, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(&toc, vm.sections)
	fmt.Fprintln(&toc)

	return humanTemplateDocumentModel{
		Header:          buildHumanHeaderBlock(vm),
		TableOfContents: toc.String(),
		Sections:        buildHumanTemplateSections(vm),
		EndOfReport:     t.endOfReport + "\n",
		Report:          vm.data,
		Language:        vm.language,
	}
}

func buildHumanTemplateSections(vm markdownReportViewModel) humanTemplateSections {
	t := vm.translations
	typedProj := vm.report.Projections
	typedCfg := vm.report.Config
	typedInp := vm.report.Input
	typedSB := vm.report.Runtime.Sandbox

	render := func(fn func(io.Writer)) string {
		var b bytes.Buffer
		fn(&b)
		return b.String()
	}

	return humanTemplateSections{
		Summary: render(func(w io.Writer) {
			writeSectionHeading(w, t.summarySection, anchorSummary)
			writeSummary(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		MethodOverview: render(func(w io.Writer) {
			writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
			writeMethodOverview(w, t)
			fmt.Fprintln(w)
		}),
		ProcessingIssues: render(func(w io.Writer) {
			writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
			writeProcessingIssues(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		ResidualRisk: render(func(w io.Writer) {
			writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
			writeResidualRisk(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		Appendix: render(func(w io.Writer) {
			writeSectionHeading(w, t.appendixSection, anchorAppendix)
			fmt.Fprintln(w, t.appendixLead)
			fmt.Fprintln(w)
		}),
		ComponentIndex: render(func(w io.Writer) {
			writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
			writeComponentOccurrenceIndex(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		ComponentNormalization: render(func(w io.Writer) {
			writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
			writeSuppressionReport(w, typedProj.SuppressionGroups, t)
			fmt.Fprintln(w)
		}),
		Input: render(func(w io.Writer) {
			writeSectionHeading(w, t.inputSection, anchorInputFile)
			fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, typedInp.Filename)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, typedInp.Size, t.unitBytes)
			fmt.Fprintf(w, "| SHA-256 | `%s` |\n", typedInp.SHA256)
			fmt.Fprintf(w, "| SHA-512 | `%s` |\n", typedInp.SHA512)
			fmt.Fprintln(w)
		}),
		Configuration: render(func(w io.Writer) {
			writeSectionHeading(w, t.configSection, anchorConfig)
			fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, typedCfg.PolicyMode)
			fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, typedCfg.InterpretMode)
			fmt.Fprintf(w, "| %s | %s |\n", t.language, typedCfg.Language)
			fmt.Fprintf(w, "| grype | %v |\n", typedCfg.GrypeEnabled)
			fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, typedCfg.Limits.MaxDepth)
			fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, typedCfg.Limits.MaxFiles)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, typedCfg.Limits.MaxTotalSize, t.unitBytes)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, typedCfg.Limits.MaxEntrySize, t.unitBytes)
			fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, typedCfg.Limits.MaxRatio)
			fmt.Fprintf(w, "| %s | %s |\n", t.timeout, typedCfg.Limits.Timeout)
			fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(typedCfg.SkipExtensions))
			fmt.Fprintf(w, "| %s | %s |\n", t.generator, vm.report.Generator.Display)
			fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, typedCfg.ProgressLevel)
			fmt.Fprintln(w)
		}),
		ExtensionFilter: render(func(w io.Writer) {
			writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
			writeExtensionFilterSection(w, typedCfg.SkipExtensions, typedProj, t)
			fmt.Fprintln(w)
		}),
		RootMetadata: render(func(w io.Writer) {
			writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
			writeRootMetadata(w, typedProj.Summary.RootComponent, t)
		}),
		Sandbox: render(func(w io.Writer) {
			writeSectionHeading(w, t.sandboxSection, anchorSandbox)
			fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, typedSB.Name)
			fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, typedSB.Available)
			if typedSB.UnsafeOverride {
				fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
			}
			fmt.Fprintln(w)
		}),
		Policy: render(func(w io.Writer) {
			writeSectionHeading(w, t.policySection, anchorPolicy)
			writePolicyDecisions(w, typedProj.PolicyDecisions, t)
			fmt.Fprintln(w)
		}),
		Scan: render(func(w io.Writer) {
			writeSectionHeading(w, t.scanSection, anchorScan)
			fmt.Fprintln(w, t.scanSectionLead)
			fmt.Fprintln(w)
			for _, row := range typedProj.Scans {
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
			writeScanNoPackageIdentitiesSubsection(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		Extraction: render(func(w io.Writer) {
			writeSectionHeading(w, t.extractionSection, anchorExtraction)
			writeExtractionLog(w, typedProj.ExtractionLog, t)
			fmt.Fprintln(w)
		}),
	}
}
