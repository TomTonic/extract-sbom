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
	RunScope               string
	MethodOverview         string
	ProcessingIssues       string
	ResidualRisk           string
	Appendix               string
	ComponentIndex         string
	ComponentNormalization string
	ExtensionFilter        string
	RootMetadata           string
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
	fmt.Fprintf(&toc, "## %s\n\n", t.TableOfContentsSection)
	writeTableOfContents(&toc, vm.sections)
	fmt.Fprintln(&toc)

	return humanTemplateDocumentModel{
		Header:          buildHumanHeaderBlock(vm),
		TableOfContents: toc.String(),
		Sections:        buildHumanTemplateSections(vm),
		EndOfReport:     t.EndOfReport + "\n",
		Report:          vm.data,
		Language:        vm.language,
	}
}

func buildHumanTemplateSections(vm markdownReportViewModel) humanTemplateSections {
	t := vm.translations
	typedProj := vm.report.Projections
	typedCfg := vm.report.Config

	render := func(fn func(io.Writer)) string {
		var b bytes.Buffer
		fn(&b)
		return b.String()
	}

	return humanTemplateSections{
		Summary: render(func(w io.Writer) {
			writeSectionHeading(w, t.SummarySection, anchorSummary)
			writeSummary(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		MethodOverview: render(func(w io.Writer) {
			writeSectionHeading(w, t.MethodOverviewSection, anchorMethodOverview)
			writeMethodOverview(w, t)
			fmt.Fprintln(w)
		}),
		ProcessingIssues: render(func(w io.Writer) {
			writeSectionHeading(w, t.ProcessingIssuesSection, anchorProcessingErrors)
			writeProcessingIssues(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		ResidualRisk: render(func(w io.Writer) {
			writeSectionHeading(w, t.ResidualRiskSection, anchorResidualRisk)
			writeResidualRisk(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		Appendix: render(func(w io.Writer) {
			writeSectionHeading(w, t.AppendixSection, anchorAppendix)
			fmt.Fprintln(w, t.AppendixLead)
			fmt.Fprintln(w)
		}),
		ComponentIndex: render(func(w io.Writer) {
			writeSectionHeading(w, t.ComponentIndexSection, anchorComponentIndex)
			writeComponentOccurrenceIndex(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		ComponentNormalization: render(func(w io.Writer) {
			writeSectionHeading(w, t.ComponentNormalizationSection, anchorSuppression)
			writeSuppressionReport(w, typedProj.SuppressionGroups, t)
			fmt.Fprintln(w)
		}),
		RunScope: render(func(w io.Writer) {
			writeRunScopeSection(w, vm)
		}),
		ExtensionFilter: render(func(w io.Writer) {
			writeSectionHeading(w, t.ExtensionFilterSection, anchorExtensionFilter)
			writeExtensionFilterSection(w, typedCfg.SkipExtensions, typedProj, t)
			fmt.Fprintln(w)
		}),
		RootMetadata: render(func(w io.Writer) {
			writeSectionHeading(w, t.RootMetadataSection, anchorRootMetadata)
			writeRootMetadata(w, typedProj.Summary.RootComponent, t)
		}),
		Policy: render(func(w io.Writer) {
			writeSectionHeading(w, t.PolicySection, anchorPolicy)
			writePolicyDecisions(w, typedProj.PolicyDecisions, t)
			fmt.Fprintln(w)
		}),
		Scan: render(func(w io.Writer) {
			writeSectionHeading(w, t.ScanSection, anchorScan)
			fmt.Fprintln(w, t.ScanSectionLead)
			fmt.Fprintln(w)
			for _, row := range typedProj.Scans {
				switch {
				case row.Error != "":
					fmt.Fprintf(w, "- **%s**: %s %s\n", row.NodePath, t.ScanError, row.Error)
				case row.ComponentCount > 0:
					fmt.Fprintf(w, "- **%s**: %d %s\n", row.NodePath, row.ComponentCount, t.ComponentsFound)
					for _, ep := range row.EvidencePaths {
						fmt.Fprintf(w, "  - %s: `%s`\n", t.ScanTaskEvidenceLabel, ep)
					}
				default:
					fmt.Fprintf(w, "- **%s**: %s\n", row.NodePath, t.NoComponents)
				}
			}
			fmt.Fprintln(w)
			writeScanNoPackageIdentitiesSubsection(w, typedProj, t)
			fmt.Fprintln(w)
		}),
		Extraction: render(func(w io.Writer) {
			writeSectionHeading(w, t.ExtractionSection, anchorExtraction)
			writeExtractionLog(w, typedProj.ExtractionLog, t)
			fmt.Fprintln(w)
		}),
	}
}
