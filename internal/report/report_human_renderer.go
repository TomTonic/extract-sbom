package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/TomTonic/extract-sbom/internal/scan"
)

// markdownWriterHumanRenderer renders the human report via direct writes.
// It is the default deterministic backend.
type markdownWriterHumanRenderer struct{}

// Render writes the full Markdown report from a precomputed view model.
func (markdownWriterHumanRenderer) Render(w io.Writer, vm humanReportViewModel) error {
	data := vm.data
	t := vm.translations
	sections := vm.sections
	occurrences := vm.occurrences
	indexStats := vm.indexStats
	extStats := vm.extStats
	scnStats := vm.scnStats
	polStats := vm.polStats

	fmt.Fprintf(w, "# %s\n\n", t.title)
	// Generator header with date and version information.
	generatorDate := time.Now().Format("2006-01-02 15:04:05")
	syftVersion := getSyftVersion()
	if syftVersion == "" {
		syftVersion = "github.com/anchore/syft (unknown version)"
	}
	linkedVersion := "[" + data.Generator.Version + "](" + generatorGitHubURL(data.Generator.Version) + ")"
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.reportHeaderGeneratorVersionTemplate, generatorDate, linkedVersion, syftVersion))

	// Tools line — only emitted if at least one external tool was used.
	var toolParts []string
	if data.ToolVersions.Grype != "" {
		entry := data.ToolVersions.Grype
		if data.ToolVersions.GrypeDB != "" {
			entry += " (" + data.ToolVersions.GrypeDB + ")"
		}
		toolParts = append(toolParts, entry)
	}
	if data.ToolVersions.SevenZip != "" {
		toolParts = append(toolParts, data.ToolVersions.SevenZip)
	}
	if data.ToolVersions.Unshield != "" {
		toolParts = append(toolParts, data.ToolVersions.Unshield)
	}
	if data.ToolVersions.Unsquashfs != "" {
		toolParts = append(toolParts, data.ToolVersions.Unsquashfs)
	}
	if len(toolParts) > 0 {
		fmt.Fprintf(w, "%s %s\n\n", t.reportHeaderToolsLabel, strings.Join(toolParts, " | "))
	}
	fmt.Fprintf(w, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(w, sections)
	fmt.Fprintln(w)

	// Executive summary and reader guidance.
	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, data, extStats, scnStats, polStats, indexStats, occurrences, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
	writeMethodOverview(w, t)
	fmt.Fprintln(w)

	// Actionable limitations and known blind spots.
	writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
	writeProcessingIssues(w, data, extStats, scnStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
	writeResidualRisk(w, data, extStats, scnStats, indexStats, t)
	fmt.Fprintln(w)

	// Appendix: complete raw audit trail.
	writeSectionHeading(w, t.appendixSection, anchorAppendix)
	fmt.Fprintln(w, t.appendixLead)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
	writeComponentOccurrenceIndex(w, occurrences, indexStats, data.Vulnerabilities, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
	writeSuppressionReport(w, data.Suppressions, data.BOM, t)
	fmt.Fprintln(w)

	// Input identification.
	writeSectionHeading(w, t.inputSection, anchorInputFile)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, data.Input.Size, t.unitBytes)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
	fmt.Fprintln(w)

	// Configuration snapshot.
	writeSectionHeading(w, t.configSection, anchorConfig)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, data.Config.PolicyMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, data.Config.InterpretMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.language, data.Config.Language)
	fmt.Fprintf(w, "| grype | %v |\n", data.Config.GrypeEnabled)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, data.Config.Limits.MaxDepth)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, data.Config.Limits.MaxFiles)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, data.Config.Limits.MaxTotalSize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, data.Config.Limits.MaxEntrySize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, data.Config.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, data.Config.Limits.Timeout)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(data.Config.SkipExtensions))
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, data.Generator.String())
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, data.Config.ProgressLevel.String())
	fmt.Fprintln(w)

	// Extension filter section: configured list and files excluded in this run.
	writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
	writeExtensionFilterSection(w, data, extStats, t)
	fmt.Fprintln(w)

	// Root SBOM metadata.
	writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
	writeRootMetadata(w, data, t)

	// Sandbox information.
	writeSectionHeading(w, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
	if data.SandboxInfo.UnsafeOvr {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)

	// Policy decisions.
	writeSectionHeading(w, t.policySection, anchorPolicy)
	writePolicyDecisions(w, data.PolicyDecisions, t)
	fmt.Fprintln(w)

	// Scan results.
	writeSectionHeading(w, t.scanSection, anchorScan)
	fmt.Fprintln(w, t.scanSectionLead)
	fmt.Fprintln(w)
	for _, sr := range data.Scans {
		evidencePaths := scan.FlattenEvidencePaths(sr)
		switch {
		case sr.Error != nil:
			fmt.Fprintf(w, "- **%s**: %s %v\n", sr.NodePath, t.scanError, sr.Error)
		case sr.BOM != nil && sr.BOM.Components != nil:
			fmt.Fprintf(w, "- **%s**: %d %s\n", sr.NodePath, len(*sr.BOM.Components), t.componentsFound)
			for _, evidencePath := range evidencePaths {
				fmt.Fprintf(w, "  - %s: `%s`\n", t.scanTaskEvidenceLabel, evidencePath)
			}
		default:
			fmt.Fprintf(w, "- **%s**: %s\n", sr.NodePath, t.noComponents)
		}
	}
	fmt.Fprintln(w)
	writeScanNoPackageIdentitiesSubsection(w, scnStats, t)
	fmt.Fprintln(w)

	// Extraction log.
	writeSectionHeading(w, t.extractionSection, anchorExtraction)
	writeExtractionTree(w, data.Tree, 0, t)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", t.endOfReport)
	return nil
}

// GenerateHumanWithTemplate writes the human report through an optional
// text/template wrapper. The wrapper receives one field, Body, containing the
// complete deterministic Markdown report produced by the default writer engine.
//
// When wrapperTemplate is empty, "{{.Body}}" is used.
func GenerateHumanWithTemplate(data ReportData, lang string, w io.Writer, wrapperTemplate string) error {
	return GenerateHumanWithOptions(data, lang, w, HumanRenderOptions{
		Engine:          HumanRenderEngineTemplateWrapper,
		WrapperTemplate: wrapperTemplate,
	})
}

// templateWrapperHumanRenderer wraps the deterministic writer output in a
// caller-provided text/template (for optional branded framing or embedding).
type templateWrapperHumanRenderer struct {
	wrapperTemplate string
}

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
// GenerateHumanWithTemplateDocument.
type humanTemplateDocumentModel struct {
	Header          string
	TableOfContents string
	Sections        humanTemplateSections
	EndOfReport     string
	Report          ReportData
	Language        string
}

// Render executes the optional wrapper template around the canonical Markdown
// report body.
func (r templateWrapperHumanRenderer) Render(w io.Writer, vm humanReportViewModel) error {
	var body bytes.Buffer
	if err := (markdownWriterHumanRenderer{}).Render(&body, vm); err != nil {
		return err
	}

	tplText := r.wrapperTemplate
	if strings.TrimSpace(tplText) == "" {
		tplText = "{{.Body}}"
	}

	tpl, err := texttemplate.New("human-wrapper").Parse(tplText)
	if err != nil {
		return fmt.Errorf("report: parse human wrapper template: %w", err)
	}

	model := struct {
		Body     string
		Report   ReportData
		Language string
	}{
		Body:     body.String(),
		Report:   vm.data,
		Language: vm.language,
	}
	if err := tpl.Execute(w, model); err != nil {
		return fmt.Errorf("report: execute human wrapper template: %w", err)
	}
	return nil
}

// GenerateHumanWithTemplateDocument renders the human report using a
// caller-provided text/template fed with pre-rendered Markdown section blocks.
//
// This optional API enables structural customization (for example reordered
// sections or custom framing) while preserving deterministic section content
// generation from the canonical writer helpers.
func GenerateHumanWithTemplateDocument(data ReportData, lang string, w io.Writer, documentTemplate string) error {
	return GenerateHumanWithOptions(data, lang, w, HumanRenderOptions{
		Engine:           HumanRenderEngineTemplateDocument,
		DocumentTemplate: documentTemplate,
	})
}

func executeHumanDocumentTemplate(w io.Writer, model humanTemplateDocumentModel, documentTemplate string) error {
	tpl, err := texttemplate.New("human-document").Parse(documentTemplate)
	if err != nil {
		return fmt.Errorf("report: parse human document template: %w", err)
	}
	if err := tpl.Execute(w, model); err != nil {
		return fmt.Errorf("report: execute human document template: %w", err)
	}
	return nil
}

func buildHumanTemplateDocumentModel(vm humanReportViewModel) humanTemplateDocumentModel {
	data := vm.data
	t := vm.translations

	var header bytes.Buffer
	fmt.Fprintf(&header, "# %s\n\n", t.title)
	generatorDate := time.Now().Format("2006-01-02 15:04:05")
	syftVersion := getSyftVersion()
	if syftVersion == "" {
		syftVersion = "github.com/anchore/syft (unknown version)"
	}
	linkedVersion := "[" + data.Generator.Version + "](" + generatorGitHubURL(data.Generator.Version) + ")"
	fmt.Fprintf(&header, "%s\n\n", fmt.Sprintf(t.reportHeaderGeneratorVersionTemplate, generatorDate, linkedVersion, syftVersion))

	var toolParts []string
	if data.ToolVersions.Grype != "" {
		entry := data.ToolVersions.Grype
		if data.ToolVersions.GrypeDB != "" {
			entry += " (" + data.ToolVersions.GrypeDB + ")"
		}
		toolParts = append(toolParts, entry)
	}
	if data.ToolVersions.SevenZip != "" {
		toolParts = append(toolParts, data.ToolVersions.SevenZip)
	}
	if data.ToolVersions.Unshield != "" {
		toolParts = append(toolParts, data.ToolVersions.Unshield)
	}
	if data.ToolVersions.Unsquashfs != "" {
		toolParts = append(toolParts, data.ToolVersions.Unsquashfs)
	}
	if len(toolParts) > 0 {
		fmt.Fprintf(&header, "%s %s\n\n", t.reportHeaderToolsLabel, strings.Join(toolParts, " | "))
	}

	var toc bytes.Buffer
	fmt.Fprintf(&toc, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(&toc, vm.sections)
	fmt.Fprintln(&toc)

	return humanTemplateDocumentModel{
		Header:          header.String(),
		TableOfContents: toc.String(),
		Sections:        buildHumanTemplateSections(vm),
		EndOfReport:     t.endOfReport + "\n",
		Report:          data,
		Language:        vm.language,
	}
}

func buildHumanTemplateSections(vm humanReportViewModel) humanTemplateSections {
	data := vm.data
	t := vm.translations

	render := func(fn func(io.Writer)) string {
		var b bytes.Buffer
		fn(&b)
		return b.String()
	}

	return humanTemplateSections{
		Summary: render(func(w io.Writer) {
			writeSectionHeading(w, t.summarySection, anchorSummary)
			writeSummary(w, data, vm.extStats, vm.scnStats, vm.polStats, vm.indexStats, vm.occurrences, t)
			fmt.Fprintln(w)
		}),
		MethodOverview: render(func(w io.Writer) {
			writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
			writeMethodOverview(w, t)
			fmt.Fprintln(w)
		}),
		ProcessingIssues: render(func(w io.Writer) {
			writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
			writeProcessingIssues(w, data, vm.extStats, vm.scnStats, t)
			fmt.Fprintln(w)
		}),
		ResidualRisk: render(func(w io.Writer) {
			writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
			writeResidualRisk(w, data, vm.extStats, vm.scnStats, vm.indexStats, t)
			fmt.Fprintln(w)
		}),
		Appendix: render(func(w io.Writer) {
			writeSectionHeading(w, t.appendixSection, anchorAppendix)
			fmt.Fprintln(w, t.appendixLead)
			fmt.Fprintln(w)
		}),
		ComponentIndex: render(func(w io.Writer) {
			writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
			writeComponentOccurrenceIndex(w, vm.occurrences, vm.indexStats, data.Vulnerabilities, t)
			fmt.Fprintln(w)
		}),
		ComponentNormalization: render(func(w io.Writer) {
			writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
			writeSuppressionReport(w, data.Suppressions, data.BOM, t)
			fmt.Fprintln(w)
		}),
		Input: render(func(w io.Writer) {
			writeSectionHeading(w, t.inputSection, anchorInputFile)
			fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, data.Input.Size, t.unitBytes)
			fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
			fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
			fmt.Fprintln(w)
		}),
		Configuration: render(func(w io.Writer) {
			writeSectionHeading(w, t.configSection, anchorConfig)
			fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, data.Config.PolicyMode)
			fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, data.Config.InterpretMode)
			fmt.Fprintf(w, "| %s | %s |\n", t.language, data.Config.Language)
			fmt.Fprintf(w, "| grype | %v |\n", data.Config.GrypeEnabled)
			fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, data.Config.Limits.MaxDepth)
			fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, data.Config.Limits.MaxFiles)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, data.Config.Limits.MaxTotalSize, t.unitBytes)
			fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, data.Config.Limits.MaxEntrySize, t.unitBytes)
			fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, data.Config.Limits.MaxRatio)
			fmt.Fprintf(w, "| %s | %s |\n", t.timeout, data.Config.Limits.Timeout)
			fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(data.Config.SkipExtensions))
			fmt.Fprintf(w, "| %s | %s |\n", t.generator, data.Generator.String())
			fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, data.Config.ProgressLevel.String())
			fmt.Fprintln(w)
		}),
		ExtensionFilter: render(func(w io.Writer) {
			writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
			writeExtensionFilterSection(w, data, vm.extStats, t)
			fmt.Fprintln(w)
		}),
		RootMetadata: render(func(w io.Writer) {
			writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
			writeRootMetadata(w, data, t)
		}),
		Sandbox: render(func(w io.Writer) {
			writeSectionHeading(w, t.sandboxSection, anchorSandbox)
			fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
			fmt.Fprintf(w, "|---|---|\n")
			fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
			fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
			if data.SandboxInfo.UnsafeOvr {
				fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
			}
			fmt.Fprintln(w)
		}),
		Policy: render(func(w io.Writer) {
			writeSectionHeading(w, t.policySection, anchorPolicy)
			writePolicyDecisions(w, data.PolicyDecisions, t)
			fmt.Fprintln(w)
		}),
		Scan: render(func(w io.Writer) {
			writeSectionHeading(w, t.scanSection, anchorScan)
			fmt.Fprintln(w, t.scanSectionLead)
			fmt.Fprintln(w)
			for _, sr := range data.Scans {
				evidencePaths := scan.FlattenEvidencePaths(sr)
				switch {
				case sr.Error != nil:
					fmt.Fprintf(w, "- **%s**: %s %v\n", sr.NodePath, t.scanError, sr.Error)
				case sr.BOM != nil && sr.BOM.Components != nil:
					fmt.Fprintf(w, "- **%s**: %d %s\n", sr.NodePath, len(*sr.BOM.Components), t.componentsFound)
					for _, evidencePath := range evidencePaths {
						fmt.Fprintf(w, "  - %s: `%s`\n", t.scanTaskEvidenceLabel, evidencePath)
					}
				default:
					fmt.Fprintf(w, "- **%s**: %s\n", sr.NodePath, t.noComponents)
				}
			}
			fmt.Fprintln(w)
			writeScanNoPackageIdentitiesSubsection(w, vm.scnStats, t)
			fmt.Fprintln(w)
		}),
		Extraction: render(func(w io.Writer) {
			writeSectionHeading(w, t.extractionSection, anchorExtraction)
			writeExtractionTree(w, data.Tree, 0, t)
			fmt.Fprintln(w)
		}),
	}
}
