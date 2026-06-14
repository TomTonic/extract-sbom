// HTML report tests validate the self-contained HTML audit report from the
// reader's perspective: the document must be well formed, must mirror the
// Markdown report's content (sharing the i18n catalog), must honor the
// configured language, must escape untrusted input, and must use HTML-native
// affordances (tables and collapsible <details> sections).
package html

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/policy"
	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

func renderHTML(t *testing.T, data ReportData, language string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Generate(data, language, &buf); err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	return buf.String()
}

// richReportData exercises the conditional branches: vulnerabilities, indexed
// components (with and without PURL), policy decisions, and processing issues.
func richReportData() ReportData {
	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef: "ref-a", Name: "alpha", Version: "1.0.0",
			PackageURL: "pkg:maven/com.acme/alpha@1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "a/alpha.jar"}},
		},
		{
			BOMRef: "ref-b", Name: "beta",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "b/beta.bin"}},
		},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-a": {{VulnerabilityID: "CVE-2026-1", Severity: "high", Description: "boom"}},
		},
	}
	data.Scans = []scan.ScanResult{{NodePath: "empty.jar", BOM: &cdx.BOM{Components: &[]cdx.Component{}}}}
	data.PolicyDecisions = []policy.Decision{{Trigger: "max-depth", NodePath: "deep.zip", Action: policy.ActionSkip, Detail: "limit"}}
	data.ProcessingIssues = []model.ProcessingIssue{{Stage: "scan", Message: "scanner failed on empty.jar"}}
	return data
}

func TestGenerateProducesWellFormedDocument(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "en")
	for _, want := range []string{
		"<!DOCTYPE html>",
		`<html lang="en">`,
		"<title>extract-sbom Audit Report</title>",
		`<h2 id="summary">Summary</h2>`,
		`<h3 id="analysis-overview">Analysis Overview</h3>`,
		`<h3 id="vulnerability-summary">Vulnerability Summary</h3>`,
		`<h2 id="run-and-scope">Run &amp; Scope</h2>`,
		`<h2 id="method-at-a-glance">Method At A Glance</h2>`,
		`<h2 id="residual-risk-and-limitations">Residual Risk and Limitations</h2>`,
		`<h2 id="appendix">Appendix</h2>`,
		`<h3 id="extraction-log">Extraction Log</h3>`,
		"End of report.",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing expected fragment %q", want)
		}
	}
}

// TestAllAppendixSectionsPresent verifies that every Markdown appendix section is
// also present in the HTML output (content parity at the section level).
func TestAllAppendixSectionsPresent(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, richReportData(), "en")
	for _, want := range []string{
		`id="component-occurrence-index"`,
		`id="component-normalization"`,
		`id="extension-filter"`,
		`id="root-sbom-metadata"`,
		`id="policy-decisions"`,
		`id="scan-results"`,
		`id="content-items-without-package-identities"`,
		`id="extraction-log"`,
		`id="components-with-purl"`,
		`id="components-without-purl"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing section anchor %q", want)
		}
	}
}

// TestTOCListsAllSections verifies the sidebar Table of Contents links every
// section, including the appendix subsections.
func TestTOCListsAllSections(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "en")
	for _, want := range []string{
		`href="#summary"`,
		`href="#analysis-overview"`,
		`href="#vulnerability-summary"`,
		`href="#run-and-scope"`,
		`href="#component-occurrence-index"`,
		`href="#components-with-purl"`,
		`href="#suppression-purl-duplicates"`,
		`href="#extraction-log"`,
	} {
		if !strings.Contains(html, `<nav class="toc">`) || !strings.Contains(html, want) {
			t.Errorf("TOC missing link %q", want)
		}
	}
}

// TestUsesCollapsibleDetails verifies the HTML uses <details> collapsibles for
// the large appendix blocks instead of a single flat dump.
func TestUsesCollapsibleDetails(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, richReportData(), "en")
	if strings.Count(html, "<details") < 3 {
		t.Errorf("expected several <details> collapsibles, got %d", strings.Count(html, "<details"))
	}
	// The two component-index buckets must be collapsible.
	if !strings.Contains(html, `<details class="bucket" open><summary id="components-with-purl">`) {
		t.Error("Components with PURL bucket should be a collapsible <details>")
	}
}

func TestGenerateUsesGermanLabels(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "de")
	for _, want := range []string{
		`<html lang="de">`,
		"<title>extract-sbom Prüfbericht</title>",
		`>Zusammenfassung</h2>`,
		`>Extraktionsprotokoll</h3>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("German HTML report missing expected fragment %q", want)
		}
	}
	if strings.Contains(html, ">Summary</h2>") {
		t.Error("German HTML report still contains the English heading 'Summary'")
	}
}

func TestGenerateEscapesUntrustedInput(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Input.Filename = "<script>alert(1)</script>.zip"
	html := renderHTML(t, data, "en")

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("HTML report contains an unescaped <script> tag from the input file name")
	}
	if !strings.Contains(html, "alert(1)") {
		t.Error("HTML report dropped the input file name entirely")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("HTML report does not contain the HTML-escaped file name")
	}
}

func TestGenerateListsExternalToolVersions(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.ToolVersions = ToolVersions{
		SevenZip:   "7-Zip 24.09",
		Unsquashfs: "unsquashfs version 4.6.1",
	}
	html := renderHTML(t, data, "en")
	for _, want := range []string{"7-Zip 24.09", "unsquashfs version 4.6.1"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing external tool version %q", want)
		}
	}
}

// TestVulnNotRequested verifies the Vulnerability Summary states "not requested"
// (and shows no state line / table) when grype was not enabled.
func TestVulnNotRequested(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "en")
	if !strings.Contains(html, "Vulnerability enrichment: not requested") {
		t.Error("expected not-requested line in vulnerability summary")
	}
	if strings.Contains(html, "Vulnerability enrichment state:") {
		t.Error("state line must not appear when grype was not requested")
	}
}

// TestVulnCompletedNoMatches verifies the completed-but-empty state.
func TestVulnCompletedNoMatches(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Vulnerabilities = &vulnscan.Result{Requested: true, State: vulnscan.StateCompleted}
	html := renderHTML(t, data, "en")

	if !strings.Contains(html, "Vulnerability enrichment state: <code>completed</code>") {
		t.Error("expected completed state line")
	}
	if !strings.Contains(html, "no matched vulnerabilities") {
		t.Error("expected 'no matched vulnerabilities' finding line")
	}
}

func TestVulnTableWithMatch(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{{BOMRef: "ref-a", Name: "libcurl", Version: "8.0.0"}}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-a": {{VulnerabilityID: "CVE-2024-0001", Severity: "critical", Description: "buffer overflow"}},
		},
	}
	html := renderHTML(t, data, "en")
	for _, want := range []string{"CVE-2024-0001", "libcurl", "buffer overflow", `<span class="badge critical">`} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML vulnerability table missing %q", want)
		}
	}
}

// TestConfigTableDefaultsAndNewRows verifies the Configuration table mirrors the
// Markdown renderer: default markers and the unsafe/sbom-format/report-selection/
// parallel-scanners rows.
func TestConfigTableDefaultsAndNewRows(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "en")
	for _, want := range []string{
		"<td>sbom-format</td><td>cyclonedx-json (default)</td>",
		"<td>report-selection</td><td>markdown (default)</td>",
		"<td>unsafe</td><td>false (default)</td>",
		"<td>parallel-scanners</td>",
		"<td>Language</td><td>en (default)</td>",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Configuration table missing %q", want)
		}
	}
}

// TestSandboxThreeStates verifies the sandbox section renders each of the three
// runtime states, mirroring the Markdown renderer.
func TestSandboxThreeStates(t *testing.T) {
	t.Parallel()

	// State 1: bwrap absent, no --unsafe → denied prose.
	denied := renderHTML(t, makeTestReportData(), "en")
	if !strings.Contains(denied, "were skipped") {
		t.Error("denied state should explain that tool-backed formats were skipped")
	}

	// State 2: bwrap absent, --unsafe → passthrough prose.
	d2 := makeTestReportData()
	d2.SandboxInfo.UnsafeOvr = true
	passthrough := renderHTML(t, d2, "en")
	if !strings.Contains(passthrough, "passthrough mode") ||
		!strings.Contains(passthrough, "authorized with <code>--unsafe</code>") {
		t.Error("passthrough state should explain the --unsafe-authorized passthrough run")
	}

	// State 3: bwrap present → status table with isolation row.
	d3 := makeTestReportData()
	d3.SandboxInfo.BwrapFound = true
	d3.SandboxInfo.Name = "bwrap"
	active := renderHTML(t, d3, "en")
	if !strings.Contains(active, "<td>Isolation</td>") {
		t.Error("active state should show the Isolation table row")
	}
}

// TestAnalysisOverviewEmbeddedLinks verifies the Analysis Overview prose carries
// the same inline deep links as the Markdown report (rendered as <a href>).
func TestAnalysisOverviewEmbeddedLinks(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "en")
	start := strings.Index(html, `id="analysis-overview"`)
	end := strings.Index(html, `id="vulnerability-summary"`)
	if start == -1 || end == -1 || end <= start {
		t.Fatal("could not isolate Analysis Overview section")
	}
	section := html[start:end]
	for _, want := range []string{
		`href="#extraction-log"`,
		`href="#component-normalization"`,
		`href="#component-occurrence-index"`,
		`href="#components-with-purl"`,
		`href="#components-without-purl"`,
		`href="#method-at-a-glance"`,
	} {
		if !strings.Contains(section, want) {
			t.Errorf("Analysis Overview missing embedded link %q", want)
		}
	}
}

// TestComponentIndexCollapsibleGroups verifies indexed package groups render as
// collapsible <details> with the package anchor id (so vuln links resolve) and
// the occurrence's delivery path.
func TestComponentIndexCollapsibleGroups(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, richReportData(), "en")
	if !strings.Contains(html, `<details class="group" id="package-alpha-1-0-0">`) {
		t.Error("expected collapsible group with package anchor id for alpha")
	}
	if !strings.Contains(html, "a/alpha.jar") {
		t.Error("expected the alpha occurrence delivery path to appear")
	}
	if !strings.Contains(html, "pkg:maven/com.acme/alpha@1.0.0") {
		t.Error("expected the alpha PURL to appear")
	}
}

// TestNormalizationAndMethodAndResidual verifies the remaining shared-content
// sections render with their localized prose and links.
func TestNormalizationAndMethodAndResidual(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, richReportData(), "en")

	// Method At A Glance: SCAN_APPROACH.md link + a deep link.
	if !strings.Contains(html, `href="https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"`) {
		t.Error("Method section should link to SCAN_APPROACH.md")
	}
	if !strings.Contains(html, "#3-two-mandatory-phases-plus-one-optional-enrichment-phase") {
		t.Error("Method section should embed the two-phases deep link")
	}
	// Residual Risk: PURL coverage prose is always emitted.
	if !strings.Contains(html, `id="residual-risk-and-limitations"`) {
		t.Error("Residual Risk section missing")
	}
	// Normalization: the four reason buckets as collapsibles.
	for _, want := range []string{
		`id="suppression-fs-artifacts"`,
		`id="suppression-low-value-file-artifacts"`,
		`id="suppression-weak-duplicates"`,
		`id="suppression-purl-duplicates"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("Normalization missing bucket %q", want)
		}
	}
	// Processing Errors + Policy Decisions from rich data.
	if !strings.Contains(html, "scanner failed on empty.jar") {
		t.Error("Processing Errors should list the scan issue")
	}
	if !strings.Contains(html, "max-depth") {
		t.Error("Policy Decisions should list the decision trigger")
	}
}
