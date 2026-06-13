package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestGenerateHumanIncludesGeneratorBuildInfo verifies that build metadata
// for the generator is visible in the report header (not in the configuration table).
func TestGenerateHumanIncludesGeneratorBuildInfo(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}

	output := buf.String()
	// Build info lives in the report header line, not in the Configuration table.
	if !strings.Contains(output, "**extract-sbom version:**") {
		t.Fatal("report header does not contain extract-sbom version")
	}
	if !strings.Contains(output, "v1.2.3") {
		t.Fatal("report does not contain generator version v1.2.3")
	}
	// Build info must NOT appear as a separate configuration table row any more.
	if strings.Contains(output, "| extract-sbom build |") {
		t.Fatal("generator build row should no longer appear in the configuration table")
	}
}

// TestGenerateHumanContainsRequiredSections verifies that the English
// Markdown report contains all required sections from DESIGN.md §10.4.
func TestGenerateHumanContainsRequiredSections(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}

	output := buf.String()

	requiredSections := []string{
		"# extract-sbom Audit Report",
		"## Table of Contents",
		"## Summary",
		"### Analysis Overview",
		"### Key Findings",
		"### Vulnerability Summary",
		"## Method At A Glance",
		"## Processing Errors",
		"## Residual Risk and Limitations",
		"## Appendix",
		"## Component Occurrence Index",
		"## Component Normalization",
		"## Input File",
		"## Configuration",
		"## Extension Filter",
		"## Root SBOM Metadata",
		"## Sandbox Configuration",
		"## Policy Decisions",
		"## Extraction Log",
		"## Package Scan Log",
		"End of report.",
	}

	for _, section := range requiredSections {
		if !strings.Contains(output, section) {
			t.Errorf("missing required section %q", section)
		}
	}
}

// TestGenerateHumanContainsInputHashes verifies that the report includes
// both SHA-256 and SHA-512 hashes of the input file.
func TestGenerateHumanContainsInputHashes(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, data.Input.SHA256) {
		t.Error("report does not contain SHA-256 hash")
	}

	if !strings.Contains(output, data.Input.SHA512) {
		t.Error("report does not contain SHA-512 hash")
	}
}

// TestGenerateHumanGermanTranslation verifies that the German report
// uses German section headers and labels.
func TestGenerateHumanGermanTranslation(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "de", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}

	output := buf.String()

	germanHeaders := []string{
		"# extract-sbom Prüfbericht",
		"## Eingabedatei",
		"## Konfiguration",
	}

	for _, header := range germanHeaders {
		if !strings.Contains(output, header) {
			t.Errorf("missing German header %q", header)
		}
	}
}

// TestGenerateHumanWithUnsafeShowsWarning verifies that the report warns when
// --unsafe was used AND bwrap was available (i.e. the user deliberately bypassed it).
func TestGenerateHumanWithUnsafeShowsWarning(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.UnsafeOvr = true
	data.SandboxInfo.BwrapFound = true // bwrap present but bypassed → WARNING expected

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "WARNING") {
		t.Error("unsafe mode report does not contain WARNING when bwrap was available")
	}
	if !strings.Contains(output, "Unsafe mode active") || !strings.Contains(output, "no sandbox isolation") {
		t.Error("unsafe mode report does not explain the risk")
	}
}

// TestGenerateHumanWithUnsafeNoWarningWhenBwrapAbsent verifies that no WARNING
// is emitted when --unsafe is set but bwrap was never available (e.g. macOS).
func TestGenerateHumanWithUnsafeNoWarningWhenBwrapAbsent(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.UnsafeOvr = true
	data.SandboxInfo.BwrapFound = false // bwrap absent → no WARNING

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "WARNING") {
		t.Error("report should not emit WARNING when bwrap was not available on this platform")
	}
}

// TestGenerateHumanWithPolicyDecisions verifies that policy decisions
// are included in the report when present.
func TestGenerateHumanWithPolicyDecisions(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.PolicyDecisions = []policy.Decision{
		{
			Trigger:  "max-depth",
			NodePath: "/deeply/nested/archive.zip",
			Action:   policy.ActionSkip,
			Detail:   "Resource limit max-depth exceeded",
		},
	}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Policy Decisions") {
		t.Error("report does not contain Policy Decisions section")
	}

	if !strings.Contains(output, "max-depth") {
		t.Error("report does not contain the policy trigger")
	}
}

// TestGenerateHumanWithProcessingIssues verifies that processing-stage errors
// are documented in a dedicated section for operator auditability.
func TestGenerateHumanWithProcessingIssues(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.ProcessingIssues = []ProcessingIssue{{
		Stage:   "assembly",
		Message: "failed to merge components",
	}}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "## Processing Errors") {
		t.Fatal("report does not contain Processing Errors section")
	}
	if !strings.Contains(output, "| Source | Location | Class | Status | Detected | Tool | Archive Type | Archive Method | Encrypted | Physical Size | Detail |") {
		t.Fatal("report does not contain structured processing issue header")
	}
	if !strings.Contains(output, "| pipeline | assembly | pipeline-error |") || !strings.Contains(output, "failed to merge components") {
		t.Fatal("report does not contain processing issue details")
	}
}

// TestGenerateHumanTOCContainsAnchorLinks verifies that the Table of Contents
// includes clickable anchor links for all major sections.
func TestGenerateHumanTOCContainsAnchorLinks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, link := range []string{
		"- [Summary](#summary)",
		"  - [Analysis Overview](#analysis-overview)",
		"  - [Key Findings](#key-findings)",
		"  - [Vulnerability Summary](#vulnerability-summary)",
		"- [Method At A Glance](#method-at-a-glance)",
		"- [Processing Errors](#processing-errors)",
		"- [Residual Risk and Limitations](#residual-risk-and-limitations)",
		"- [Appendix](#appendix)",
		"- [Component Occurrence Index](#component-occurrence-index)",
		"    - [Components with PURL](#components-with-purl)",
		"    - [Components without PURL](#components-without-purl)",
		"- [Component Normalization](#component-normalization)",
		"    - [FS-cataloger artifact](#suppression-fs-artifacts)",
		"    - [File with no identification metadata](#suppression-low-value-file-artifacts)",
		"    - [Weak duplicate](#suppression-weak-duplicates)",
		"    - [PURL duplicate](#suppression-purl-duplicates)",
		"- [Input File](#input-file)",
		"- [Configuration](#configuration)",
		"- [Extension Filter](#extension-filter)",
		"- [Policy Decisions](#policy-decisions)",
		"- [Package Scan Log](#scan-results)",
		"- [Extraction Log](#extraction-log)",
	} {
		if !strings.Contains(output, link) {
			t.Fatalf("report table of contents missing %q", link)
		}
	}
}

func TestGenerateHumanAvoidsDuplicateExplicitAnchorsForNaturalHeadingSlugs(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, anchor := range []string{
		"summary",
		"analysis-overview",
		"key-findings",
		"vulnerability-summary",
		"method-at-a-glance",
		"processing-errors",
		"residual-risk-and-limitations",
		"appendix",
		"component-occurrence-index",
		"component-normalization",
		"input-file",
		"configuration",
		"extension-filter",
		"root-sbom-metadata",
		"sandbox-configuration",
		"policy-decisions",
		"content-items-without-package-identities",
		"extraction-log",
	} {
		if strings.Contains(output, "<a id=\""+anchor+"\"></a>") {
			t.Fatalf("report should rely on Markdown heading slug for %q", anchor)
		}
	}

	if !strings.Contains(output, "<a id=\"scan-results\"></a>") {
		t.Fatal("report should keep explicit anchor when heading slug differs from link target")
	}
}

// TestGenerateHumanSectionOrderPutsExecutiveSectionsFirst verifies that
// Summary/method/errors/risk appear before the large appendix sections.
func TestGenerateHumanSectionOrderPutsExecutiveSectionsFirst(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	summaryIdx := strings.Index(output, "## Summary")
	methodIdx := strings.Index(output, "## Method At A Glance")
	errorsIdx := strings.Index(output, "## Processing Errors")
	riskIdx := strings.Index(output, "## Residual Risk and Limitations")
	appendixIdx := strings.Index(output, "## Appendix")
	indexIdx := strings.Index(output, "## Component Occurrence Index")
	scanIdx := strings.Index(output, "## Package Scan Log")
	extractionIdx := strings.Index(output, "## Extraction Log")

	if summaryIdx == -1 || methodIdx == -1 || errorsIdx == -1 || riskIdx == -1 || appendixIdx == -1 || indexIdx == -1 || scanIdx == -1 || extractionIdx == -1 {
		t.Fatal("one or more expected sections are missing")
	}

	if summaryIdx >= appendixIdx || methodIdx >= appendixIdx ||
		summaryIdx >= scanIdx || summaryIdx >= extractionIdx ||
		methodIdx >= scanIdx || methodIdx >= extractionIdx ||
		errorsIdx >= scanIdx || errorsIdx >= extractionIdx ||
		riskIdx >= scanIdx || riskIdx >= extractionIdx ||
		appendixIdx >= indexIdx {
		t.Fatal("executive guidance is not placed before the appendix bulk sections")
	}
}

func TestGenerateHumanIncludesMethodDeepLinks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer

	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, fragment := range []string{
		"https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md#3-two-phases",
		"https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md#81-how-deduplication-works",
		"https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md#6-package-detection-reliability",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
	}
}

// TestGenerateHumanWithScanResults verifies that scan results
// are displayed in the report.
func TestGenerateHumanWithScanResults(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Scans = []scan.ScanResult{
		{
			NodePath: "test.zip",
			BOM: &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "express", Version: "4.18.0"},
					{Name: "lodash", Version: "4.17.21"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "2 components found") {
		t.Error("report does not show component count")
	}
	if !strings.Contains(output, "## Package Scan Log") {
		t.Error("report does not contain Package Scan Log section")
	}
	if !strings.Contains(output, "This is a per-item package scan log") {
		t.Error("scan log does not explain its item-level semantics")
	}
}

// TestGenerateHumanRootPropertiesAreSorted verifies that repeated runs render
// root metadata properties in deterministic key order for audit stability.
func TestGenerateHumanRootPropertiesAreSorted(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Config.RootMetadata.Properties = map[string]string{
		"zeta":  "last",
		"alpha": "first",
		"mu":    "middle",
	}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	alphaIdx := strings.Index(output, "| alpha | first | User-supplied |")
	muIdx := strings.Index(output, "| mu | middle | User-supplied |")
	zetaIdx := strings.Index(output, "| zeta | last | User-supplied |")
	if alphaIdx == -1 || muIdx == -1 || zetaIdx == -1 {
		t.Fatal("expected sorted root property rows to be present in markdown report")
	}
	if alphaIdx >= muIdx || muIdx >= zetaIdx {
		t.Fatalf("root properties are not sorted deterministically: alpha=%d mu=%d zeta=%d", alphaIdx, muIdx, zetaIdx)
	}
}

// TestGenerateHumanIncludesNestedExtractionEvidenceAndPolicyDetails verifies
// that the markdown report includes the full extraction tree, evidence paths, and
// explanatory policy decisions for a nested delivery.
func TestGenerateHumanIncludesNestedExtractionEvidenceAndPolicyDetails(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "delivery.cab",
		Status: extract.StatusExtracted,
		Format: identify.FormatInfo{Format: identify.CAB},
		Tool:   "7zz",
		Children: []*extract.ExtractionNode{{
			Path:   "delivery.cab/layer.tar",
			Status: extract.StatusExtracted,
			Format: identify.FormatInfo{Format: identify.TAR},
			Tool:   "archive/tar",
			Children: []*extract.ExtractionNode{{
				Path:   "delivery.cab/layer.tar/app.zip",
				Status: extract.StatusExtracted,
				Format: identify.FormatInfo{Format: identify.ZIP},
				Tool:   "archive/zip",
				Children: []*extract.ExtractionNode{{
					Path:   "delivery.cab/layer.tar/app.zip/lib.jar",
					Status: extract.StatusSyftNative,
					Format: identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
					Tool:   "syft",
				}},
			}},
		}},
	}
	data.Scans = []scan.ScanResult{{
		NodePath: "delivery.cab/layer.tar/app.zip/lib.jar",
		BOM: &cdx.BOM{Components: &[]cdx.Component{{
			BOMRef:  "pkg:maven/com.acme/demo@1.0.0",
			Name:    "demo",
			Version: "1.0.0",
		}}},
		EvidencePaths: map[string][]string{
			"pkg:maven/com.acme/demo@1.0.0": {"delivery.cab/layer.tar/app.zip/lib.jar/META-INF/MANIFEST.MF"},
		},
	}}
	data.PolicyDecisions = []policy.Decision{{
		Trigger:  "max-depth",
		NodePath: "delivery.cab/layer.tar/deeper.zip",
		Action:   policy.ActionSkip,
		Detail:   "Resource limit max-depth exceeded at delivery.cab/layer.tar/deeper.zip (partial mode: skipping subtree)",
	}}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}
	output := buf.String()

	for _, fragment := range []string{
		"delivery.cab",
		"delivery.cab/layer.tar",
		"delivery.cab/layer.tar/app.zip",
		"delivery.cab/layer.tar/app.zip/lib.jar",
		"1 components found",
		"evidence-path: `delivery.cab/layer.tar/app.zip/lib.jar/META-INF/MANIFEST.MF`",
		"max-depth",
		"partial mode: skipping subtree",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("report output missing %q", fragment)
		}
	}
}

// TestEscapeMarkdownText verifies that angle brackets in user-supplied strings
// are escaped to HTML entities when rendered in headings.
func TestEscapeMarkdownText(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"TODO: <Produktname>", "TODO: &lt;Produktname&gt;"},
		{"<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"a > b < c", "a &gt; b &lt; c"},
	}
	for _, tc := range cases {
		got := escapeMarkdownText(tc.in)
		if got != tc.want {
			t.Errorf("escapeMarkdownText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPackageHeadingEscapesAngleBrackets verifies that a package with angle
// brackets in its name is rendered as an escaped H4 heading (not raw HTML).
func TestPackageHeadingEscapesAngleBrackets(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "extract-sbom:ABCD_1234",
		Name:       "TODO: <Produktname>",
		Version:    "1.0.0.1",
		PackageURL: "pkg:generic/todo/produktname@1.0.0.1",
		Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "native/rsDomus.dll"}},
	}}}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "#### TODO: <Produktname>") {
		t.Error("unescaped angle brackets must not appear in H4 heading")
	}
	if !strings.Contains(output, "#### TODO: &lt;Produktname&gt;") {
		t.Error("escaped heading TODO: &lt;Produktname&gt; missing from report")
	}
}

// TestConfigDefaultMarkers verifies that configuration values matching the
// defaults are annotated with "(default)" in the Configuration table.
func TestConfigDefaultMarkers(t *testing.T) {
	t.Parallel()

	data := makeTestReportData() // uses config.DefaultConfig()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	for _, want := range []string{
		"| Policy mode | strict (default) |",
		"| Interpretation mode | installer-semantic (default) |",
		"| Language | en (default) |",
		"| sbom-format | cyclonedx-json (default) |",
		"| report-selection | markdown (default) |",
		"| grype | false (default) |",
		"| unsafe | false (default) |",
		"| Max depth | 6 (default) |",
		"| Max files | 200000 (default) |",
		"| Timeout | 1m0s (default) |",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("configuration table missing %q", want)
		}
	}
	if strings.Contains(output, "| extract-sbom build |") {
		t.Error("generator build row should not appear in configuration table")
	}
	if strings.Contains(output, "| Progress |") {
		t.Error("progress row should not appear in configuration table")
	}
}

// TestConfigNonDefaultValuesHaveNoMarker verifies that explicitly-set non-default
// values do not get the "(default)" annotation.
func TestConfigNonDefaultValuesHaveNoMarker(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Config.PolicyMode = config.PolicyPartial // non-default
	data.Config.Language = "de"                   // non-default
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "| Policy mode | partial (default) |") {
		t.Error("non-default value 'partial' should not be marked as default")
	}
	if strings.Contains(output, "| Language | de (default) |") {
		t.Error("non-default value 'de' should not be marked as default")
	}
}

// TestVulnSummaryNoTableWhenNotRequested verifies that when grype was not
// requested the Vulnerability Summary shows only the informational line and
// no empty table.
func TestVulnSummaryNoTableWhenNotRequested(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Vulnerability enrichment: not requested") {
		t.Error("expected 'Vulnerability enrichment: not requested' in report")
	}
	if strings.Contains(output, "| Vulnerability | Severity |") {
		t.Error("empty vulnerability table must not appear when grype was not requested")
	}
}

// TestKeyFindingsNotRequestedWhenGrypeOff verifies that the Key Findings bullet
// does not falsely claim "scan complete" when grype was not requested.
func TestKeyFindingsVulnNotRequested(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "Vulnerability scan complete") {
		t.Error("Key Findings should not say 'scan complete' when grype was not requested")
	}
	if !strings.Contains(output, "Vulnerability scan not requested") {
		t.Error("Key Findings should say 'scan not requested' when grype was not requested")
	}
}

// TestMethodAtAGlanceLinksDocumentAndBullets verifies the restructured section:
// lead contains a Markdown link to SCAN_APPROACH.md, bullets embed deep links,
// and the old "Deep links into SCAN_APPROACH.md:" paragraph is gone.
func TestMethodAtAGlanceLinksDocumentAndBullets(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "[SCAN_APPROACH.md](https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md)") {
		t.Error("Method section lead should link to SCAN_APPROACH.md")
	}
	if strings.Contains(output, "Deep links into SCAN_APPROACH.md:") {
		t.Error("old 'Deep links into SCAN_APPROACH.md:' paragraph should be removed")
	}
	if !strings.Contains(output, "[Two phases]") {
		t.Error("Two phases link should appear embedded in a bullet")
	}
	if !strings.Contains(output, "[Deduplication]") {
		t.Error("Deduplication link should appear embedded in a bullet")
	}
}

// TestComponentIndexSortedAlphabetically verifies that the Component Occurrence
// Index is sorted by (package name, version) case-insensitively.
func TestComponentIndexSortedAlphabetically(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef: "extract-sbom:ZZZ", Name: "zlib", Version: "1.0",
			PackageURL: "pkg:generic/zlib@1.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "z/zlib.so"}},
		},
		{
			BOMRef: "extract-sbom:MMM", Name: "mongoose", Version: "7.14",
			PackageURL: "pkg:generic/mongoose@7.14",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "m/mongoose.so"}},
		},
		{
			BOMRef: "extract-sbom:AAA", Name: "alpha", Version: "2.0",
			PackageURL: "pkg:generic/alpha@2.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "a/alpha.so"}},
		},
	}}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	alphaIdx := strings.Index(output, "#### alpha 2.0")
	mongooseIdx := strings.Index(output, "#### mongoose 7.14")
	zlibIdx := strings.Index(output, "#### zlib 1.0")

	if alphaIdx == -1 || mongooseIdx == -1 || zlibIdx == -1 {
		t.Fatal("one or more package headings missing")
	}
	if !(alphaIdx < mongooseIdx && mongooseIdx < zlibIdx) {
		t.Errorf("component index not sorted alphabetically: alpha=%d mongoose=%d zlib=%d",
			alphaIdx, mongooseIdx, zlibIdx)
	}
}

// TestVulnSummaryHeadingAbsentWhenNotRequested verifies that the
// "Vulnerability summary (grype-inspired view):" heading does not appear
// when --grype was not requested.
func TestVulnSummaryHeadingAbsentWhenNotRequested(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "Vulnerability summary (grype-inspired view):") {
		t.Error("vuln summary heading must not appear when grype was not requested")
	}
}

// TestSkipExtensionsDefaultMarker verifies that the skip-extensions row shows
// "(default)" when the configured list matches the default list.
func TestSkipExtensionsDefaultMarker(t *testing.T) {
	t.Parallel()

	data := makeTestReportData() // uses config.DefaultConfig() → default SkipExtensions
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "(default)") || !strings.Contains(output, ".doc, .dot") {
		t.Error("skip-extensions with default list should include '(default)' marker")
	}
	// Verify the full marker is in the skip-extensions row specifically.
	if !strings.Contains(output, "| skip-extensions | .doc") {
		t.Error("skip-extensions row not found")
	}
	if !strings.Contains(output, ".pdf (default) |") {
		t.Error("skip-extensions default marker missing at end of value")
	}
}

// TestSkipExtensionsNoDefaultMarkerWhenCustom verifies that a custom
// skip-extensions list does not receive the "(default)" marker.
func TestSkipExtensionsNoDefaultMarkerWhenCustom(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Config.SkipExtensions = []string{".tmp", ".log"}
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if strings.Contains(output, "| skip-extensions | .tmp, .log (default) |") {
		t.Error("custom skip-extensions list must not be marked as default")
	}
	if !strings.Contains(output, "| skip-extensions | .tmp, .log |") {
		t.Error("custom skip-extensions list not rendered correctly")
	}
}

// TestConfigTableHasNewRows verifies that the config table now includes
// unsafe, sbom-format, report-selection, and parallel-scanners rows.
func TestConfigTableHasNewRows(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	for _, row := range []string{
		"| unsafe |",
		"| sbom-format |",
		"| report-selection |",
		"| parallel-scanners |",
	} {
		if !strings.Contains(output, row) {
			t.Errorf("config table missing row %q", row)
		}
	}
}

// TestSandboxProseWhenBwrapAbsent verifies that when bwrap is not available
// the sandbox section shows explanatory prose instead of a misleading table.
func TestSandboxProseWhenBwrapAbsent(t *testing.T) {
	t.Parallel()

	data := makeTestReportData() // BwrapFound=false by default
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "bwrap") {
		t.Error("sandbox section should mention bwrap when it is absent")
	}
	if !strings.Contains(output, "passthrough mode") {
		t.Error("sandbox section should mention passthrough mode when bwrap is absent")
	}
	// The raw "Available: true" table row must not appear on macOS.
	if strings.Contains(output, "| Available | true |") {
		t.Error("misleading 'Available: true' table row must not appear when bwrap is absent")
	}
}

// TestSandboxTableWhenBwrapPresent verifies that when bwrap IS available and
// active (no --unsafe), the sandbox section shows the status table, not prose.
func TestSandboxTableWhenBwrapPresent(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SandboxInfo.BwrapFound = true
	data.SandboxInfo.Name = "bubblewrap"
	data.SandboxInfo.Available = true
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "| Sandbox | bubblewrap |") {
		t.Error("sandbox table row 'bubblewrap' missing when bwrap is present")
	}
	if strings.Contains(output, "WARNING") {
		t.Error("no WARNING expected when bwrap is present but --unsafe was not used")
	}
	if strings.Contains(output, "passthrough mode") {
		t.Error("passthrough prose must not appear when bwrap IS available")
	}
}

// TestSuppressionSubsectionsAreH3 verifies that the four Component Normalization
// subsections are rendered as H3 (###) headings, not H4 (####).
func TestSuppressionSubsectionsAreH3(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	for _, heading := range []string{
		"### FS-cataloger artifact",
		"### File with no identification metadata",
		"### Weak duplicate",
		"### PURL duplicate",
	} {
		if !strings.Contains(output, heading) {
			t.Errorf("suppression subsection not H3: want %q in output", heading)
		}
	}
	for _, heading := range []string{
		"#### FS-cataloger artifact",
		"#### File with no identification metadata",
		"#### Weak duplicate",
		"#### PURL duplicate",
	} {
		if strings.Contains(output, heading) {
			t.Errorf("suppression subsection must not be H4: found %q in output", heading)
		}
	}
}

// TestTOCContainsSuppressionSubsections verifies that the four suppression-reason
// subsections appear in the Table of Contents with their correct anchors.
func TestTOCContainsSuppressionSubsections(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	output := buf.String()

	for _, link := range []string{
		"[FS-cataloger artifact](#suppression-fs-artifacts)",
		"[File with no identification metadata](#suppression-low-value-file-artifacts)",
		"[Weak duplicate](#suppression-weak-duplicates)",
		"[PURL duplicate](#suppression-purl-duplicates)",
	} {
		if !strings.Contains(output, link) {
			t.Errorf("ToC missing suppression subsection entry %q", link)
		}
	}
}
