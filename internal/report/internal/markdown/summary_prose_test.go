package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// richReportData returns report data that exercises every conditional prose
// branch in the Summary and Residual Risk sections (vulnerabilities, empty
// scans, policy decisions, scan-stage issues), so format-string contracts are
// covered for every templated line.
func richReportData() ReportData {
	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "ref-a",
			Name:       "alpha",
			Version:    "1.0.0",
			PackageURL: "pkg:maven/com.acme/alpha@1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "a/alpha.jar"}},
		},
		{
			BOMRef:     "ref-b",
			Name:       "beta",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "b/beta.bin"}},
		},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-a": {{VulnerabilityID: "CVE-2026-1", Severity: "high"}},
		},
	}
	data.Scans = []scan.ScanResult{{NodePath: "empty.jar", BOM: &cdx.BOM{Components: &[]cdx.Component{}}}}
	data.PolicyDecisions = []policy.Decision{{Trigger: "max-depth", NodePath: "deep.zip", Action: policy.ActionSkip, Detail: "limit"}}
	data.ProcessingIssues = []ProcessingIssue{{Stage: "scan", Message: "scanner failed on empty.jar"}}
	return data
}

// TestSummaryProseHasNoFormatPlaceholders guards against argument/verb mismatches
// in the i18n templates used by the Summary and Residual Risk sections. A wrong
// fmt.Sprintf argument count or type renders Go's "%!..." placeholder, which is
// what this test rejects. It runs for every supported language.
func TestSummaryProseHasNoFormatPlaceholders(t *testing.T) {
	t.Parallel()

	for _, lang := range []string{"en", "de"} {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := GenerateMarkdownWithOptions(richReportData(), lang, &buf, RenderOptions{}); err != nil {
				t.Fatalf("GenerateMarkdownWithOptions(%s) error: %v", lang, err)
			}
			for i, line := range strings.Split(buf.String(), "\n") {
				if strings.Contains(line, "%!") {
					t.Errorf("[%s] format placeholder leaked on line %d: %s", lang, i, line)
				}
			}
		})
	}
}

// TestSummaryProseRendersComputedMetrics verifies that the Summary prose is wired
// to the projection metrics (not just free of placeholders): the delivery
// composition, PURL coverage, and vulnerability counts must reflect the input.
func TestSummaryProseRendersComputedMetrics(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(richReportData(), "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		// delivery composition: 2 indexed components, 1 with PURL / 1 without
		"2 distinct software components",
		// PURL coverage finding: "1 of 2 package occurrences"
		"1 of 2 package occurrences",
		// vulnerability matches finding: "1 vulnerability matches in 1 packages (1 unique CVEs)"
		"1 vulnerability matches in 1 packages (1 unique CVEs)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary prose missing computed metric %q", want)
		}
	}
}
