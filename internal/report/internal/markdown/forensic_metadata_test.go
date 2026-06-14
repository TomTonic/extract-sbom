package markdown

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// TestHeaderGeneratedTimestampUsesRunTimeNotBuildTime verifies that the report
// header documents when the analysis actually ran (run end time), not when the
// extract-sbom binary was built. The build time must only appear in the
// configuration provenance row.
func TestHeaderGeneratedTimestampUsesRunTimeNotBuildTime(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Generator = buildinfo.Info{Version: "v1.2.3", Revision: "abc123", Time: "2099-12-31T00:00:00Z"}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	lines := strings.Split(buf.String(), "\n")

	var header string
	for _, line := range lines {
		if strings.Contains(line, "Report generated") {
			header = line
			break
		}
	}
	if header == "" {
		t.Fatal("report header missing 'Report generated' line")
	}
	if !strings.Contains(header, "2025-01-15T10:00:05Z") {
		t.Errorf("header should show run end time, got: %s", header)
	}
	if strings.Contains(header, "2099-12-31T00:00:00Z") {
		t.Errorf("header must not show binary build time, got: %s", header)
	}
}

// TestInputSectionContainsRunProvenance verifies that the input section carries
// the run identity and timing needed for dispute-grade auditability.
func TestInputSectionContainsRunProvenance(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(makeTestReportData(), "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"| Run ID | `run:",
		"| Analysis started | 2025-01-15T10:00:00Z |",
		"| Analysis finished | 2025-01-15T10:00:05Z |",
		"| Duration | 5s |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("input section missing run provenance %q", want)
		}
	}
}

// TestRunScopeAppearsBeforeAppendix verifies that the "Run & Scope" block
// (input file, configuration, sandbox) appears directly after the Summary and
// before the Appendix, so auditors do not have to scroll through the large
// Component Occurrence Index to find provenance information.
func TestRunScopeAppearsBeforeAppendix(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(makeTestReportData(), "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	out := buf.String()

	// Use H2 markers to find actual section headings, not TOC entries.
	posRunScope := strings.Index(out, "## Run & Scope")
	posSummary := strings.Index(out, "## Summary")
	posAppendix := strings.Index(out, "## Appendix")
	posInputInAppendix := strings.Index(out[posAppendix:], "## Input File")

	if posRunScope < 0 {
		t.Fatal("'## Run & Scope' section heading not found")
	}
	if posSummary < 0 || posRunScope < posSummary {
		t.Errorf("'Run & Scope' heading should appear after Summary (summary=%d, runScope=%d)", posSummary, posRunScope)
	}
	if posAppendix < 0 || posRunScope > posAppendix {
		t.Errorf("'Run & Scope' heading should appear before Appendix (runScope=%d, appendix=%d)", posRunScope, posAppendix)
	}
	if posInputInAppendix >= 0 {
		t.Error("'## Input File' must not appear as a standalone H2 section inside the Appendix area")
	}
}

// TestToolProvenanceLineListsAllToolsAndGrypeDB verifies that every external
// tool version and the Grype database provenance are surfaced for supply-chain
// reproducibility, not just the Grype scanner version.
func TestToolProvenanceLineListsAllToolsAndGrypeDB(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	// Use realistic version strings that match what the external tools emit:
	// 7-Zip prefixes its own name, unshield uses "Unshield version X", grype
	// is stored as "grype <version>" by the orchestrator.
	data.ToolVersions = ToolVersions{
		SevenZip:   "7-Zip (z) 23.01 (x64)",
		Unshield:   "Unshield version 1.5.0",
		Unsquashfs: "unsquashfs version 4.6",
		Grype:      "grype 0.74.0",
	}
	data.Vulnerabilities = &vulnscan.Result{
		Requested:       true,
		State:           vulnscan.StateCompleted,
		GrypeVersion:    "0.74.0",
		DBSchemaVersion: "5",
		DBBuilt:         "2025-01-10T00:00:00Z",
		DBUpdated:       "2025-01-14T00:00:00Z",
	}
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "r",
		Name:       "x",
		Version:    "1",
		Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "x.jar"}},
	}}}

	var buf bytes.Buffer
	if err := GenerateMarkdownWithOptions(data, "en", &buf, RenderOptions{}); err != nil {
		t.Fatalf("GenerateMarkdownWithOptions error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"7-Zip (z) 23.01",
		"Unshield version 1.5.0",
		"unsquashfs version 4.6",
		"grype 0.74.0",
		"Grype DB: schema=`5` built=`2025-01-10T00:00:00Z` updated=`2025-01-14T00:00:00Z`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tool provenance missing %q", want)
		}
	}
}
