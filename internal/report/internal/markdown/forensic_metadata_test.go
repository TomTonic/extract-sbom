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

// TestToolProvenanceLineListsAllToolsAndGrypeDB verifies that every external
// tool version and the Grype database provenance are surfaced for supply-chain
// reproducibility, not just the Grype scanner version.
func TestToolProvenanceLineListsAllToolsAndGrypeDB(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.ToolVersions = ToolVersions{SevenZip: "23.01", Unshield: "1.5.0", Unsquashfs: "4.6"}
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
		"7-Zip 23.01",
		"unshield 1.5.0",
		"unsquashfs 4.6",
		"grype 0.74.0",
		"Grype DB: schema=`5` built=`2025-01-10T00:00:00Z` updated=`2025-01-14T00:00:00Z`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tool provenance missing %q", want)
		}
	}
}
