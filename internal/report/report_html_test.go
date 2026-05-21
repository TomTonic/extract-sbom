// HTML report tests validate the self-contained HTML audit report from the
// reader's perspective: the document must be well formed, must honor the
// configured output language, must escape untrusted input, and — most
// importantly for an audit artifact — must let a reader tell "no
// vulnerabilities found" apart from "enrichment was not requested" or "Grype
// was unavailable". These behaviors belong to the report module's HTML
// rendering responsibility.
package report

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// renderHTML renders the HTML report for the given data and language.
func renderHTML(t *testing.T, data ReportData, language string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := GenerateHTML(data, language, &buf); err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	return buf.String()
}

// TestGenerateHTMLProducesWellFormedDocument verifies that the HTML report is a
// complete document with the expected language attribute and core sections.
func TestGenerateHTMLProducesWellFormedDocument(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "en")
	for _, want := range []string{
		"<!DOCTYPE html>",
		`<html lang="en">`,
		"<title>extract-sbom Audit Report</title>",
		"<h2>Summary</h2>",
		"<h2>Extraction Overview</h2>",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing expected fragment %q", want)
		}
	}
}

// TestGenerateHTMLUsesGermanLabelsForDE verifies that requesting the German
// language renders German section labels — i.e. the report is genuinely
// localized and not hard-coded to English.
func TestGenerateHTMLUsesGermanLabelsForDE(t *testing.T) {
	t.Parallel()

	html := renderHTML(t, makeTestReportData(), "de")
	for _, want := range []string{
		`<html lang="de">`,
		"<h2>Zusammenfassung</h2>",
		"<h2>Extraktionsübersicht</h2>",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("German HTML report missing expected fragment %q", want)
		}
	}
	if strings.Contains(html, "<h2>Extraction Overview</h2>") {
		t.Error("German HTML report still contains the English heading 'Extraction Overview'")
	}
}

// TestGenerateHTMLDistinguishesVulnerabilityAuditStates verifies that the
// Vulnerabilities summary cell renders a distinct, non-misleading value for
// each enrichment outcome. A bare "0" must never stand in for "not requested"
// or "unavailable".
func TestGenerateHTMLDistinguishesVulnerabilityAuditStates(t *testing.T) {
	t.Parallel()

	oneMatch := map[string][]vulnscan.VMatch{
		"ref-a": {{VulnerabilityID: "CVE-2024-0001", Severity: "high"}},
	}

	cases := []struct {
		name     string
		vulns    *vulnscan.Result
		wantCell string
	}{
		{
			name:     "enrichment not requested",
			vulns:    nil,
			wantCell: `<td>Vulnerabilities</td><td><span class="muted">not requested</span>`,
		},
		{
			name:     "explicit not-requested state",
			vulns:    &vulnscan.Result{Requested: false, State: vulnscan.StateNotRequested},
			wantCell: `<td>Vulnerabilities</td><td><span class="muted">not requested</span>`,
		},
		{
			name:     "grype unavailable",
			vulns:    &vulnscan.Result{Requested: true, State: vulnscan.StateUnavailable},
			wantCell: `<td>Vulnerabilities</td><td><span class="err">unavailable</span>`,
		},
		{
			name:     "completed with no matches",
			vulns:    &vulnscan.Result{Requested: true, State: vulnscan.StateCompleted},
			wantCell: `<td>Vulnerabilities</td><td><span class="ok">0</span>`,
		},
		{
			name: "completed with one match",
			vulns: &vulnscan.Result{
				Requested:       true,
				State:           vulnscan.StateCompleted,
				MatchesByBOMRef: oneMatch,
			},
			wantCell: `<td>Vulnerabilities</td><td><span class="badge high">1</span>`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := makeTestReportData()
			data.Vulnerabilities = tc.vulns
			html := renderHTML(t, data, "en")
			if !strings.Contains(html, tc.wantCell) {
				t.Errorf("Vulnerabilities summary cell missing %q", tc.wantCell)
			}
		})
	}
}

// TestGenerateHTMLEscapesUntrustedInput verifies that attacker-controlled text
// (here, the input file name) is HTML-escaped so the report cannot be used as
// an XSS vector.
func TestGenerateHTMLEscapesUntrustedInput(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Input.Filename = "<script>alert(1)</script>.zip"
	html := renderHTML(t, data, "en")

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("HTML report contains an unescaped <script> tag from the input file name")
	}
	// The file name content is still present, but only in escaped form.
	if !strings.Contains(html, "alert(1)") {
		t.Error("HTML report dropped the input file name entirely")
	}
	if !strings.Contains(html, "&lt;") {
		t.Error("HTML report does not contain any HTML-escaped markup from the input file name")
	}
}

// TestGenerateHTMLListsExternalToolVersions verifies that detected external
// tool versions — including the SquashFS extractor unsquashfs — are surfaced in
// the report.
func TestGenerateHTMLListsExternalToolVersions(t *testing.T) {
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

// TestGenerateHTMLRendersVulnerabilityTable verifies that, when matches exist,
// they are rendered as table rows correlated to the owning component.
func TestGenerateHTMLRendersVulnerabilityTable(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{BOMRef: "ref-a", Name: "libcurl", Version: "8.0.0"},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-a": {{VulnerabilityID: "CVE-2024-0001", Severity: "critical", Description: "buffer overflow"}},
		},
	}
	html := renderHTML(t, data, "en")

	for _, want := range []string{"CVE-2024-0001", "libcurl", "buffer overflow"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML vulnerability table missing %q", want)
		}
	}
}
