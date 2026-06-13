package html

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// TestOrderingContractVulnerabilities verifies that HTML vulnerability rows are
// sorted by severity rank and then by package name as produced by the JSON v2
// projection layer consumed by the HTML renderer.
func TestOrderingContractVulnerabilities(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{BOMRef: "ref-z", Name: "zlib", Version: "1.2.13"},
		{BOMRef: "ref-a", Name: "alpha", Version: "1.0.0"},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-z": {
				{VulnerabilityID: "CVE-2026-0002", Severity: "medium"},
				{VulnerabilityID: "CVE-2026-0001", Severity: "high"},
			},
			"ref-a": {
				{VulnerabilityID: "CVE-2026-0001", Severity: "critical"},
			},
		},
	}

	rows := buildPage(data, "en").Vuln.Rows
	if len(rows) != 3 {
		t.Fatalf("expected 3 vulnerability rows, got %d", len(rows))
	}
	// JSON v2 projection sorts by severity rank (critical < high < medium), then name.
	wantID := []string{"CVE-2026-0001", "CVE-2026-0001", "CVE-2026-0002"}
	wantName := []string{"alpha", "zlib", "zlib"}
	for i := range rows {
		if rows[i].ID != wantID[i] {
			t.Errorf("row %d ID = %q, want %q", i, rows[i].ID, wantID[i])
		}
		if !strings.Contains(rows[i].Name, wantName[i]) {
			t.Errorf("row %d Name = %q, want it to contain %q", i, rows[i].Name, wantName[i])
		}
	}
}
