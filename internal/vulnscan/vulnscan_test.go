package vulnscan

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TestNormalizeSeverity verifies that normalizeSeverity trims, lowercases, and
// maps empty input to "unknown" without altering unrecognised severity strings.
func TestNormalizeSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"Critical", "critical"},
		{" HIGH ", "high"},
		{"", "unknown"},
		{"custom", "custom"},
	}
	for _, tc := range cases {
		if got := normalizeSeverity(tc.in); got != tc.want {
			t.Fatalf("normalizeSeverity(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

// TestApplyCoverage verifies that applyCoverage classifies bom-refs as found,
// none, or not-assessable based on match presence and PURL/CPE availability.
func TestApplyCoverage(t *testing.T) {
	t.Parallel()
	bom := &cdx.BOM{Components: &[]cdx.Component{
		{BOMRef: "a", PackageURL: "pkg:maven/a/a@1.0.0"},
		{BOMRef: "b", CPE: "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*"},
		{BOMRef: "c"},
	}}
	res := &Result{
		MatchesByBOMRef: map[string][]VMatch{
			"a": {{VulnerabilityID: "CVE-1", Severity: "high"}},
		},
		CoverageByBOMRef: map[string]CoverageState{},
	}

	applyCoverage(res, bom)
	if res.CoverageByBOMRef["a"] != CoverageFound {
		t.Fatalf("coverage a=%s want %s", res.CoverageByBOMRef["a"], CoverageFound)
	}
	if res.CoverageByBOMRef["b"] != CoverageNone {
		t.Fatalf("coverage b=%s want %s", res.CoverageByBOMRef["b"], CoverageNone)
	}
	if res.CoverageByBOMRef["c"] != CoverageNotAssessable {
		t.Fatalf("coverage c=%s want %s", res.CoverageByBOMRef["c"], CoverageNotAssessable)
	}
}

// TestRunNotRequested verifies that Run returns a non-nil result with
// StateNotRequested and Requested=false when enabled is false.
func TestRunNotRequested(t *testing.T) {
	t.Parallel()
	res := Run(t.Context(), "", false, nil)
	if res == nil {
		t.Fatal("Run returned nil result")
	}
	if res.State != StateNotRequested {
		t.Fatalf("state=%s want %s", res.State, StateNotRequested)
	}
	if res.Requested {
		t.Fatal("Requested=true want false")
	}
}
