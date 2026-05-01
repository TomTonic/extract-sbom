package vulnscan

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

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
