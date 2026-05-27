package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// TestCrossReportOrderingContractHumanSectionBlocks verifies that the human
// report keeps executive guidance before appendix-heavy sections.
func TestCrossReportOrderingContractHumanSectionBlocks(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	var buf bytes.Buffer
	if err := GenerateHuman(data, "en", &buf); err != nil {
		t.Fatalf("GenerateHuman error: %v", err)
	}
	out := buf.String()

	summaryIdx := strings.Index(out, "## Summary")
	methodIdx := strings.Index(out, "## Method At A Glance")
	appendixIdx := strings.Index(out, "## Appendix")
	scanLogIdx := strings.Index(out, "## Package Scan Log")
	extractionLogIdx := strings.Index(out, "## Extraction Log")
	if summaryIdx == -1 || methodIdx == -1 || appendixIdx == -1 || scanLogIdx == -1 || extractionLogIdx == -1 {
		t.Fatal("expected report sections are missing")
	}
	if summaryIdx >= appendixIdx || methodIdx >= appendixIdx || appendixIdx >= scanLogIdx || appendixIdx >= extractionLogIdx {
		t.Fatal("human section ordering contract violated")
	}
}

// TestCrossReportOrderingContractMachineSlicesPreserveProcessingOrder verifies
// that machine report slices keep processing order from orchestrator input.
func TestCrossReportOrderingContractMachineSlicesPreserveProcessingOrder(t *testing.T) {
	t.Parallel()

	scans := []scan.ScanResult{
		{NodePath: "z/path"},
		{NodePath: "a/path"},
	}
	decisions := []policy.Decision{
		{Trigger: "max-files", NodePath: "z/path", Action: policy.ActionSkip, Detail: "skip z"},
		{Trigger: "max-depth", NodePath: "a/path", Action: policy.ActionContinue, Detail: "continue a"},
	}

	machineScans := buildMachineScans(scans)
	if len(machineScans) != 2 || machineScans[0].NodePath != "z/path" || machineScans[1].NodePath != "a/path" {
		t.Fatalf("machine scan order changed: %+v", machineScans)
	}

	machineDecisions := buildMachineDecisions(decisions)
	if len(machineDecisions) != 2 || machineDecisions[0].NodePath != "z/path" || machineDecisions[1].NodePath != "a/path" {
		t.Fatalf("machine decision order changed: %+v", machineDecisions)
	}
}

// TestCrossReportOrderingContractSARIFRulesAndResults verifies deterministic
// ordering of SARIF rules and results.
func TestCrossReportOrderingContractSARIFRulesAndResults(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Input.Filename = "delivery.zip"
	data.BOM = &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef: "ref-z",
			Name:   "zlib",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "delivery/z/path/zlib.jar"},
			},
		},
		{
			BOMRef: "ref-a",
			Name:   "alpha",
			Properties: &[]cdx.Property{
				{Name: "extract-sbom:delivery-path", Value: "delivery/a/path/alpha.jar"},
			},
		},
	}}
	data.Vulnerabilities = &vulnscan.Result{
		Requested: true,
		State:     vulnscan.StateCompleted,
		MatchesByBOMRef: map[string][]vulnscan.VMatch{
			"ref-z": {
				{VulnerabilityID: "CVE-2026-0001", Severity: "high"},
			},
			"ref-a": {
				{VulnerabilityID: "CVE-2026-0002", Severity: "medium"},
				{VulnerabilityID: "CVE-2026-0001", Severity: "critical"},
			},
		},
	}

	rules := buildSARIFRules(data.Vulnerabilities)
	if len(rules) != 2 || rules[0].ID != "CVE-2026-0001" || rules[1].ID != "CVE-2026-0002" {
		t.Fatalf("SARIF rule ordering changed: %+v", rules)
	}

	results := buildSARIFResults(data)
	got := make([]string, 0, len(results))
	for i := range results {
		uri := ""
		if len(results[i].Locations) > 0 {
			uri = results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		got = append(got, results[i].RuleID+"@"+uri)
	}
	want := []string{
		"CVE-2026-0001@delivery/a/path/alpha.jar",
		"CVE-2026-0002@delivery/a/path/alpha.jar",
		"CVE-2026-0001@delivery/z/path/zlib.jar",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SARIF result ordering = %v, want %v", got, want)
	}
}
