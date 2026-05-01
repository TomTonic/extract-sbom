package vulnscan

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func writeExecutable(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := "#!/bin/sh\nset -eu\n" + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
	// #nosec G302 -- test helper script must be executable for command-based integration tests.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("chmod executable %s: %v", path, err)
	}
}

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

// TestRunParsesExtendedMetadata verifies that Run maps grype JSON metadata
// fields used in console output, including fixed-in, type, EPSS, risk, and KEV.
func TestRunParsesExtendedMetadata(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	writeExecutable(t, binDir, "grype", `
cat <<'JSON'
{
  "descriptor": {
    "version": "0.112.0",
    "timestamp": "2026-05-01T10:00:00Z",
    "db": {
      "status": {
        "schemaVersion": "v6.1.5",
        "built": "2026-04-30T00:00:00Z"
      }
    }
  },
  "matches": [
    {
      "artifact": {
        "id": "extract-sbom:AAA",
        "name": "activemq-client",
        "version": "5.15.9",
        "type": "java-archive",
        "purl": "pkg:maven/org.apache.activemq/activemq-client@5.15.9"
      },
      "vulnerability": {
        "id": "GHSA-crg9-44h2-xw35",
        "severity": "Critical",
				"description": "Apache ActiveMQ is vulnerable to Remote Code Execution",
        "namespace": "github:language:java",
        "dataSource": "https://example.test/vuln",
        "urls": ["https://github.com/advisories/GHSA-crg9-44h2-xw35"],
        "risk": 100.0,
				"knownExploited": [
					{"cve": "CVE-2023-46604"}
				],
				"cvss": [
					{
						"version": "2.0",
						"vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						"metrics": {"baseScore": 7.5}
					},
					{
						"version": "3.1",
						"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						"metrics": {"baseScore": 9.8}
					}
				],
        "epss": [
          {
            "epss": 0.944,
            "percentile": 0.99
          }
        ],
        "fix": {
          "state": "fixed",
          "versions": ["5.15.16"]
        }
      },
      "matchDetails": [
        {
          "type": "exact-direct-match",
          "matcher": "java-matcher"
        }
      ]
    }
  ]
}
JSON
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")

	bom := &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "extract-sbom:AAA",
		Name:       "activemq-client",
		Version:    "5.15.9",
		PackageURL: "pkg:maven/org.apache.activemq/activemq-client@5.15.9",
	}}}

	res := Run(t.Context(), filepath.Join(dir, "out.cdx.json"), true, bom)
	if res == nil {
		t.Fatal("Run returned nil")
	}
	if res.State != StateCompleted {
		t.Fatalf("state=%s want %s", res.State, StateCompleted)
	}
	matches := res.MatchesByBOMRef["extract-sbom:AAA"]
	if len(matches) != 1 {
		t.Fatalf("matches len=%d want 1", len(matches))
	}
	m := matches[0]
	if m.ArtifactType != "java-archive" {
		t.Fatalf("artifactType=%q want %q", m.ArtifactType, "java-archive")
	}
	if len(m.FixVersions) != 1 || m.FixVersions[0] != "5.15.16" {
		t.Fatalf("fixVersions=%v want [5.15.16]", m.FixVersions)
	}
	if m.EPSS == nil || *m.EPSS != 0.944 {
		t.Fatalf("epss=%v want 0.944", m.EPSS)
	}
	if m.EPSSPercentile == nil || *m.EPSSPercentile != 0.99 {
		t.Fatalf("epssPercentile=%v want 0.99", m.EPSSPercentile)
	}
	if m.Risk == nil || *m.Risk != 100.0 {
		t.Fatalf("risk=%v want 100.0", m.Risk)
	}
	if m.KEV == nil || !*m.KEV {
		t.Fatalf("kev=%v want true", m.KEV)
	}
	if m.CVSSVersion != "3.1" {
		t.Fatalf("cvssVersion=%q want 3.1", m.CVSSVersion)
	}
	if m.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("cvssVector=%q", m.CVSSVector)
	}
	if m.CVSSScore == nil || *m.CVSSScore != 9.8 {
		t.Fatalf("cvssScore=%v want 9.8", m.CVSSScore)
	}
	if m.Description == "" {
		t.Fatal("description should be populated")
	}
}
