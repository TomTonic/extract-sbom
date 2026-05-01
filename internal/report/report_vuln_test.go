package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

func floatPtrVuln(v float64) *float64 {
	return &v
}

func boolPtrVuln(v bool) *bool {
	return &v
}

func TestWriteVulnerabilitySummaryGermanNotRequested(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writeVulnerabilitySummary(&buf, ReportData{}, nil, getTranslations("de"))

	out := buf.String()
	if !strings.Contains(out, "Schwachstellenanreicherung: nicht angefordert") {
		t.Fatalf("expected German not-requested text, got: %s", out)
	}
}

func TestWriteVulnerabilitySummaryGermanTableHeaders(t *testing.T) {
	t.Parallel()

	data := ReportData{
		Vulnerabilities: &vulnscan.Result{
			State:        vulnscan.StateCompleted,
			Requested:    true,
			GrypeVersion: "0.111.1",
			MatchesByBOMRef: map[string][]vulnscan.VMatch{
				"extract-sbom:ABC": {{
					VulnerabilityID: "CVE-2026-0001",
					Severity:        "high",
					ArtifactName:    "paket-a",
					ArtifactVersion: "1.0.0",
					CVSSScore:       floatPtrVuln(9.8),
					EPSS:            floatPtrVuln(0.92),
					Risk:            floatPtrVuln(80.0),
					KEV:             boolPtrVuln(true),
				}},
			},
		},
	}
	occurrences := []componentOccurrence{{
		ObjectID:    "extract-sbom:ABC",
		PackageName: "paket-a",
		Version:     "1.0.0",
	}}

	var buf bytes.Buffer
	writeVulnerabilitySummary(&buf, data, occurrences, getTranslations("de"))

	out := buf.String()
	checks := []string{
		"Schwachstellenanreicherungsstatus: `completed`",
		"Schwachstellenübersicht (grype-inspirierte Ansicht):",
		"| Name | Installiert | Behoben in | Schwachstelle | Schweregrad | EPSS | Risiko | KEV |",
		"HIGH (9.8)",
		"| 80.0 | ja |",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("expected output to contain %q, got: %s", c, out)
		}
	}
}

func TestWriteOccurrenceVulnerabilityBlockGermanDetailsAndStates(t *testing.T) {
	t.Parallel()

	t.Run("found-details", func(t *testing.T) {
		t.Parallel()

		occ := componentOccurrence{ObjectID: "extract-sbom:ABC", PURL: "pkg:maven/a/a@1.0.0"}
		v := &vulnscan.Result{
			State: vulnscan.StateCompleted,
			MatchesByBOMRef: map[string][]vulnscan.VMatch{
				"extract-sbom:ABC": {{
					VulnerabilityID: "CVE-2026-0001",
					Severity:        "high",
					ArtifactType:    "java-archive",
					Risk:            floatPtrVuln(77.7),
					KEV:             boolPtrVuln(true),
					FixState:        "fixed",
					FixVersions:     []string{"1.0.1"},
					CVSSVersion:     "3.1",
					CVSSScore:       floatPtrVuln(9.8),
					CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Description:     "kritischer Fehler",
					EPSS:            floatPtrVuln(0.9),
					DataSource:      "https://example.test/source",
					URLs:            []string{"https://example.test/ref"},
				}},
			},
		}

		var buf bytes.Buffer
		writeOccurrenceVulnerabilityBlock(&buf, occ, v, getTranslations("de"))
		out := buf.String()

		checks := []string{
			"Schwachstellenstatus: `found` (1)",
			"kev=`ja`",
			"Quelle: https://example.test/source",
			"Behebung: status=`fixed` versionen=`1.0.1`",
			"Beschreibung: kritischer Fehler",
			"Referenz: https://example.test/ref",
		}
		for _, c := range checks {
			if !strings.Contains(out, c) {
				t.Fatalf("expected output to contain %q, got: %s", c, out)
			}
		}
	})

	t.Run("not-assessable-unavailable", func(t *testing.T) {
		t.Parallel()

		occ := componentOccurrence{ObjectID: "extract-sbom:XYZ"}
		v := &vulnscan.Result{State: vulnscan.StateCompletedWithErrors}

		var buf bytes.Buffer
		writeOccurrenceVulnerabilityBlock(&buf, occ, v, getTranslations("de"))
		out := buf.String()

		if !strings.Contains(out, "Schwachstellenstatus: `not-assessable` (Anreicherung nicht verfügbar oder unvollständig)") {
			t.Fatalf("expected German not-assessable unavailable message, got: %s", out)
		}
	})
}
