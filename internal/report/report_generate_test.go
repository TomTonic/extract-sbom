package report

import (
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
)

// minimalReportData returns a small but complete snapshot sufficient to drive
// every output renderer through the facade.
func minimalReportData() ReportData {
	return ReportData{
		Input: InputSummary{
			Filename: "delivery.zip",
			Size:     2048,
			SHA256:   strings.Repeat("a", 64),
			SHA512:   strings.Repeat("b", 128),
		},
		Config: config.DefaultConfig(),
		Tree: &extract.ExtractionNode{
			Path:   "delivery.zip",
			Status: extract.StatusExtracted,
			Format: identify.FormatInfo{Format: identify.ZIP},
		},
		BOM: &cdx.BOM{Components: &[]cdx.Component{{
			BOMRef:     "extract-sbom:A",
			Name:       "alpha",
			Version:    "1.0.0",
			PackageURL: "pkg:maven/com.acme/alpha@1.0.0",
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "alpha.jar"}},
		}}},
		StartTime: time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2025, 1, 1, 10, 0, 1, 0, time.UTC),
	}
}

// TestFacadeGeneratorsProduceOutput drives each public report generator through
// the facade and asserts non-empty, error-free output.
func TestFacadeGeneratorsProduceOutput(t *testing.T) {
	t.Parallel()

	data := minimalReportData()

	cases := []struct {
		name string
		gen  func(w *strings.Builder) error
		want string
	}{
		{"markdown", func(w *strings.Builder) error { return GenerateMarkdown(data, "en", w) }, "alpha"},
		{"markdown-engine", func(w *strings.Builder) error {
			return GenerateMarkdownWithEngine(data, "en", w, "", "")
		}, "alpha"},
		{"html", func(w *strings.Builder) error { return GenerateHTML(data, "en", w) }, "<html"},
		{"json", func(w *strings.Builder) error { return GenerateJSON(data, w) }, "\"schemaVersion\""},
		{"sarif", func(w *strings.Builder) error { return GenerateSARIF(data, w) }, "\"version\""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			if err := tc.gen(&b); err != nil {
				t.Fatalf("%s generator error: %v", tc.name, err)
			}
			if b.Len() == 0 {
				t.Fatalf("%s generator produced empty output", tc.name)
			}
			if !strings.Contains(b.String(), tc.want) {
				t.Errorf("%s output missing %q", tc.name, tc.want)
			}
		})
	}
}
