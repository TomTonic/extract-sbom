package markdown

import (
	"bytes"
	"strings"
	"testing"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func englishTranslations() translations {
	return getTranslations("en")
}

func TestSuppressedByCellResolvedWithAnchor(t *testing.T) {
	t.Parallel()
	row := &reportjson.SuppressionRowV2{
		ResolutionStatus:  "resolved",
		KeptComponentName: "openssl",
		KeptAnchorID:      "pkg-openssl-1-0",
	}
	got := suppressedByCell(row, englishTranslations())
	if !strings.Contains(got, "openssl") {
		t.Errorf("expected component name in output, got %q", got)
	}
	if !strings.Contains(got, "#pkg-openssl-1-0") {
		t.Errorf("expected anchor link in output, got %q", got)
	}
}

func TestSuppressedByCellResolvedWithoutAnchor(t *testing.T) {
	t.Parallel()
	row := &reportjson.SuppressionRowV2{
		ResolutionStatus:  "resolved",
		KeptComponentName: "openssl",
		KeptAnchorID:      "",
	}
	got := suppressedByCell(row, englishTranslations())
	if !strings.Contains(got, "openssl") {
		t.Errorf("expected component name in output, got %q", got)
	}
	if strings.Contains(got, "#") {
		t.Errorf("unexpected anchor when KeptAnchorID is empty, got %q", got)
	}
}

func TestSuppressedByCellUnresolved(t *testing.T) {
	t.Parallel()
	tr := englishTranslations()
	row := &reportjson.SuppressionRowV2{ResolutionStatus: "unresolved"}
	got := suppressedByCell(row, tr)
	if got == "" {
		t.Error("expected non-empty fallback output")
	}
}

func TestSuppressedByCellKnownReason(t *testing.T) {
	t.Parallel()
	row := &reportjson.SuppressionRowV2{
		ResolutionStatus: "unresolved",
		ResolutionReason: "suppressed component not present in canonical component set",
	}
	tr := englishTranslations()
	got := suppressedByCell(row, tr)
	if !strings.Contains(got, tr.SuppressedByNoIndexedMatch) {
		t.Errorf("expected SuppressedByNoIndexedMatch text, got %q", got)
	}
}

func TestSuppressionResolveReasonText(t *testing.T) {
	t.Parallel()
	tr := englishTranslations()
	if got := suppressionResolveReasonText("suppressed component not present in canonical component set", tr); got != tr.SuppressedByNoIndexedMatch {
		t.Errorf("known code: got %q, want %q", got, tr.SuppressedByNoIndexedMatch)
	}
	if got := suppressionResolveReasonText("unknown-code", tr); got != "" {
		t.Errorf("unknown code: got %q, want empty string", got)
	}
}

func TestWriteSuppressionTableEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	writeSuppressionTable(&buf, nil, englishTranslations())
	out := buf.String()
	if !strings.Contains(out, "| - | - | - |") {
		t.Errorf("expected empty placeholder row, got:\n%s", out)
	}
}

func TestWriteSuppressionTableTruncated(t *testing.T) {
	t.Parallel()
	rows := make([]reportjson.SuppressionRowV2, 35)
	for i := range rows {
		rows[i] = reportjson.SuppressionRowV2{
			DeliveryPath:  "path/file.jar",
			ComponentName: "comp",
		}
	}
	var buf bytes.Buffer
	writeSuppressionTable(&buf, rows, englishTranslations())
	out := buf.String()
	if !strings.Contains(out, "...") {
		t.Errorf("expected truncation marker, got:\n%s", out)
	}
}
