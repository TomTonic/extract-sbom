package html

import (
	"testing"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// TestExtractionPathsByStatus verifies that only rows matching one of the
// requested statuses contribute their path to the result, in row order.
func TestExtractionPathsByStatus(t *testing.T) {
	t.Parallel()

	rows := []reportjson.ExtractionLogRowV2{
		{Path: "a.zip", Status: "failed"},
		{Path: "b.zip", Status: "extracted"},
		{Path: "c.zip", Status: "security-blocked"},
		{Path: "d.zip", Status: "failed"},
	}

	got := extractionPathsByStatus(rows, "failed", "security-blocked")
	want := []string{"a.zip", "c.zip", "d.zip"}
	if len(got) != len(want) {
		t.Fatalf("extractionPathsByStatus() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("extractionPathsByStatus()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractionPathsByStatusNoMatch verifies that an empty slice (not a
// panic) is returned when no row matches any requested status.
func TestExtractionPathsByStatusNoMatch(t *testing.T) {
	t.Parallel()

	rows := []reportjson.ExtractionLogRowV2{{Path: "a.zip", Status: "extracted"}}
	if got := extractionPathsByStatus(rows, "failed"); len(got) != 0 {
		t.Errorf("extractionPathsByStatus() = %v, want empty", got)
	}
}

// TestExtractionStatusClass verifies that the "failed" status is further
// classified by scanning the detail message for known failure signatures,
// and that other statuses map directly to their label.
func TestExtractionStatusClass(t *testing.T) {
	t.Parallel()

	tr := i18npkg.For("en")

	cases := []struct {
		name   string
		status string
		detail string
		want   string
	}{
		{"timeout", "failed", "per-extraction timeout (30s) exceeded", tr.ProcessingTimeoutLabel},
		{"password required", "failed", "no matching password found", tr.ProcessingPasswordRequiredLabel},
		{"format mismatch: not archive", "failed", "Can not open the file as archive", tr.ProcessingFormatMismatchLabel},
		{"format mismatch: does not match", "failed", "does not match the detected archive format", tr.ProcessingFormatMismatchLabel},
		{"corrupt: unexpected eof", "failed", "unexpected end of archive", tr.ProcessingCorruptLabel},
		{"corrupt: invalid tar header", "failed", "invalid tar header", tr.ProcessingCorruptLabel},
		{"generic failure", "failed", "some other error", tr.ProcessingExtractionFailedLabel},
		{"security blocked", "security-blocked", "", tr.ProcessingSecurityBlockedLabel},
		{"tool missing", "tool-missing", "", tr.ProcessingToolMissingLabel},
		{"unmapped status passes through", "extracted", "", "extracted"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractionStatusClass(tc.status, tc.detail, tr); got != tc.want {
				t.Errorf("extractionStatusClass(%q, %q) = %q, want %q", tc.status, tc.detail, got, tc.want)
			}
		})
	}
}

// TestExtractionArchiveCols verifies the dash-fallback behavior for missing
// archive metadata, both when ArchiveMeta is nil and when individual fields
// are empty.
func TestExtractionArchiveCols(t *testing.T) {
	t.Parallel()

	t.Run("nil meta", func(t *testing.T) {
		t.Parallel()
		row := &reportjson.ExtractionLogRowV2{}
		archiveType, archiveMethod, encrypted, physicalSize := extractionArchiveCols(row)
		if archiveType != "-" || archiveMethod != "-" || encrypted != "-" || physicalSize != "-" {
			t.Errorf("extractionArchiveCols(nil meta) = (%q, %q, %q, %q), want all dashes",
				archiveType, archiveMethod, encrypted, physicalSize)
		}
	})

	t.Run("populated meta", func(t *testing.T) {
		t.Parallel()
		row := &reportjson.ExtractionLogRowV2{ArchiveMeta: &reportjson.ExtractionArchiveMetaV2{
			Type:             "Zip",
			Methods:          []string{"Deflate", "AES256"},
			HasEncryptedItem: true,
			PhysicalSize:     "1024",
		}}
		archiveType, archiveMethod, encrypted, physicalSize := extractionArchiveCols(row)
		if archiveType != "Zip" {
			t.Errorf("archiveType = %q, want %q", archiveType, "Zip")
		}
		if archiveMethod != "Deflate, AES256" {
			t.Errorf("archiveMethod = %q, want %q", archiveMethod, "Deflate, AES256")
		}
		if encrypted != "true" {
			t.Errorf("encrypted = %q, want %q", encrypted, "true")
		}
		if physicalSize != "1024" {
			t.Errorf("physicalSize = %q, want %q", physicalSize, "1024")
		}
	})

	t.Run("empty type and size, not encrypted", func(t *testing.T) {
		t.Parallel()
		row := &reportjson.ExtractionLogRowV2{ArchiveMeta: &reportjson.ExtractionArchiveMetaV2{}}
		archiveType, archiveMethod, encrypted, physicalSize := extractionArchiveCols(row)
		if archiveType != "-" || archiveMethod != "-" || physicalSize != "-" {
			t.Errorf("extractionArchiveCols(empty meta) = (%q, _, %q), want dashes", archiveType, physicalSize)
		}
		if encrypted != "false" {
			t.Errorf("encrypted = %q, want %q", encrypted, "false")
		}
	})
}
