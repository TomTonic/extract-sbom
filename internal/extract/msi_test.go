package extract

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadMSIMetadataReturnsErrorForNonOLEFile verifies that reading MSI
// metadata from a non-OLE file produces a clear error rather than panicking.
func TestReadMSIMetadataReturnsErrorForNonOLEFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fakePath := filepath.Join(dir, "fake.msi")
	if err := os.WriteFile(fakePath, []byte("not an MSI file"), 0o600); err != nil {
		t.Fatal(err)
	}

	meta, err := ReadMSIMetadata(fakePath, 1024)
	if err == nil {
		t.Error("expected error for non-OLE file, got nil")
	}
	if meta != nil {
		t.Error("expected nil metadata for non-OLE file")
	}
}

// TestReadMSIMetadataReturnsErrorForMissingFile verifies that a missing
// file produces a clear error.
func TestReadMSIMetadataReturnsErrorForMissingFile(t *testing.T) {
	t.Parallel()

	_, err := ReadMSIMetadata("/nonexistent/file.msi", 1024)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestDecodeMSIStreamNamePassthrough verifies that plain ASCII names
// pass through unchanged.
func TestDecodeMSIStreamNamePassthrough(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"_StringPool", "_StringPool"},
		{"!_StringData", "!_StringData"},
		{"Property", "Property"},
		{"SummaryInformation", "SummaryInformation"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := decodeMSIStreamName(tt.input)
			if got != tt.want {
				t.Errorf("decodeMSIStreamName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestDecodeMSIStreamNameEncoded verifies that MSI-encoded OLE stream names
// are correctly decoded. These encoded names are produced by msitools/wixl
// using the standard MSI database encoding (two-char packed in U+3800..U+47FF,
// single-char in U+4800..U+483F, table prefix U+4840).
func TestDecodeMSIStreamNameEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "StringPool",
			input: "\u4840\u3F3F\u4577\u446C\u3E6A\u44B2\u482F",
			want:  "!_StringPool",
		},
		{
			name:  "StringData",
			input: "\u4840\u3F3F\u4577\u446C\u3B6A\u45E4\u4824",
			want:  "!_StringData",
		},
		{
			name:  "Property",
			input: "\u4840\u4559\u44F2\u4568\u4737",
			want:  "!Property",
		},
		{
			name:  "File",
			input: "\u4840\u430F\u422F",
			want:  "!File",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := decodeMSIStreamName(tt.input)
			if got != tt.want {
				t.Errorf("decodeMSIStreamName(encoded %s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// TestParseMSIStringPoolEmptyInput verifies that an empty or minimal
// string pool is handled gracefully.
func TestParseMSIStringPoolEmptyInput(t *testing.T) {
	t.Parallel()

	// Pool with just the 4-byte header, no strings.
	poolData := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00})
	stringData := bytes.NewReader([]byte{})

	result, err := parseMSIStringPool(poolData, stringData, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 strings, got %d", len(result))
	}
}

// TestParseMSIStringPoolTooSmall verifies that a string pool smaller
// than the header is rejected.
func TestParseMSIStringPoolTooSmall(t *testing.T) {
	t.Parallel()

	poolData := bytes.NewReader([]byte{0x00, 0x00})
	stringData := bytes.NewReader([]byte{})

	_, err := parseMSIStringPool(poolData, stringData, 1024)
	if err == nil {
		t.Error("expected error for pool too small, got nil")
	}
}

// TestParseMSIStringPoolRejectsOversizedStreams verifies that metadata parsing
// enforces a hard byte limit per MSI stream to avoid unbounded memory use.
func TestParseMSIStringPoolRejectsOversizedStreams(t *testing.T) {
	t.Parallel()

	poolData := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00})
	stringData := bytes.NewReader([]byte("A"))

	if _, err := parseMSIStringPool(poolData, stringData, 4); err == nil {
		t.Fatal("expected oversized _StringPool stream to be rejected")
	}
}

// TestParseMSIPropertyTableRejectsOversizedStream verifies that Property table
// parsing is bounded by the configured stream limit.
func TestParseMSIPropertyTableRejectsOversizedStream(t *testing.T) {
	t.Parallel()

	tableData := bytes.NewReader([]byte{0x01, 0x00, 0x02, 0x00})
	if _, err := parseMSIPropertyTable(tableData, []string{"Name", "Value"}, 2); err == nil {
		t.Fatal("expected oversized Property stream to be rejected")
	}
}

// TestMSIPropertyNamesContainsRequiredKeys verifies that all
// design-specified MSI properties are in the lookup map.
func TestMSIPropertyNamesContainsRequiredKeys(t *testing.T) {
	t.Parallel()

	required := []string{
		"Manufacturer",
		"ProductName",
		"ProductVersion",
		"ProductCode",
		"UpgradeCode",
		"ProductLanguage",
	}

	for _, key := range required {
		if !msiPropertyNames[key] {
			t.Errorf("msiPropertyNames missing required key %q", key)
		}
	}
}

// TestIsStreamNameMatchesDirectAndEncoded verifies that stream name
// matching works for both direct names and encoded variants.
func TestIsStreamNameMatchesDirectAndEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"_StringPool", "_StringPool", true},
		{"!_StringPool", "_StringPool", true},
		{"_StringData", "_StringData", true},
		{"Other", "_StringPool", false},
		// Encoded stream names from wixl/msitools (two-char packed encoding).
		{"\u4840\u3F3F\u4577\u446C\u3E6A\u44B2\u482F", "_StringPool", true},
		{"\u4840\u3F3F\u4577\u446C\u3B6A\u45E4\u4824", "_StringData", true},
	}

	for _, tt := range tests {
		t.Run(tt.name+"->"+tt.target, func(t *testing.T) {
			t.Parallel()
			got := isStreamName(tt.name, tt.target)
			if got != tt.want {
				t.Errorf("isStreamName(%q, %q) = %v, want %v", tt.name, tt.target, got, tt.want)
			}
		})
	}
}
