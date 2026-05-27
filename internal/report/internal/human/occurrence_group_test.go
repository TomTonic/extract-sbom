package human

import "testing"

// TestCrossReportOrderingContractOccurrenceGroupsSortByDeliveryPath verifies
// deterministic package grouping by primary delivery path.
func TestCrossReportOrderingContractOccurrenceGroupsSortByDeliveryPath(t *testing.T) {
	t.Parallel()

	groups := buildPackageOccurrenceGroups([]componentOccurrence{
		{
			ObjectID:       "extract-sbom:ZZZ",
			PackageName:    "zlib",
			Version:        "1.2.13",
			DeliveryPaths:  []string{"z/path/zlib.jar"},
			EvidencePaths:  []string{"z/path/zlib.jar/META-INF/MANIFEST.MF"},
			EvidenceSource: "manifest",
		},
		{
			ObjectID:       "extract-sbom:AAA",
			PackageName:    "alpha",
			Version:        "1.0.0",
			DeliveryPaths:  []string{"a/path/alpha.jar"},
			EvidencePaths:  []string{"a/path/alpha.jar/META-INF/MANIFEST.MF"},
			EvidenceSource: "manifest",
		},
	})

	if len(groups) != 2 {
		t.Fatalf("package group count = %d, want 2", len(groups))
	}
	if groups[0].PackageName != "alpha" || groups[1].PackageName != "zlib" {
		t.Fatalf("package groups not sorted by delivery path: first=%q second=%q", groups[0].PackageName, groups[1].PackageName)
	}
}
