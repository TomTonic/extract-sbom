package domain

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func prop(name, value string) cdx.Property { return cdx.Property{Name: name, Value: value} }

// TestCollectComponentOccurrencesFiltersAndStats exercises the quality filters,
// statistics, and PURL/evidence bucketing of the occurrence collector.
func TestCollectComponentOccurrencesFiltersAndStats(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{Components: &[]cdx.Component{
		// Indexed: has delivery path, PURL, evidence path, foundBy.
		{
			BOMRef:     "extract-sbom:GOOD",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "alpha",
			Version:    "1.0.0",
			PackageURL: "pkg:maven/com.acme/alpha@1.0.0",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "a/alpha.jar"),
				prop("extract-sbom:evidence-path", "a/alpha.jar/META-INF/MANIFEST.MF"),
				prop("syft:package:foundBy", "java-archive-cataloger"),
			},
		},
		// Filtered: no delivery path at all.
		{BOMRef: "extract-sbom:NODP", Name: "nodp"},
		// Filtered: container node (carries extraction-status).
		{
			BOMRef: "extract-sbom:CONTAINER",
			Name:   "container.zip",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "container.zip"),
				prop("extract-sbom:extraction-status", "extracted"),
			},
		},
		// Filtered: absolute-path name (file-cataloger temp leak).
		{
			BOMRef: "extract-sbom:ABS",
			Type:   cdx.ComponentTypeFile,
			Name:   "/tmp/extract-sbom-x/inner.jar",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "d/inner.jar"),
			},
		},
		// Filtered: low-value file artifact (file type, no purl/version/foundBy).
		{
			BOMRef: "extract-sbom:LOWVAL",
			Type:   cdx.ComponentTypeFile,
			Name:   "lowval",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "e/lowval.bin"),
			},
		},
		// Indexed without PURL, evidence source only.
		{
			BOMRef:  "extract-sbom:NOPURL",
			Type:    cdx.ComponentTypeLibrary,
			Name:    "beta",
			Version: "2.0.0",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "b/beta.jar"),
				prop("extract-sbom:evidence-source", "binary"),
				prop("syft:package:foundBy", "binary-cataloger"),
			},
		},
	}}

	occ, stats := CollectComponentOccurrences(bom)

	if stats.TotalComponents != 6 {
		t.Errorf("TotalComponents = %d, want 6", stats.TotalComponents)
	}
	if stats.MissingDeliveryPath != 1 {
		t.Errorf("MissingDeliveryPath = %d, want 1", stats.MissingDeliveryPath)
	}
	if stats.FilteredContainerNodes != 1 {
		t.Errorf("FilteredContainerNodes = %d, want 1", stats.FilteredContainerNodes)
	}
	if stats.FilteredAbsolutePathNames != 1 {
		t.Errorf("FilteredAbsolutePathNames = %d, want 1", stats.FilteredAbsolutePathNames)
	}
	if stats.FilteredLowValueFileArtifacts != 1 {
		t.Errorf("FilteredLowValueFileArtifacts = %d, want 1", stats.FilteredLowValueFileArtifacts)
	}
	if stats.IndexedComponents != 2 {
		t.Fatalf("IndexedComponents = %d, want 2", stats.IndexedComponents)
	}
	if stats.IndexedWithPURL != 1 || stats.IndexedWithoutPURL != 1 {
		t.Errorf("PURL buckets = (%d,%d), want (1,1)", stats.IndexedWithPURL, stats.IndexedWithoutPURL)
	}
	if stats.IndexedWithEvidencePath != 1 || stats.IndexedWithEvidenceSourceOnly != 1 {
		t.Errorf("evidence buckets = (%d,%d), want (1,1)", stats.IndexedWithEvidencePath, stats.IndexedWithEvidenceSourceOnly)
	}
	if len(occ) != 2 {
		t.Fatalf("len(occurrences) = %d, want 2", len(occ))
	}
}

// TestCollectComponentOccurrencesMergesWeakDuplicate verifies a weak placeholder
// at the same locus collapses into the stronger record.
func TestCollectComponentOccurrencesMergesWeakDuplicate(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{Components: &[]cdx.Component{
		{
			BOMRef:     "extract-sbom:RICH",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "janino",
			Version:    "3.1.10",
			PackageURL: "pkg:maven/org.codehaus.janino/janino@3.1.10",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "p/janino-3.1.10.jar"),
				prop("extract-sbom:evidence-path", "p/janino-3.1.10.jar/META-INF/MANIFEST.MF"),
				prop("syft:package:foundBy", "java-archive-cataloger"),
			},
		},
		{
			BOMRef: "extract-sbom:WEAK",
			Type:   cdx.ComponentTypeLibrary,
			Name:   "janino-3.1.10.jar",
			Properties: &[]cdx.Property{
				prop("extract-sbom:delivery-path", "p/janino-3.1.10.jar"),
				prop("extract-sbom:evidence-path", "p/janino-3.1.10.jar/META-INF/MANIFEST.MF"),
			},
		},
	}}

	occ, stats := CollectComponentOccurrences(bom)
	if stats.DuplicateMerged != 1 {
		t.Errorf("DuplicateMerged = %d, want 1", stats.DuplicateMerged)
	}
	if len(occ) != 1 || occ[0].ObjectID != "extract-sbom:RICH" {
		t.Fatalf("expected only the rich record to survive, got %+v", occ)
	}
}

// TestCollectComponentOccurrencesPrunesAncestorPaths verifies that ancestor
// delivery paths are pruned in favour of leaf-most logical paths.
func TestCollectComponentOccurrencesPrunesAncestorPaths(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{Components: &[]cdx.Component{{
		BOMRef:     "extract-sbom:JRT",
		Type:       cdx.ComponentTypeLibrary,
		Name:       "jrt-fs",
		Version:    "11",
		PackageURL: "pkg:maven/jrt-fs/jrt-fs@11",
		Properties: &[]cdx.Property{
			prop("extract-sbom:delivery-path", "d.zip/Client.zip"),
			prop("extract-sbom:delivery-path", "d.zip/Client.zip/jre/lib/jrt-fs.jar"),
			prop("syft:package:foundBy", "java-archive-cataloger"),
		},
	}}}

	occ, _ := CollectComponentOccurrences(bom)
	if len(occ) != 1 {
		t.Fatalf("len(occurrences) = %d, want 1", len(occ))
	}
	for _, dp := range occ[0].DeliveryPaths {
		if dp == "d.zip/Client.zip" {
			t.Errorf("ancestor delivery path should have been pruned, got %v", occ[0].DeliveryPaths)
		}
	}
}

func TestCollectComponentOccurrencesNilBOM(t *testing.T) {
	t.Parallel()
	occ, stats := CollectComponentOccurrences(nil)
	if occ != nil || stats.TotalComponents != 0 {
		t.Errorf("nil BOM should yield no occurrences, got %v / %+v", occ, stats)
	}
}

func TestNormalizeSeverityDomain(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"CRITICAL", "critical"},
		{" High ", "high"},
		{"", "unknown"},
		{"weird", "weird"},
	}
	for _, c := range cases {
		if got := NormalizeSeverity(c.in); got != c.want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestOccurrenceQualityScoreOrdering(t *testing.T) {
	t.Parallel()
	full := ComponentOccurrence{PURL: "pkg:x", FoundBy: "cat", Version: "1", PackageName: "alpha"}
	bare := ComponentOccurrence{PackageName: "alpha"}
	if OccurrenceQualityScore(full) <= OccurrenceQualityScore(bare) {
		t.Errorf("richer occurrence should score higher: %d vs %d",
			OccurrenceQualityScore(full), OccurrenceQualityScore(bare))
	}
}
