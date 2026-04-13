// Deduplication tests validate user-visible collapse behavior for repeated
// PURLs across paths and across scan-node boundaries.
package assembly

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestAssembleDeduplicatesSamePURLAtDifferentPaths verifies that when the
// same PURL appears at two different delivery paths, only one component
// survives and carries both paths as provenance.
func TestAssembleDeduplicatesSamePURLAtDifferentPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	const (
		purl    = "pkg:maven/org.tanukisoftware.wrapper/wrapper@3.5.34"
		pathX64 = "delivery.zip/x64/wrapper.jar"
		pathX86 = "delivery.zip/x86/wrapper.jar"
	)

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         pathX64,
				OriginalPath: filepath.Join(dir, "x64-wrapper.jar"),
				Status:       extract.StatusSyftNative,
				Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
			},
			{
				Path:         pathX86,
				OriginalPath: filepath.Join(dir, "x86-wrapper.jar"),
				Status:       extract.StatusSyftNative,
				Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
			},
		},
	}
	for _, child := range tree.Children {
		if err := os.WriteFile(child.OriginalPath, []byte("PK jar"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	scans := []scan.ScanResult{
		{NodePath: "delivery.zip", BOM: &cdx.BOM{Components: &[]cdx.Component{}}},
		{
			NodePath: pathX64,
			BOM: &cdx.BOM{Components: &[]cdx.Component{{
				BOMRef: "x64-wrapper", Type: cdx.ComponentTypeLibrary,
				Name: "wrapper", Version: "3.5.34", PackageURL: purl,
				Properties: &[]cdx.Property{{Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
			}}},
			EvidencePaths: map[string][]string{"x64-wrapper": {pathX64 + "/META-INF/MANIFEST.MF"}},
		},
		{
			NodePath: pathX86,
			BOM: &cdx.BOM{Components: &[]cdx.Component{{
				BOMRef: "x86-wrapper", Type: cdx.ComponentTypeLibrary,
				Name: "wrapper", Version: "3.5.34", PackageURL: purl,
				Properties: &[]cdx.Property{{Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
			}}},
			EvidencePaths: map[string][]string{"x86-wrapper": {pathX86 + "/META-INF/MANIFEST.MF"}},
		},
	}

	bom, suppressions, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var purlMatches []cdx.Component
	for _, comp := range *bom.Components {
		if comp.PackageURL == purl {
			purlMatches = append(purlMatches, comp)
		}
	}
	if len(purlMatches) != 1 {
		t.Fatalf("expected exactly 1 wrapper component, got %d", len(purlMatches))
	}

	comp := purlMatches[0]
	deliveryPaths := make(map[string]bool)
	evidencePaths := make(map[string]bool)
	for _, p := range *comp.Properties {
		if p.Name == "extract-sbom:delivery-path" {
			deliveryPaths[p.Value] = true
		}
		if p.Name == "extract-sbom:evidence-path" {
			evidencePaths[p.Value] = true
		}
	}
	if !deliveryPaths[pathX64] || !deliveryPaths[pathX86] {
		t.Errorf("surviving component should carry both delivery paths; got %v", deliveryPaths)
	}
	if !evidencePaths[pathX64+"/META-INF/MANIFEST.MF"] || !evidencePaths[pathX86+"/META-INF/MANIFEST.MF"] {
		t.Errorf("surviving component should carry both evidence paths; got %v", evidencePaths)
	}

	purlCount := 0
	for _, s := range suppressions {
		if s.Reason == SuppressionPURLDuplicate && s.Component.PackageURL == purl {
			purlCount++
		}
	}
	if purlCount != 1 {
		t.Errorf("expected 1 cross-path PURL-duplicate suppression, got %d", purlCount)
	}
}

// TestDeduplicateGlobalComponentsPrunesAncestorDeliveryPaths verifies that
// global PURL dedup keeps leaf-most logical paths and drops redundant ancestors.
func TestDeduplicateGlobalComponentsPrunesAncestorDeliveryPaths(t *testing.T) {
	t.Parallel()

	const purl = "pkg:maven/jrt-fs/jrt-fs@11.0.30"
	components := []cdx.Component{
		{
			BOMRef:     "parent-zip",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "jrt-fs",
			Version:    "11.0.30",
			PackageURL: purl,
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery.zip/windows/Client-37.0.5.0.zip"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
		},
		{
			BOMRef:     "x64-jar",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "jrt-fs",
			Version:    "11.0.30",
			PackageURL: purl,
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar"}, {Name: "extract-sbom:evidence-path", Value: "delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
		},
		{
			BOMRef:     "x86-jar",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "jrt-fs",
			Version:    "11.0.30",
			PackageURL: purl,
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar"}, {Name: "extract-sbom:evidence-path", Value: "delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
		},
		{
			BOMRef:     "linux-jar",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "jrt-fs",
			Version:    "11.0.30",
			PackageURL: purl,
			Properties: &[]cdx.Property{{Name: "extract-sbom:delivery-path", Value: "delivery.zip/linux/SharedComponents.tar.gz/rsFrame1/foundation/java/x64/linux/jre/lib/jrt-fs.jar"}, {Name: "extract-sbom:evidence-path", Value: "delivery.zip/linux/SharedComponents.tar.gz/rsFrame1/foundation/java/x64/linux/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
		},
	}

	filtered, suppressions := deduplicateGlobalComponents(components, nil)
	if len(filtered) != 1 {
		t.Fatalf("filtered components = %d, want 1", len(filtered))
	}

	if filtered[0].Properties == nil {
		t.Fatal("surviving component has no properties")
	}
	deliveryPaths := map[string]bool{}
	evidencePaths := map[string]bool{}
	for _, p := range *filtered[0].Properties {
		if p.Name == "extract-sbom:delivery-path" {
			deliveryPaths[p.Value] = true
		}
		if p.Name == "extract-sbom:evidence-path" {
			evidencePaths[p.Value] = true
		}
	}
	if deliveryPaths["delivery.zip/windows/Client-37.0.5.0.zip"] {
		t.Fatal("redundant ancestor delivery path should have been pruned")
	}
	for _, want := range []string{
		"delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar",
		"delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar",
		"delivery.zip/linux/SharedComponents.tar.gz/rsFrame1/foundation/java/x64/linux/jre/lib/jrt-fs.jar",
	} {
		if !deliveryPaths[want] {
			t.Fatalf("missing delivery path %q in merged component: %v", want, deliveryPaths)
		}
	}
	for _, want := range []string{
		"delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x64/windows/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF",
		"delivery.zip/windows/Client-37.0.5.0.zip/foundation/java/x86/windows/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF",
		"delivery.zip/linux/SharedComponents.tar.gz/rsFrame1/foundation/java/x64/linux/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF",
	} {
		if !evidencePaths[want] {
			t.Fatalf("missing evidence path %q in merged component: %v", want, evidencePaths)
		}
	}

	purlCount := 0
	for _, s := range suppressions {
		if s.Reason == SuppressionPURLDuplicate && s.Component.PackageURL == purl {
			purlCount++
		}
	}
	if purlCount != 3 {
		t.Fatalf("expected 3 PURL-duplicate suppressions, got %d", purlCount)
	}
}

// TestAssembleDeduplicatesCrossNodeComponents verifies that when the same PURL
// appears in scan results from two different nodes, only one component survives
// and dependency references remain valid.
func TestAssembleDeduplicatesCrossNodeComponents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	jarPath := filepath.Join(dir, "jrt-fs.jar")
	if err := os.WriteFile(jarPath, []byte("PK jar"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	const (
		jarDeliveryPath = "delivery.zip/jre/lib/jrt-fs.jar"
		purl            = "pkg:maven/jrt-fs/jrt-fs@11.0.30"
		manifestPath    = "delivery.zip/jre/lib/jrt-fs.jar/META-INF/MANIFEST.MF"
	)

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{{
			Path:         jarDeliveryPath,
			OriginalPath: jarPath,
			Status:       extract.StatusSyftNative,
			Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
		}},
	}

	scans := []scan.ScanResult{
		{
			NodePath: "delivery.zip",
			BOM: &cdx.BOM{Components: &[]cdx.Component{{
				BOMRef:     "from-extracted",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "jrt-fs",
				Version:    "11.0.30",
				PackageURL: purl,
				Properties: &[]cdx.Property{{Name: "syft:location:0:path", Value: "/jre/lib/jrt-fs.jar"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
			}}},
			EvidencePaths: map[string][]string{"from-extracted": {jarDeliveryPath}},
		},
		{
			NodePath: jarDeliveryPath,
			BOM: &cdx.BOM{Components: &[]cdx.Component{{
				BOMRef:     "from-native",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "jrt-fs",
				Version:    "11.0.30",
				PackageURL: purl,
				Properties: &[]cdx.Property{{Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
			}}},
			EvidencePaths: map[string][]string{"from-native": {manifestPath}},
		},
	}

	bom, suppressions, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var purlMatches []cdx.Component
	for _, comp := range *bom.Components {
		if comp.PackageURL == purl {
			purlMatches = append(purlMatches, comp)
		}
	}
	if len(purlMatches) != 1 {
		t.Fatalf("expected exactly 1 jrt-fs component, got %d", len(purlMatches))
	}

	comp := purlMatches[0]
	if comp.Properties == nil {
		t.Fatal("surviving component has no properties")
	}
	var hasEvidence bool
	for _, p := range *comp.Properties {
		if p.Name == "extract-sbom:evidence-path" && p.Value != "" {
			hasEvidence = true
		}
	}
	if !hasEvidence {
		t.Error("surviving component should have evidence-path")
	}

	purlCount := 0
	for _, s := range suppressions {
		if s.Reason == SuppressionPURLDuplicate && s.Component.PackageURL == purl {
			purlCount++
		}
	}
	if purlCount != 1 {
		t.Errorf("expected 1 cross-node SuppressionPURLDuplicate for %s, got %d", purl, purlCount)
	}

	if bom.Dependencies != nil {
		componentRefs := make(map[string]bool)
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			componentRefs[bom.Metadata.Component.BOMRef] = true
		}
		for _, comp := range *bom.Components {
			componentRefs[comp.BOMRef] = true
		}
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies == nil {
				continue
			}
			for _, childRef := range *dep.Dependencies {
				if !componentRefs[childRef] {
					t.Errorf("dangling dependency ref %q in dep %q", childRef, dep.Ref)
				}
			}
		}
	}
}
