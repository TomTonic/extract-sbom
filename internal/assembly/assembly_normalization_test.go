// Normalization tests validate end-user visible package selection behavior
// when Syft emits overlapping, weak, or low-value component records.
package assembly

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestComponentDeliveryPathHandlesNilNode verifies that delivery path
// derivation remains defensive when no extraction node context exists.
func TestComponentDeliveryPathHandlesNilNode(t *testing.T) {
	t.Parallel()

	comp := cdx.Component{Name: "demo"}
	if got := componentDeliveryPath(nil, comp); got != "" {
		t.Fatalf("componentDeliveryPath(nil, comp) = %q, want empty", got)
	}
}

// TestAssembleFiltersFileCatalogerArtifacts verifies that Syft file-cataloger
// entries (type=file with absolute temp paths as names) are excluded from the
// assembled BOM. Only the properly-identified library-type entry should survive.
func TestAssembleFiltersFileCatalogerArtifacts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	scans := []scan.ScanResult{
		{
			NodePath: "delivery.zip",
			BOM: &cdx.BOM{
				Components: &[]cdx.Component{
					{
						BOMRef: "file-entry",
						Type:   cdx.ComponentTypeFile,
						Name:   "/tmp/extract-sbom-zip-12345/plugins/janino-3.1.10.jar",
					},
					{
						BOMRef:     "lib-entry",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "janino",
						Version:    "3.1.10",
						PackageURL: "pkg:maven/org.codehaus.janino/janino@3.1.10",
					},
				},
			},
		},
	}

	bom, _, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	for _, comp := range *bom.Components {
		if strings.HasPrefix(comp.Name, "/") {
			t.Errorf("file-cataloger artifact not filtered: Name=%q", comp.Name)
		}
	}

	found := false
	for _, comp := range *bom.Components {
		if comp.Name == "janino" && comp.Version == "3.1.10" {
			found = true
			break
		}
	}
	if !found {
		t.Error("properly-identified library component missing from BOM")
	}
}

// TestAssembleRefinesDeliveryPathFromSyftLocation verifies that for
// extracted-directory scans, the delivery-path is refined using
// syft:location:0:path instead of just using the container path.
func TestAssembleRefinesDeliveryPathFromSyftLocation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	scans := []scan.ScanResult{
		{
			NodePath: "delivery.zip",
			BOM: &cdx.BOM{
				Components: &[]cdx.Component{
					{
						BOMRef:     "pkg:maven/spring/web@6.0",
						Type:       cdx.ComponentTypeLibrary,
						Name:       "spring-web",
						Version:    "6.0",
						PackageURL: "pkg:maven/spring/web@6.0",
						Properties: &[]cdx.Property{
							{Name: "syft:location:0:path", Value: "/inner/services/app.zip"},
							{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
						},
					},
				},
			},
		},
	}

	bom, _, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	for _, comp := range *bom.Components {
		if comp.Name != "spring-web" {
			continue
		}
		if comp.Properties == nil {
			t.Fatal("spring-web component has no properties")
		}
		for _, p := range *comp.Properties {
			if p.Name == "extract-sbom:delivery-path" {
				want := "delivery.zip/inner/services/app.zip"
				if p.Value != want {
					t.Errorf("delivery-path = %q, want %q", p.Value, want)
				}
				return
			}
		}
		t.Error("spring-web component has no delivery-path property")
	}
	t.Error("spring-web component not found in BOM")
}

// TestAssembleMergesWeakDuplicatePlaceholders verifies that the assembled SBOM
// keeps a rich package record and drops weak placeholder duplicates for the
// same delivery/evidence location.
func TestAssembleMergesWeakDuplicatePlaceholders(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	scans := []scan.ScanResult{{
		NodePath: "delivery.zip",
		BOM: &cdx.BOM{Components: &[]cdx.Component{
			{
				BOMRef:     "good",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "janino",
				Version:    "3.1.10",
				PackageURL: "pkg:maven/org.codehaus.janino/janino@3.1.10",
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: "/plugins/launcher-ext/janino-3.1.10.jar"},
					{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
				},
			},
			{
				BOMRef: "weak",
				Type:   cdx.ComponentTypeLibrary,
				Name:   "janino-3.1.10.jar",
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: "/plugins/launcher-ext/janino-3.1.10.jar"},
				},
			},
		}},
		EvidencePaths: map[string][]string{
			"good": {"delivery.zip/plugins/launcher-ext/janino-3.1.10.jar/META-INF/MANIFEST.MF"},
			"weak": {"delivery.zip/plugins/launcher-ext/janino-3.1.10.jar/META-INF/MANIFEST.MF"},
		},
	}}

	bom, _, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	goodCount := 0
	weakCount := 0
	for _, comp := range *bom.Components {
		if comp.Name == "janino" && comp.Version == "3.1.10" && comp.PackageURL != "" {
			goodCount++
		}
		if comp.Name == "janino-3.1.10.jar" {
			weakCount++
		}
	}

	if goodCount != 1 {
		t.Fatalf("good janino component count = %d, want 1", goodCount)
	}
	if weakCount != 0 {
		t.Fatalf("weak placeholder count = %d, want 0", weakCount)
	}
}

// TestAssembleMergesSamePURLAtSameLocationWithDifferentEvidence verifies that
// two Syft entries for the same PURL at the same delivery path are collapsed
// into one component, keeping the entry that has evidence.
func TestAssembleMergesSamePURLAtSameLocationWithDifferentEvidence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	const (
		jarPath      = "/lib/gis/gt-xsd-wfs-28.0.jar"
		purl         = "pkg:maven/org.geotools.xsd/gt-xsd-wfs@28.0"
		manifestPath = "delivery.zip/lib/gis/gt-xsd-wfs-28.0.jar/META-INF/MANIFEST.MF"
	)

	noEvidenceBOMRef := "syft-no-evidence"
	withEvidenceBOMRef := "syft-with-evidence"

	scans := []scan.ScanResult{{
		NodePath: "delivery.zip",
		BOM: &cdx.BOM{Components: &[]cdx.Component{
			{
				BOMRef:     noEvidenceBOMRef,
				Type:       cdx.ComponentTypeLibrary,
				Name:       "gt-xsd-wfs",
				Version:    "28.0",
				PackageURL: purl,
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: jarPath},
					{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
				},
			},
			{
				BOMRef:     withEvidenceBOMRef,
				Type:       cdx.ComponentTypeLibrary,
				Name:       "gt-xsd-wfs",
				Version:    "28.0",
				PackageURL: purl,
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: jarPath},
					{Name: "syft:package:foundBy", Value: "java-archive-cataloger"},
				},
			},
		}},
		EvidencePaths: map[string][]string{
			withEvidenceBOMRef: {manifestPath},
		},
	}}

	bom, suppressions, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var matches []cdx.Component
	for _, comp := range *bom.Components {
		if comp.PackageURL == purl {
			matches = append(matches, comp)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 gt-xsd-wfs component, got %d", len(matches))
	}

	comp := matches[0]
	if comp.Properties == nil {
		t.Fatal("surviving component has no properties")
	}
	var evidenceFound bool
	for _, p := range *comp.Properties {
		if p.Name == "extract-sbom:evidence-path" && p.Value == manifestPath {
			evidenceFound = true
		}
	}
	if !evidenceFound {
		t.Errorf("surviving component is missing evidence-path %q", manifestPath)
	}

	purlCount := 0
	for _, s := range suppressions {
		if s.Reason == SuppressionPURLDuplicate && s.Component.PackageURL == purl {
			purlCount++
		}
	}
	if purlCount != 1 {
		t.Errorf("expected 1 SuppressionPURLDuplicate for %s, got %d", purl, purlCount)
	}
}

// TestAssembleKeepsDistinctStrongDuplicates verifies that if multiple strong
// package records exist at the same location, assembly does not collapse them.
func TestAssembleKeepsDistinctStrongDuplicates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	scans := []scan.ScanResult{{
		NodePath: "delivery.zip",
		BOM: &cdx.BOM{Components: &[]cdx.Component{
			{
				BOMRef:     "a",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "pkg-a",
				Version:    "1.0.0",
				PackageURL: "pkg:maven/acme/pkg-a@1.0.0",
				Properties: &[]cdx.Property{{Name: "syft:location:0:path", Value: "/plugins/shared.jar"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
			},
			{
				BOMRef:     "b",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "pkg-b",
				Version:    "2.0.0",
				PackageURL: "pkg:maven/acme/pkg-b@2.0.0",
				Properties: &[]cdx.Property{{Name: "syft:location:0:path", Value: "/plugins/shared.jar"}, {Name: "syft:package:foundBy", Value: "java-archive-cataloger"}},
			},
		}},
		EvidencePaths: map[string][]string{
			"a": {"delivery.zip/plugins/shared.jar/META-INF/MANIFEST.MF"},
			"b": {"delivery.zip/plugins/shared.jar/META-INF/MANIFEST.MF"},
		},
	}}

	bom, _, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	foundA := false
	foundB := false
	for _, comp := range *bom.Components {
		if comp.Name == "pkg-a" {
			foundA = true
		}
		if comp.Name == "pkg-b" {
			foundB = true
		}
	}

	if !foundA || !foundB {
		t.Fatalf("expected both strong components to remain (foundA=%t, foundB=%t)", foundA, foundB)
	}
}

// TestNormalizeScanComponentsUsesLogicalDeliveryPathForSuppressedFileArtifacts
// verifies that suppressed file artifacts are reported with a logical
// delivery path instead of temp workspace paths.
func TestNormalizeScanComponentsUsesLogicalDeliveryPathForSuppressedFileArtifacts(t *testing.T) {
	t.Parallel()

	node := &extract.ExtractionNode{
		Path:   "delivery.zip/lib.tar",
		Status: extract.StatusExtracted,
	}
	sr := &scan.ScanResult{
		NodePath: node.Path,
		BOM: &cdx.BOM{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeFile,
			Name: "/tmp/extract-sbom/lib/example.jar",
			Properties: &[]cdx.Property{{
				Name:  "syft:location:0:path",
				Value: "nested/example.jar",
			}},
		}}},
	}

	_, suppressions := normalizeScanComponents(node, sr)
	if len(suppressions) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(suppressions))
	}
	if suppressions[0].Reason != SuppressionFSArtifact {
		t.Fatalf("suppression reason = %q, want %q", suppressions[0].Reason, SuppressionFSArtifact)
	}
	if suppressions[0].DeliveryPath != "delivery.zip/lib.tar/nested/example.jar" {
		t.Fatalf("delivery path = %q, want %q", suppressions[0].DeliveryPath, "delivery.zip/lib.tar/nested/example.jar")
	}
}
