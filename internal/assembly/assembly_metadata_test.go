// Assembly metadata tests validate user-visible root metadata behavior,
// composition flags, and interpretation hints in the assembled SBOM.
package assembly

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
)

// TestAssembleProducesValidBOM verifies that Assemble produces a well-formed
// CycloneDX BOM with correct metadata from the simplest possible input:
// a single extracted node with no scan results.
func TestAssembleProducesValidBOM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a minimal input file so we can compute its hash.
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake zip content"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.RootMetadata = config.RootMetadata{
		Name:         "TestProduct",
		Manufacturer: "TestCorp",
		Version:      "1.0.0",
		DeliveryDate: "2025-01-15",
	}

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("SpecVersion = %v, want 1.6", bom.SpecVersion)
	}

	if bom.Metadata == nil {
		t.Fatal("Metadata is nil")
	}

	if bom.Metadata.Component == nil {
		t.Fatal("Metadata.Component is nil")
	}

	if bom.Metadata.Component.Name != "TestProduct" {
		t.Errorf("root name = %q, want %q", bom.Metadata.Component.Name, "TestProduct")
	}

	if bom.Metadata.Component.Version != "1.0.0" {
		t.Errorf("root version = %q, want %q", bom.Metadata.Component.Version, "1.0.0")
	}

	if bom.Metadata.Component.Supplier == nil || bom.Metadata.Component.Supplier.Name != "TestCorp" {
		t.Error("root supplier not set to TestCorp")
	}

	// Verify hash was computed.
	if bom.Metadata.Component.Hashes == nil || len(*bom.Metadata.Component.Hashes) == 0 {
		t.Error("root component has no hashes")
	}
}

// TestAssembleIncludesGeneratorVersionInMetadata verifies that the
// extract-sbom tool entry in metadata.tools reflects release build version
// metadata and that root properties include the generator version.
func TestAssembleIncludesGeneratorVersionInMetadata(t *testing.T) {
	old := buildinfo.ReleaseVersion
	buildinfo.ReleaseVersion = "v2.3.4"
	t.Cleanup(func() { buildinfo.ReleaseVersion = old })

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake zip content"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath

	tree := &extract.ExtractionNode{
		Path:         "delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Metadata == nil || bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatal("metadata tools are missing")
	}

	var foundExtractSBOM bool
	for _, comp := range *bom.Metadata.Tools.Components {
		if comp.Name != "extract-sbom" {
			continue
		}
		foundExtractSBOM = true
		if comp.Version != "v2.3.4" {
			t.Fatalf("extract-sbom tool version = %q, want %q", comp.Version, "v2.3.4")
		}
	}
	if !foundExtractSBOM {
		t.Fatal("extract-sbom tool metadata component not found")
	}

	if bom.Metadata.Component == nil || bom.Metadata.Component.Properties == nil {
		t.Fatal("root component properties are missing")
	}

	var foundGeneratorVersion bool
	for _, p := range *bom.Metadata.Component.Properties {
		if p.Name == "extract-sbom:generator-version" && p.Value == "v2.3.4" {
			foundGeneratorVersion = true
			break
		}
	}
	if !foundGeneratorVersion {
		t.Fatal("extract-sbom:generator-version property missing or incorrect")
	}
}

// TestAssembleDeriveRootNameFromFilename verifies that when no root name
// is configured, the input filename is used as the root component name.
func TestAssembleDeriveRootNameFromFilename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "my-delivery.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "my-delivery.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Metadata.Component.Name != "my-delivery.zip" {
		t.Errorf("root name = %q, want %q", bom.Metadata.Component.Name, "my-delivery.zip")
	}
}

// TestAssembleWithCompositions verifies that composition annotations
// are generated for extraction nodes based on their status.
func TestAssembleWithCompositions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "test.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "test.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Compositions == nil || len(*bom.Compositions) == 0 {
		t.Error("expected at least one composition annotation")
	}
}

// TestAssembleIncludesInterpretModeProperty verifies that the root component
// includes an extract-sbom:interpret-mode property reflecting the configured mode.
func TestAssembleIncludesInterpretModeProperty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "test.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []config.InterpretMode{config.InterpretPhysical, config.InterpretInstallerSemantic} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			cfg := config.DefaultConfig()
			cfg.InputPath = inputPath
			cfg.OutputDir = dir
			cfg.InterpretMode = mode

			tree := &extract.ExtractionNode{
				Path:         "test.zip",
				OriginalPath: inputPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.ZIP},
			}

			bom, _, err := Assemble(tree, nil, cfg)
			if err != nil {
				t.Fatalf("Assemble error: %v", err)
			}

			props := bom.Metadata.Component.Properties
			if props == nil {
				t.Fatal("root component has no properties")
			}

			found := false
			for _, p := range *props {
				if p.Name == "extract-sbom:interpret-mode" {
					if p.Value != mode.String() {
						t.Errorf("interpret-mode = %q, want %q", p.Value, mode.String())
					}
					found = true
				}
			}
			if !found {
				t.Error("extract-sbom:interpret-mode property not found on root component")
			}
		})
	}
}

// TestAssembleInstallerHintSurfacedOnMSINode verifies that when an extraction
// node has an InstallerHint, it appears as an extract-sbom:installer-hint
// property on the corresponding SBOM component.
func TestAssembleInstallerHintSurfacedOnMSINode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	msiPath := filepath.Join(dir, "setup.msi")
	if err := os.WriteFile(msiPath, []byte("MSI fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.InterpretMode = config.InterpretInstallerSemantic

	tree := &extract.ExtractionNode{
		Path:         "outer.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         "outer.zip/setup.msi",
				OriginalPath: msiPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.MSI},
				Metadata: &extract.ContainerMetadata{
					ProductName:    "Acme Widget",
					Manufacturer:   "Acme Corp",
					ProductVersion: "3.0.0",
				},
				InstallerHint: "msi-file-table-remapping-available",
			},
		},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var hintFound bool
	for _, comp := range *bom.Components {
		if comp.Properties == nil {
			continue
		}
		for _, p := range *comp.Properties {
			if p.Name == "extract-sbom:installer-hint" {
				if p.Value != "msi-file-table-remapping-available" {
					t.Errorf("installer-hint = %q, want %q", p.Value, "msi-file-table-remapping-available")
				}
				hintFound = true
			}
		}
	}

	if !hintFound {
		t.Error("extract-sbom:installer-hint property not found on MSI component")
	}
}

// TestAssembleNoInstallerHintInPhysicalMode verifies that when InstallerHint
// is empty (physical mode), no installer-hint property appears.
func TestAssembleNoInstallerHintInPhysicalMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(inputPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}

	msiPath := filepath.Join(dir, "setup.msi")
	if err := os.WriteFile(msiPath, []byte("MSI fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir
	cfg.InterpretMode = config.InterpretPhysical

	tree := &extract.ExtractionNode{
		Path:         "outer.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         "outer.zip/setup.msi",
				OriginalPath: msiPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.MSI},
				Metadata: &extract.ContainerMetadata{
					ProductName:    "Acme Widget",
					Manufacturer:   "Acme Corp",
					ProductVersion: "3.0.0",
				},
			},
		},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		return
	}

	for _, comp := range *bom.Components {
		if comp.Properties == nil {
			continue
		}
		for _, p := range *comp.Properties {
			if p.Name == "extract-sbom:installer-hint" {
				t.Errorf("unexpected installer-hint property in physical mode: %q", p.Value)
			}
		}
	}
}
