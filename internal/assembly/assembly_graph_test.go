// Assembly graph tests validate user-visible containment graph construction
// for nested containers and package dependencies.
package assembly

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// TestAssembleNestedScenarioBuildsDependencyGraph verifies a realistic nested
// container chain with merged scan results: CAB -> TAR -> ZIP -> JAR -> package.
func TestAssembleNestedScenarioBuildsDependencyGraph(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outerPath := filepath.Join(dir, "delivery.cab")
	tarPath := filepath.Join(dir, "layer.tar")
	zipPath := filepath.Join(dir, "app.zip")
	jarPath := filepath.Join(dir, "lib.jar")
	for _, file := range []string{outerPath, tarPath, zipPath, jarPath} {
		if err := os.WriteFile(file, []byte(filepath.Base(file)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = outerPath
	cfg.OutputDir = dir

	jarNodePath := "delivery.cab/layer.tar/app.zip/lib.jar"
	tree := &extract.ExtractionNode{
		Path:         "delivery.cab",
		OriginalPath: outerPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.CAB},
		Children: []*extract.ExtractionNode{{
			Path:         "delivery.cab/layer.tar",
			OriginalPath: tarPath,
			Status:       extract.StatusExtracted,
			Format:       identify.FormatInfo{Format: identify.TAR},
			Children: []*extract.ExtractionNode{{
				Path:         "delivery.cab/layer.tar/app.zip",
				OriginalPath: zipPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.ZIP},
				Children: []*extract.ExtractionNode{{
					Path:         jarNodePath,
					OriginalPath: jarPath,
					Status:       extract.StatusSyftNative,
					Format:       identify.FormatInfo{Format: identify.ZIP, SyftNative: true},
				}},
			}},
		}},
	}

	scans := []scan.ScanResult{{
		NodePath: jarNodePath,
		BOM: &cdx.BOM{Components: &[]cdx.Component{{
			BOMRef:  "pkg:maven/com.acme/demo@1.0.0",
			Name:    "demo",
			Version: "1.0.0",
		}}},
		EvidencePaths: map[string][]string{
			"pkg:maven/com.acme/demo@1.0.0": {jarNodePath + "/META-INF/MANIFEST.MF"},
		},
	}}

	bom, _, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Dependencies == nil {
		t.Fatal("Dependencies is nil")
	}

	depsByRef := make(map[string][]string)
	for _, dep := range *bom.Dependencies {
		if dep.Dependencies != nil {
			depsByRef[dep.Ref] = append([]string(nil), *dep.Dependencies...)
		}
	}
	scanMap := map[string]*scan.ScanResult{jarNodePath: &scans[0]}
	refAssigner := newBOMRefAssigner(tree, scanMap)

	tarRef := refAssigner.RefForNode("delivery.cab/layer.tar")
	zipRef := refAssigner.RefForNode("delivery.cab/layer.tar/app.zip")
	jarRef := refAssigner.RefForNode(jarNodePath)
	pkgRef := refAssigner.RefForComponent(jarNodePath, (*scans[0].BOM.Components)[0], 0)
	rootRef := refAssigner.RefForNode("delivery.cab")

	if !reflect.DeepEqual(depsByRef[rootRef], []string{tarRef}) {
		t.Fatalf("root deps = %v, want [%s]", depsByRef[rootRef], tarRef)
	}
	if !reflect.DeepEqual(depsByRef[tarRef], []string{zipRef}) {
		t.Fatalf("tar deps = %v, want [%s]", depsByRef[tarRef], zipRef)
	}
	if !reflect.DeepEqual(depsByRef[zipRef], []string{jarRef}) {
		t.Fatalf("zip deps = %v, want [%s]", depsByRef[zipRef], jarRef)
	}
	if !reflect.DeepEqual(depsByRef[jarRef], []string{pkgRef}) {
		t.Fatalf("jar deps = %v, want [%s]", depsByRef[jarRef], pkgRef)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil")
	}

	var packageFound bool
	for _, comp := range *bom.Components {
		if comp.BOMRef != pkgRef {
			continue
		}
		packageFound = true
		if comp.Properties == nil {
			t.Fatal("merged package has no properties")
		}
		props := make(map[string][]string)
		for _, prop := range *comp.Properties {
			props[prop.Name] = append(props[prop.Name], prop.Value)
		}
		if !reflect.DeepEqual(props["extract-sbom:delivery-path"], []string{jarNodePath}) {
			t.Fatalf("delivery-path = %v, want [%s]", props["extract-sbom:delivery-path"], jarNodePath)
		}
		if !reflect.DeepEqual(props["extract-sbom:evidence-path"], []string{jarNodePath + "/META-INF/MANIFEST.MF"}) {
			t.Fatalf("evidence-path = %v, want manifest path", props["extract-sbom:evidence-path"])
		}
	}
	if !packageFound {
		t.Fatal("merged package component not found")
	}
}

// TestAssembleWithScanResultsMergesComponents verifies that components
// from per-node scan results are merged into the consolidated BOM.
func TestAssembleWithScanResultsMergesComponents(t *testing.T) {
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
					{BOMRef: "pkg:npm/express@4.18.0", Name: "express", Version: "4.18.0"},
					{BOMRef: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21"},
				},
			},
		},
	}

	bom, _, err := Assemble(tree, scans, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil, expected merged components")
	}

	if len(*bom.Components) < 2 {
		t.Errorf("Components count = %d, want >= 2", len(*bom.Components))
	}
}

// TestAssembleNestedTreeCreatesContainerComponents verifies that nested
// extraction nodes produce container-as-module components with proper
// dependency relationships.
func TestAssembleNestedTreeCreatesContainerComponents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(inputPath, []byte("PK fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	innerPath := filepath.Join(dir, "inner.zip")
	if err := os.WriteFile(innerPath, []byte("PK inner"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.InputPath = inputPath
	cfg.OutputDir = dir

	tree := &extract.ExtractionNode{
		Path:         "outer.zip",
		OriginalPath: inputPath,
		Status:       extract.StatusExtracted,
		Format:       identify.FormatInfo{Format: identify.ZIP},
		Children: []*extract.ExtractionNode{
			{
				Path:         "outer.zip/inner.zip",
				OriginalPath: innerPath,
				Status:       extract.StatusExtracted,
				Format:       identify.FormatInfo{Format: identify.ZIP},
			},
		},
	}

	bom, _, err := Assemble(tree, nil, cfg)
	if err != nil {
		t.Fatalf("Assemble error: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Components is nil, expected container component for inner.zip")
	}

	found := false
	for _, comp := range *bom.Components {
		if comp.Name == "inner.zip" {
			found = true
			break
		}
	}

	if !found {
		t.Error("inner.zip container component not found in Components")
	}

	if bom.Dependencies == nil {
		t.Fatal("Dependencies is nil")
	}
}
