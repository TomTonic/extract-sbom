package assembly

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// evidenceSourceFromCataloger maps a Syft cataloger name (foundBy) to a
// human-readable description of the evidence source for the identification.
func evidenceSourceFromCataloger(foundBy string) string {
	switch {
	case strings.Contains(foundBy, "java-archive"):
		return "Java archive metadata (MANIFEST.MF / pom.properties)"
	case strings.Contains(foundBy, "java-pom"):
		return "Maven POM metadata"
	case strings.Contains(foundBy, "pe-binary"):
		return "PE version resource"
	case strings.Contains(foundBy, "dotnet-portable-executable"):
		return ".NET PE assembly metadata"
	case strings.Contains(foundBy, "dotnet-deps"):
		return ".NET deps.json"
	case strings.Contains(foundBy, "rpm"):
		return "RPM package header"
	case strings.Contains(foundBy, "dpkg"):
		return "Debian dpkg metadata"
	case strings.Contains(foundBy, "apk-db"):
		return "Alpine APK metadata"
	case strings.Contains(foundBy, "npm"):
		return "npm package.json"
	case strings.Contains(foundBy, "python"):
		return "Python package metadata"
	case strings.Contains(foundBy, "go-module"):
		return "Go module metadata"
	case strings.Contains(foundBy, "rust"):
		return "Rust Cargo metadata"
	case strings.Contains(foundBy, "conan"):
		return "Conan package metadata"
	case strings.Contains(foundBy, "linux-kernel"):
		return "Linux kernel metadata"
	case foundBy != "":
		return foundBy
	default:
		return ""
	}
}

// Assemble builds one consolidated CycloneDX BOM from the extraction tree and
// per-node scan results.
//
// Why this exists:
// The scan phase emits independent BOM fragments per extraction node, while
// downstream consumers need one auditable SBOM with deterministic references,
// containment dependencies, and completeness annotations.
//
// Typical use:
// The orchestrator calls Assemble once after extraction and scanning. The
// returned BOM is written via WriteSBOM, and suppression records are passed to
// report generation for traceability.
//
// Parameters:
// - tree: root extraction node that models the recursive delivery structure
// - scans: per-node scan results produced by scan.ScanAll
// - cfg: run configuration (root metadata, interpret mode, input path)
//
// Returns:
// - *cdx.BOM: unified deterministic BOM
// - []SuppressionRecord: dropped/merged component records for audit reporting
// - error: assembly failures (for example, unrecoverable BOM construction issues)
//
// Assumptions and constraints:
// - tree is expected to be non-nil and represent the processed input
// - component and dependency ordering is deterministic for reproducible output
func Assemble(tree *extract.ExtractionNode, scans []scan.ScanResult, cfg config.Config) (*cdx.BOM, []SuppressionRecord, error) {
	generatorInfo := buildinfo.Read()

	bom := cdx.NewBOM()
	bom.BOMFormat = "CycloneDX"
	bom.SpecVersion = cdx.SpecVersion1_6

	// Use input file's modification time for determinism.
	var serialTimestamp string
	if info, err := os.Stat(cfg.InputPath); err == nil {
		serialTimestamp = info.ModTime().UTC().Format(time.RFC3339)
	}

	// Set metadata.
	bom.Metadata = &cdx.Metadata{
		Timestamp: serialTimestamp,
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "extract-sbom",
					Version: generatorInfo.Version,
					Properties: &[]cdx.Property{
						{Name: "extract-sbom:build", Value: generatorInfo.String()},
						{Name: "extract-sbom:vcs-revision", Value: generatorInfo.Revision},
						{Name: "extract-sbom:vcs-time", Value: generatorInfo.Time},
						{Name: "extract-sbom:vcs-modified", Value: fmt.Sprintf("%t", generatorInfo.Modified)},
					},
				},
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "syft",
					Version: scan.Version,
				},
			},
		},
	}

	scanMap := make(map[string]*scan.ScanResult)
	for i := range scans {
		scanMap[scans[i].NodePath] = &scans[i]
	}
	refAssigner := newBOMRefAssigner(tree, scanMap)

	rootRef := refAssigner.RefForNode(tree.Path)
	rootComponent := cdx.Component{
		BOMRef: rootRef,
		Type:   cdx.ComponentTypeApplication,
		Name:   deriveRootName(cfg),
	}

	if cfg.RootMetadata.Version != "" {
		rootComponent.Version = cfg.RootMetadata.Version
	}

	if cfg.RootMetadata.Manufacturer != "" {
		rootComponent.Supplier = &cdx.OrganizationalEntity{
			Name: cfg.RootMetadata.Manufacturer,
		}
	}

	rootProps := []cdx.Property{
		{Name: "extract-sbom:delivery-path", Value: tree.Path},
		{Name: "extract-sbom:interpret-mode", Value: cfg.InterpretMode.String()},
		{Name: "extract-sbom:generator-version", Value: generatorInfo.Version},
		{Name: "extract-sbom:generator-build", Value: generatorInfo.String()},
	}

	if cfg.RootMetadata.DeliveryDate != "" {
		rootProps = append(rootProps, cdx.Property{
			Name: "extract-sbom:delivery-date", Value: cfg.RootMetadata.DeliveryDate,
		})
	}

	for k, v := range cfg.RootMetadata.Properties {
		rootProps = append(rootProps, cdx.Property{Name: k, Value: v})
	}

	if hash, err := computeSHA256(cfg.InputPath); err == nil {
		rootComponent.Hashes = &[]cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: hash},
		}
	}

	sort.Slice(rootProps, func(i, j int) bool {
		if rootProps[i].Name == rootProps[j].Name {
			return rootProps[i].Value < rootProps[j].Value
		}
		return rootProps[i].Name < rootProps[j].Name
	})
	rootComponent.Properties = &rootProps

	bom.Metadata.Component = &rootComponent

	var components []cdx.Component
	var dependencies []cdx.Dependency
	var compositions []cdx.Composition

	rootDep := cdx.Dependency{Ref: rootRef}

	var suppressions []SuppressionRecord
	processNode(tree, &components, &dependencies, &rootDep, &compositions, scanMap, refAssigner, true, &suppressions)

	dependencies = append(dependencies, rootDep)

	components, globalSuppressions := deduplicateGlobalComponents(components, dependencies)
	suppressions = append(suppressions, globalSuppressions...)

	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})

	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Ref < dependencies[j].Ref
	})
	for i := range dependencies {
		sortDependencyRefs(&dependencies[i])
	}

	if len(components) > 0 {
		bom.Components = &components
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}
	if len(compositions) > 0 {
		bom.Compositions = &compositions
	}

	return bom, suppressions, nil
}

// processNode recursively processes the extraction tree, creating components,
// dependencies, and composition annotations.
func processNode(node *extract.ExtractionNode, components *[]cdx.Component, dependencies *[]cdx.Dependency,
	parentDep *cdx.Dependency, compositions *[]cdx.Composition, scanMap map[string]*scan.ScanResult,
	refAssigner *bomRefAssigner, isRoot bool, suppressions *[]SuppressionRecord) {
	nodeRef := refAssigner.RefForNode(node.Path)

	if !isRoot {
		comp := cdx.Component{
			BOMRef: nodeRef,
			Type:   cdx.ComponentTypeFile,
			Name:   filepath.Base(node.Path),
		}

		props := []cdx.Property{{Name: "extract-sbom:delivery-path", Value: node.Path}}

		if node.Status != extract.StatusPending {
			props = append(props, cdx.Property{
				Name: "extract-sbom:extraction-status", Value: node.Status.String(),
			})
		}

		if node.Metadata != nil {
			if node.Metadata.ProductName != "" {
				comp.Name = node.Metadata.ProductName
			}
			if node.Metadata.ProductVersion != "" {
				comp.Version = node.Metadata.ProductVersion
			}
			if node.Metadata.Manufacturer != "" {
				comp.Supplier = &cdx.OrganizationalEntity{Name: node.Metadata.Manufacturer}
				cpe := generateCPE(node.Metadata.Manufacturer, comp.Name, comp.Version)
				if cpe != "" {
					comp.CPE = cpe
				}
			}
			if node.Metadata.ProductCode != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:msi-product-code", Value: node.Metadata.ProductCode})
			}
			if node.Metadata.UpgradeCode != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:msi-upgrade-code", Value: node.Metadata.UpgradeCode})
			}
			if node.Metadata.Language != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:msi-language", Value: node.Metadata.Language})
			}
		}

		if node.OriginalPath != "" {
			if hash, err := computeSHA256(node.OriginalPath); err == nil {
				comp.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: hash}}
			}
		}

		if node.InstallerHint != "" {
			props = append(props, cdx.Property{
				Name: "extract-sbom:installer-hint", Value: node.InstallerHint,
			})
		}

		sort.Slice(props, func(i, j int) bool {
			if props[i].Name == props[j].Name {
				return props[i].Value < props[j].Value
			}
			return props[i].Name < props[j].Name
		})
		comp.Properties = &props

		*components = append(*components, comp)

		if parentDep.Dependencies == nil {
			deps := make([]string, 0)
			parentDep.Dependencies = &deps
		}
		*parentDep.Dependencies = append(*parentDep.Dependencies, nodeRef)
	}

	nodeDep := cdx.Dependency{Ref: nodeRef}

	var compositionAggregate cdx.CompositionAggregate
	switch node.Status {
	case extract.StatusExtracted, extract.StatusSyftNative:
		compositionAggregate = cdx.CompositionAggregateComplete
	case extract.StatusSkipped, extract.StatusFailed, extract.StatusToolMissing, extract.StatusSecurityBlocked:
		compositionAggregate = cdx.CompositionAggregateIncomplete
	default:
		compositionAggregate = cdx.CompositionAggregateUnknown
	}

	if sr, ok := scanMap[node.Path]; ok && sr.Error == nil && sr.BOM != nil {
		candidates, nodeSuppressed := normalizeScanComponents(node, sr)
		*suppressions = append(*suppressions, nodeSuppressed...)
		for i := range candidates {
			comp := candidates[i].component
			comp.BOMRef = refAssigner.RefForComponent(node.Path, comp, i)

			props := []cdx.Property{{Name: "extract-sbom:delivery-path", Value: candidates[i].deliveryPath}}
			for _, evidencePath := range candidates[i].evidence {
				props = append(props, cdx.Property{Name: "extract-sbom:evidence-path", Value: evidencePath})
			}
			if src := evidenceSourceFromCataloger(candidates[i].foundBy); src != "" {
				props = append(props, cdx.Property{Name: "extract-sbom:evidence-source", Value: src})
			}
			if comp.Properties != nil {
				props = append(props, *comp.Properties...)
			}
			props = uniqueSortedProperties(props)
			comp.Properties = &props

			*components = append(*components, comp)

			if nodeDep.Dependencies == nil {
				deps := make([]string, 0)
				nodeDep.Dependencies = &deps
			}
			*nodeDep.Dependencies = append(*nodeDep.Dependencies, comp.BOMRef)
		}
	} else if sr, ok := scanMap[node.Path]; ok && sr.Error != nil {
		compositionAggregate = cdx.CompositionAggregateUnknown
	}

	*compositions = append(*compositions, cdx.Composition{
		Aggregate: compositionAggregate,
		Assemblies: &[]cdx.BOMReference{
			cdx.BOMReference(nodeRef),
		},
	})

	for _, child := range node.Children {
		processNode(child, components, dependencies, &nodeDep, compositions, scanMap, refAssigner, false, suppressions)
	}

	if !isRoot {
		*dependencies = append(*dependencies, nodeDep)
	} else if nodeDep.Dependencies != nil {
		if parentDep.Dependencies == nil {
			parentDep.Dependencies = nodeDep.Dependencies
		} else {
			*parentDep.Dependencies = append(*parentDep.Dependencies, *nodeDep.Dependencies...)
		}
	}
}

// sortDependencyRefs sorts one dependency's child reference list
// lexicographically for deterministic BOM output.
func sortDependencyRefs(dep *cdx.Dependency) {
	if dep == nil || dep.Dependencies == nil {
		return
	}
	sort.Slice(*dep.Dependencies, func(i, j int) bool {
		return (*dep.Dependencies)[i] < (*dep.Dependencies)[j]
	})
}

// uniqueSortedProperties removes duplicate property pairs and returns a stable
// name/value-ordered slice used throughout assembly and deduplication.
func uniqueSortedProperties(props []cdx.Property) []cdx.Property {
	if len(props) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(props))
	unique := make([]cdx.Property, 0, len(props))
	for _, prop := range props {
		key := prop.Name + "\x00" + prop.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, prop)
	}

	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Name == unique[j].Name {
			return unique[i].Value < unique[j].Value
		}
		return unique[i].Name < unique[j].Name
	})

	return unique
}

// deriveRootName produces the root component name from config or filename.
func deriveRootName(cfg config.Config) string {
	if cfg.RootMetadata.Name != "" {
		return cfg.RootMetadata.Name
	}
	return filepath.Base(cfg.InputPath)
}
