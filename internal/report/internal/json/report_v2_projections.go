package json

import (
	"strings"

	"github.com/TomTonic/extract-sbom/internal/extract"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// buildProjectionsV2 prepares renderer-facing views from entities and raw data.
//
// The per-section row builders live in report_v2_projections_pipeline.go
// (extraction/scan/policy/issues) and report_v2_projections_findings.go
// (vulnerabilities/component index/suppression); this file owns the orchestration
// and the summary-level metrics.
func buildProjectionsV2(data ReportData, entities entitiesV2, index entityIndexV2) ProjectionsV2 {
	occurrences, occurrenceStats := domain.CollectComponentOccurrences(data.BOM)
	packageGroups := domain.BuildPackageOccurrenceGroups(occurrences)

	vulnSetByBOMRef := buildVulnIDSetByBOMRef(data.Vulnerabilities)
	componentIndexRows := buildComponentIndexProjectionRows(packageGroups, index, vulnSetByBOMRef)
	if len(componentIndexRows) == 0 {
		componentIndexRows = buildComponentFallbackProjectionRows(entities.Components)
	}

	extPaths := make([]string, 0)
	var walkTree func(node *extract.ExtractionNode)
	walkTree = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}
		if node.Status == extract.StatusSkipped && strings.Contains(strings.ToLower(node.StatusDetail), "extension") {
			extPaths = append(extPaths, node.Path)
		}
		for _, child := range node.Children {
			walkTree(child)
		}
	}
	walkTree(data.Tree)
	extPaths = domain.SortedUniqueNonEmptyStrings(extPaths)
	if extPaths == nil {
		extPaths = make([]string, 0)
	}

	noPkgs := make([]string, 0)
	for _, sr := range data.Scans {
		if sr.BOM != nil && sr.BOM.Components != nil && len(*sr.BOM.Components) == 0 {
			noPkgs = append(noPkgs, sr.NodePath)
		}
	}
	noPkgs = domain.SortedUniqueNonEmptyStrings(noPkgs)
	if noPkgs == nil {
		noPkgs = make([]string, 0)
	}

	scanRows := buildScanProjectionRows(data.Scans, entities)
	policyRows := buildPolicyDecisionProjectionRows(entities)
	suppressionGroups := buildSuppressionGroupsProjection(data.Suppressions, entities.Suppressions, componentIndexRows)
	rootComponent := buildRootComponent(data)
	archiveCount, fileCount := countTreeArchivesAndFiles(data.Tree)
	_, uniqueVulns, affectedPackages := domain.CollectVulnStats(data.Vulnerabilities)
	grypeProvenance := buildGrypeProvenance(data.Vulnerabilities)

	return ProjectionsV2{
		Summary: ProjectionSummaryV2{
			Nodes:           len(entities.Nodes),
			ScanTasks:       len(entities.ScanTasks),
			Components:      len(entities.Components),
			PackageGroups:   len(entities.PackageGroups),
			Vulnerabilities: len(entities.Vulnerabilities),
			Suppressions:    len(entities.Suppressions),
			PolicyDecisions: len(entities.PolicyDecisions),
			Issues:          len(entities.Issues),
			ComponentIndexStats: ComponentIndexStatsV2{
				TotalComponents:               occurrenceStats.TotalComponents,
				MissingDeliveryPath:           occurrenceStats.MissingDeliveryPath,
				FilteredContainerNodes:        occurrenceStats.FilteredContainerNodes,
				FilteredAbsolutePathNames:     occurrenceStats.FilteredAbsolutePathNames,
				FilteredLowValueFileArtifacts: occurrenceStats.FilteredLowValueFileArtifacts,
				DuplicateMerged:               occurrenceStats.DuplicateMerged,
				IndexedComponents:             occurrenceStats.IndexedComponents,
				IndexedWithPURL:               occurrenceStats.IndexedWithPURL,
				IndexedWithoutPURL:            occurrenceStats.IndexedWithoutPURL,
				IndexedWithEvidencePath:       occurrenceStats.IndexedWithEvidencePath,
				IndexedWithEvidenceSourceOnly: occurrenceStats.IndexedWithEvidenceSourceOnly,
				IndexedWithoutEvidence:        occurrenceStats.IndexedWithoutEvidence,
			},
			VulnerabilityEnrichmentState: vulnerabilityStateValue(data.Vulnerabilities),
			VulnerabilityRequested:       vulnerabilityRequestedValue(data.Vulnerabilities),
			ExtensionFilteredPaths:       extPaths,
			ScanNoPackagePaths:           noPkgs,
			RootComponent:                rootComponent,
			ArchiveCount:                 archiveCount,
			FileCount:                    fileCount,
			AffectedPackageCount:         affectedPackages,
			UniqueVulnerabilityCount:     uniqueVulns,
			GrypeProvenance:              grypeProvenance,
		},
		ExtractionLog:     buildExtractionProjectionRows(data.Tree, index),
		Scans:             scanRows,
		Vulnerabilities:   buildVulnerabilityProjectionRows(data.Vulnerabilities, packageGroups, index, bomNamesByRef(data)),
		Issues:            buildIssueProjectionRows(entities),
		ComponentIndex:    componentIndexRows,
		PolicyDecisions:   policyRows,
		SuppressionGroups: suppressionGroups,
	}
}

// buildRootComponent extracts the assembled BOM's root component metadata for projection,
// augmented with operator-supplied config properties.
func buildRootComponent(data ReportData) *BOMRootComponentV2 {
	hasProps := len(data.Config.RootMetadata.Properties) > 0
	hasBOM := data.BOM != nil && data.BOM.Metadata != nil && data.BOM.Metadata.Component != nil
	if !hasBOM && !hasProps {
		return nil
	}
	rc := &BOMRootComponentV2{}
	if hasBOM {
		comp := data.BOM.Metadata.Component
		rc.BOMRef = comp.BOMRef
		rc.Name = comp.Name
		rc.Version = comp.Version
	}
	if hasProps {
		rc.ConfigProperties = make(map[string]string, len(data.Config.RootMetadata.Properties))
		for k, v := range data.Config.RootMetadata.Properties {
			rc.ConfigProperties[k] = v
		}
	}
	return rc
}

// bomNamesByRef builds a BOMRef→Name lookup from the assembled BOM for use as a
// fallback when a component doesn't appear in the occurrence index (e.g. missing delivery path).
func bomNamesByRef(data ReportData) map[string]string {
	if data.BOM == nil || data.BOM.Components == nil {
		return nil
	}
	comps := *data.BOM.Components
	m := make(map[string]string, len(comps))
	for i := range comps {
		if comps[i].BOMRef != "" {
			m[comps[i].BOMRef] = comps[i].Name
		}
	}
	return m
}

// countTreeArchivesAndFiles walks the extraction tree, counting expanded
// containers (nodes with children) as archives and leaf nodes as files.
func countTreeArchivesAndFiles(tree *extract.ExtractionNode) (archives, files int) {
	var walk func(node *extract.ExtractionNode)
	walk = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}
		if len(node.Children) > 0 {
			archives++
		} else {
			files++
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(tree)
	return archives, files
}

// buildGrypeProvenance extracts the Grype scanner and DB provenance for the
// projection, leaving fields empty when enrichment did not run.
func buildGrypeProvenance(v *vulnscan.Result) GrypeProvenanceV2 {
	if v == nil {
		return GrypeProvenanceV2{}
	}
	return GrypeProvenanceV2{
		Version:   v.GrypeVersion,
		DBSchema:  v.DBSchemaVersion,
		DBBuilt:   v.DBBuilt,
		DBUpdated: v.DBUpdated,
	}
}

// sourceRefsOrNil returns a valid sourceRefs slice or nil to skip omit serialization.
func sourceRefsOrNil(ids ...string) []string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func vulnerabilityStateValue(v *vulnscan.Result) string {
	if v == nil {
		return string(vulnscan.StateNotRequested)
	}
	if v.Requested && v.State == "" {
		return string(vulnscan.StateNotRequested)
	}
	return string(v.State)
}

func vulnerabilityRequestedValue(v *vulnscan.Result) bool {
	return v != nil && v.Requested
}
