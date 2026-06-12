package json

import (
	"sort"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// buildProjectionsV2 prepares renderer-facing views from entities and raw data.
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

// buildExtractionProjectionRows flattens extraction tree data into ordered rows.
func buildExtractionProjectionRows(tree *extract.ExtractionNode, index entityIndexV2) []ExtractionLogRowV2 {
	rows := make([]ExtractionLogRowV2, 0)
	var walk func(node *extract.ExtractionNode, depth int)
	walk = func(node *extract.ExtractionNode, depth int) {
		if node == nil {
			return
		}
		row := ExtractionLogRowV2{
			SourceRefs:  sourceRefsOrNil(index.nodeByPath[node.Path]),
			Path:        node.Path,
			Status:      node.Status.String(),
			Format:      node.Format.Format.String(),
			Tool:        node.Tool,
			Detail:      node.StatusDetail,
			Depth:       depth,
			SandboxUsed: node.SandboxUsed,
		}
		if node.Duration > 0 {
			row.Duration = node.Duration.Round(time.Millisecond).String()
		}
		if node.ArchiveMeta != nil {
			row.ArchiveMeta = &ExtractionArchiveMetaV2{
				Type:             node.ArchiveMeta.Type,
				Methods:          append([]string(nil), node.ArchiveMeta.Methods...),
				HasEncryptedItem: node.ArchiveMeta.HasEncryptedItem,
				PhysicalSize:     node.ArchiveMeta.PhysicalSize,
				HeadersSize:      node.ArchiveMeta.HeadersSize,
				Solid:            node.ArchiveMeta.Solid,
				Blocks:           node.ArchiveMeta.Blocks,
			}
		}
		rows = append(rows, row)
		for _, child := range node.Children {
			walk(child, depth+1)
		}
	}
	walk(tree, 0)
	return rows
}

// buildScanProjectionRows maps scan results into display rows.
func buildScanProjectionRows(scans []scan.ScanResult, entities entitiesV2) []ScanRowV2 {
	scanEntityByPath := make(map[string]string, len(entities.ScanTasks))
	for i := range entities.ScanTasks {
		scanEntityByPath[entities.ScanTasks[i].NodePath] = entities.ScanTasks[i].ID
	}

	rows := make([]ScanRowV2, 0, len(scans))
	for i := range scans {
		compCount := 0
		if scans[i].BOM != nil && scans[i].BOM.Components != nil {
			compCount = len(*scans[i].BOM.Components)
		}
		evidencePaths := scan.FlattenEvidencePaths(scans[i])
		if evidencePaths == nil {
			evidencePaths = []string{}
		}
		row := ScanRowV2{
			SourceRefs:     sourceRefsOrNil(scanEntityByPath[scans[i].NodePath]),
			NodePath:       scans[i].NodePath,
			ComponentCount: compCount,
			EvidencePaths:  evidencePaths,
		}
		if scans[i].Error != nil {
			row.Error = scans[i].Error.Error()
		}
		rows = append(rows, row)
	}
	return rows
}

// buildPolicyDecisionProjectionRows converts policy decision entities into projection rows.
func buildPolicyDecisionProjectionRows(entities entitiesV2) []PolicyDecisionRowV2 {
	rows := make([]PolicyDecisionRowV2, 0, len(entities.PolicyDecisions))
	for i := range entities.PolicyDecisions {
		rows = append(rows, PolicyDecisionRowV2{
			SourceRef: entities.PolicyDecisions[i].ID,
			Trigger:   entities.PolicyDecisions[i].Trigger,
			NodePath:  entities.PolicyDecisions[i].NodePath,
			Action:    entities.PolicyDecisions[i].Action,
			Detail:    entities.PolicyDecisions[i].Detail,
		})
	}
	return rows
}

// buildSuppressionGroupsProjection groups suppression records by reason, sorts them
// deterministically, and resolves kept-component anchors from the component index.
func buildSuppressionGroupsProjection(records []assembly.SuppressionRecord, suppressionEntities []suppressionEntityV2, componentIndex []PackageOccurrenceGroupV2) SuppressionGroupsV2 {
	componentToAnchor := make(map[string]string)
	for _, group := range componentIndex {
		for _, occ := range group.Occurrences {
			for _, ref := range occ.SourceRefs {
				componentToAnchor[ref] = group.AnchorID
			}
		}
	}

	fsArtifacts := make([]SuppressionRowV2, 0)
	lowValue := make([]SuppressionRowV2, 0)
	weakDups := make([]SuppressionRowV2, 0)
	purlDups := make([]SuppressionRowV2, 0)

	for i := range records {
		var entity suppressionEntityV2
		if i < len(suppressionEntities) {
			entity = suppressionEntities[i]
		}
		row := SuppressionRowV2{
			SourceRef:         entity.ID,
			DeliveryPath:      records[i].DeliveryPath,
			ComponentName:     records[i].Component.Name,
			KeptComponentName: entity.KeptComponentName,
			KeptComponentID:   entity.KeptComponentID,
			KeptAnchorID:      componentToAnchor[entity.KeptComponentID],
			ResolutionStatus:  entity.ResolutionStatus,
			ResolutionReason:  entity.ResolutionReason,
		}
		switch records[i].Reason {
		case assembly.SuppressionFSArtifact:
			fsArtifacts = append(fsArtifacts, row)
		case assembly.SuppressionLowValueFile:
			lowValue = append(lowValue, row)
		case assembly.SuppressionWeakDuplicate:
			weakDups = append(weakDups, row)
		case assembly.SuppressionPURLDuplicate:
			purlDups = append(purlDups, row)
		}
	}

	sortSuppressionRows(fsArtifacts)
	sortSuppressionRows(lowValue)
	sortSuppressionRows(weakDups)
	sortSuppressionRows(purlDups)

	return SuppressionGroupsV2{
		FSArtifacts: fsArtifacts,
		LowValue:    lowValue,
		WeakDups:    weakDups,
		PURLDups:    purlDups,
	}
}

func sortSuppressionRows(rows []SuppressionRowV2) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DeliveryPath != rows[j].DeliveryPath {
			return rows[i].DeliveryPath < rows[j].DeliveryPath
		}
		return rows[i].ComponentName < rows[j].ComponentName
	})
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
	m := make(map[string]string, len(*data.BOM.Components))
	for _, c := range *data.BOM.Components {
		if c.BOMRef != "" {
			m[c.BOMRef] = c.Name
		}
	}
	return m
}

// buildVulnerabilityProjectionRows builds highly grouped and enriched vulnerability rows.
func buildVulnerabilityProjectionRows(v *vulnscan.Result, packageGroups []domain.PackageOccurrenceGroup, index entityIndexV2, bomNames map[string]string) []VulnerabilityRowV2 {
	if v == nil || len(v.MatchesByBOMRef) == 0 {
		return []VulnerabilityRowV2{}
	}
	// We map ObjectID back to component
	byID := map[string]domain.ComponentOccurrence{}
	for i := range packageGroups {
		for j := range packageGroups[i].Occurrences {
			byID[packageGroups[i].Occurrences[j].ObjectID] = packageGroups[i].Occurrences[j]
		}
	}
	anchorByOccurrence := map[string]string{}
	for i := range packageGroups {
		for j := range packageGroups[i].Occurrences {
			anchorByOccurrence[packageGroups[i].Occurrences[j].ObjectID] = packageGroups[i].AnchorID
		}
	}

	rows := make([]VulnerabilityRowV2, 0)
	seen := map[string]struct{}{}
	for compID, matches := range v.MatchesByBOMRef {
		occ := byID[compID]
		packageName := strings.TrimSpace(occ.PackageName)
		if packageName == "" {
			packageName = strings.TrimSpace(bomNames[compID])
		}
		packageVersion := strings.TrimSpace(occ.Version)
		packageAnchorID := anchorByOccurrence[compID]
		for i := range matches {
			name := packageName
			if name == "" {
				name = strings.TrimSpace(matches[i].ArtifactName)
			}
			if packageName == "" {
				packageName = name
			}
			installed := packageVersion
			if installed == "" {
				installed = strings.TrimSpace(matches[i].ArtifactVersion)
			}
			if packageVersion == "" {
				packageVersion = installed
			}
			packageKey := strings.Join([]string{packageName, packageVersion}, "|")
			key := strings.Join([]string{
				packageKey,
				name,
				installed,
				strings.TrimSpace(matches[i].VulnerabilityID),
				domain.NormalizeSeverity(matches[i].Severity),
				strings.Join(matches[i].FixVersions, ", "),
			}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			// Try to link it to the vulnerabilityEntityV2
			// The entity logic matches on VulnerabilityID & BOMRef
			// But for now, we just pass the compID as a fallback source ref
			var sourceRefs []string
			if entityID := index.componentByRef[compID]; entityID != "" {
				sourceRefs = []string{entityID} // Ideally we'd find the exact vulnerability entity ID
			}

			kevVal := false
			if matches[i].KEV != nil && *matches[i].KEV {
				kevVal = true
			}

			rows = append(rows, VulnerabilityRowV2{
				SourceRefs:      sourceRefs,
				PackageAnchorID: packageAnchorID,
				PackageKey:      packageKey,
				Name:            name,
				Installed:       installed,
				FixedIn:         strings.Join(matches[i].FixVersions, ", "),
				VulnerabilityID: matches[i].VulnerabilityID,
				Severity:        domain.NormalizeSeverity(matches[i].Severity),
				CVSSScore:       matches[i].CVSSScore,
				CVSSVersion:     matches[i].CVSSVersion,
				CVSSVector:      matches[i].CVSSVector,
				Description:     matches[i].Description,
				EPSS:            matches[i].EPSS,
				EPSSPercentile:  matches[i].EPSSPercentile,
				Risk:            matches[i].Risk,
				KEV:             kevVal,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		leftRisk, rightRisk := 0.0, 0.0
		if rows[i].Risk != nil {
			leftRisk = *rows[i].Risk
		}
		if rows[j].Risk != nil {
			rightRisk = *rows[j].Risk
		}
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}

		if rows[i].KEV != rows[j].KEV {
			return rows[i].KEV
		}

		leftEPSSPct, rightEPSSPct := 0.0, 0.0
		if rows[i].EPSSPercentile != nil {
			leftEPSSPct = *rows[i].EPSSPercentile
		}
		if rows[j].EPSSPercentile != nil {
			rightEPSSPct = *rows[j].EPSSPercentile
		}
		if leftEPSSPct != rightEPSSPct {
			return leftEPSSPct > rightEPSSPct
		}

		leftEPSS, rightEPSS := 0.0, 0.0
		if rows[i].EPSS != nil {
			leftEPSS = *rows[i].EPSS
		}
		if rows[j].EPSS != nil {
			rightEPSS = *rows[j].EPSS
		}
		if leftEPSS != rightEPSS {
			return leftEPSS > rightEPSS
		}

		if severityRank(rows[i].Severity) != severityRank(rows[j].Severity) {
			return severityRank(rows[i].Severity) < severityRank(rows[j].Severity)
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		if rows[i].VulnerabilityID != rows[j].VulnerabilityID {
			return rows[i].VulnerabilityID < rows[j].VulnerabilityID
		}
		return rows[i].PackageKey < rows[j].PackageKey
	})
	return rows
}

// buildIssueProjectionRows emits issue rows.
func buildIssueProjectionRows(entities entitiesV2) []IssueRowV2 {
	rows := make([]IssueRowV2, 0, len(entities.Issues))
	for i := range entities.Issues {
		rows = append(rows, IssueRowV2{
			SourceRefs: []string{entities.Issues[i].ID},
			Stage:      entities.Issues[i].Stage,
			Message:    entities.Issues[i].Message,
		})
	}
	return rows
}

// buildVulnIDSetByBOMRef maps each BOMRef to the set of unique vulnerability IDs matched against it.
func buildVulnIDSetByBOMRef(v *vulnscan.Result) map[string]map[string]struct{} {
	if v == nil || len(v.MatchesByBOMRef) == 0 {
		return nil
	}
	m := make(map[string]map[string]struct{}, len(v.MatchesByBOMRef))
	for ref, matches := range v.MatchesByBOMRef {
		set := make(map[string]struct{}, len(matches))
		for i := range matches {
			set[matches[i].VulnerabilityID] = struct{}{}
		}
		m[ref] = set
	}
	return m
}

// buildComponentIndexProjectionRows maps domain occurrence grouping into rows,
// annotating each occurrence with its vulnerability count.
func buildComponentIndexProjectionRows(groups []domain.PackageOccurrenceGroup, index entityIndexV2, vulnSetByBOMRef map[string]map[string]struct{}) []PackageOccurrenceGroupV2 {
	rows := make([]PackageOccurrenceGroupV2, 0, len(groups))
	for i := range groups {
		groupRefs := make([]string, 0, len(groups[i].Occurrences))
		occRows := make([]OccurrenceRowV2, 0, len(groups[i].Occurrences))
		groupUniqueIDs := make(map[string]struct{})

		for j := range groups[i].Occurrences {
			bomRef := groups[i].Occurrences[j].ObjectID
			compID := index.componentByRef[bomRef]
			if compID != "" {
				groupRefs = append(groupRefs, compID)
			}
			vulnCount := len(vulnSetByBOMRef[bomRef])
			for id := range vulnSetByBOMRef[bomRef] {
				groupUniqueIDs[id] = struct{}{}
			}
			occRows = append(occRows, OccurrenceRowV2{
				SourceRefs:     sourceRefsOrNil(compID),
				ObjectID:       groups[i].Occurrences[j].ObjectID,
				DeliveryPaths:  groups[i].Occurrences[j].DeliveryPaths,
				EvidencePaths:  groups[i].Occurrences[j].EvidencePaths,
				EvidenceSource: groups[i].Occurrences[j].EvidenceSource,
				FoundBy:        groups[i].Occurrences[j].FoundBy,
				VulnCount:      vulnCount,
			})
		}
		groupRefs = domain.SortedUniqueStrings(groupRefs)
		rows = append(rows, PackageOccurrenceGroupV2{
			SourceRefs:      domain.NormalizeProjectionRefs(groupRefs),
			AnchorID:        groups[i].AnchorID,
			PackageName:     groups[i].PackageName,
			Version:         groups[i].Version,
			PURLs:           groups[i].PURLs,
			OccurrenceCount: len(groups[i].Occurrences),
			VulnUniqueCount: len(groupUniqueIDs),
			Occurrences:     occRows,
		})
	}
	return rows
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

// buildComponentFallbackProjectionRows provides a projection when occurrence data is unavailable.
func buildComponentFallbackProjectionRows(components []componentEntityV2) []PackageOccurrenceGroupV2 {
	rows := make([]PackageOccurrenceGroupV2, 0, len(components))
	for i := range components {
		purls := []string{}
		if components[i].PURL != "" {
			purls = append(purls, components[i].PURL)
		}
		rows = append(rows, PackageOccurrenceGroupV2{
			SourceRefs:  []string{components[i].ID},
			AnchorID:    components[i].ID,
			PackageName: components[i].Name,
			Version:     components[i].Version,
			PURLs:       purls,
			OccurrenceCount: 1, // Fallback assumption
			Occurrences: []OccurrenceRowV2{
				{
					SourceRefs: []string{components[i].ID},
					ObjectID:   components[i].BOMRef,
					FoundBy:    "fallback",
				},
			},
		})
	}
	return rows
}

func severityRank(raw string) int {
	switch raw {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	case "negligible":
		return 5
	default:
		return 99
	}
}
