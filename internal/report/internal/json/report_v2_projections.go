package json

import (
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/extract"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// buildProjectionsV2 prepares renderer-facing views from entities and raw data.
func buildProjectionsV2(data ReportData, entities entitiesV2, index entityIndexV2) projectionsV2 {
	occurrences, occurrenceStats := domain.CollectComponentOccurrences(data.BOM)
	packageGroups := domain.BuildPackageOccurrenceGroups(occurrences)

	componentIndexRows := buildComponentIndexProjectionRows(packageGroups, index)
	if len(componentIndexRows) == 0 {
		componentIndexRows = buildComponentFallbackProjectionRows(entities.Components)
	}

	return projectionsV2{
		Summary: projectionSummaryV2{
			Nodes:                        len(entities.Nodes),
			ScanTasks:                    len(entities.ScanTasks),
			Components:                   len(entities.Components),
			PackageGroups:                len(entities.PackageGroups),
			Vulnerabilities:              len(entities.Vulnerabilities),
			Suppressions:                 len(entities.Suppressions),
			PolicyDecisions:              len(entities.PolicyDecisions),
			Issues:                       len(entities.Issues),
			ComponentIndexStats: componentIndexStatsV2{
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
		},
		ExtractionLog:   buildExtractionProjectionRows(data.Tree, index),
		Vulnerabilities: buildVulnerabilityProjectionRows(data.Vulnerabilities, packageGroups, index),
		Issues:          buildIssueProjectionRows(entities),
		ComponentIndex:  componentIndexRows,
	}
}

// buildExtractionProjectionRows flattens extraction tree data into ordered rows.
func buildExtractionProjectionRows(tree *extract.ExtractionNode, index entityIndexV2) []extractionLogRowV2 {
	rows := make([]extractionLogRowV2, 0)
	var walk func(node *extract.ExtractionNode, depth int)
	walk = func(node *extract.ExtractionNode, depth int) {
		if node == nil {
			return
		}
		row := extractionLogRowV2{
			SourceRefs: sourceRefsOrNil(index.nodeByPath[node.Path]),
			Path:       node.Path,
			Status:     node.Status.String(),
			Format:     node.Format.Format.String(),
			Tool:       node.Tool,
			Detail:     node.StatusDetail,
			Depth:      depth,
		}
		rows = append(rows, row)
		for _, child := range node.Children {
			walk(child, depth+1)
		}
	}
	walk(tree, 0)
	return rows
}

// buildVulnerabilityProjectionRows builds highly grouped and enriched vulnerability rows.
func buildVulnerabilityProjectionRows(v *vulnscan.Result, packageGroups []domain.PackageOccurrenceGroup, index entityIndexV2) []vulnerabilityRowV2 {
	if v == nil || len(v.MatchesByBOMRef) == 0 {
		return []vulnerabilityRowV2{}
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

	rows := make([]vulnerabilityRowV2, 0)
	seen := map[string]struct{}{}
	for compID, matches := range v.MatchesByBOMRef {
		occ := byID[compID]
		packageName := strings.TrimSpace(occ.PackageName)
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

			rows = append(rows, vulnerabilityRowV2{
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
func buildIssueProjectionRows(entities entitiesV2) []issueRowV2 {
	rows := make([]issueRowV2, 0, len(entities.Issues))
	for i := range entities.Issues {
		rows = append(rows, issueRowV2{
			SourceRefs: []string{entities.Issues[i].ID},
			Stage:      entities.Issues[i].Stage,
			Message:    entities.Issues[i].Message,
		})
	}
	return rows
}

// buildComponentIndexProjectionRows maps domain occurrence grouping into rows.
func buildComponentIndexProjectionRows(groups []domain.PackageOccurrenceGroup, index entityIndexV2) []packageOccurrenceGroupV2 {
	rows := make([]packageOccurrenceGroupV2, 0, len(groups))
	for i := range groups {
		groupRefs := make([]string, 0, len(groups[i].Occurrences))
		occRows := make([]occurrenceRowV2, 0, len(groups[i].Occurrences))

		for j := range groups[i].Occurrences {
			compID := index.componentByRef[groups[i].Occurrences[j].ObjectID]
			if compID != "" {
				groupRefs = append(groupRefs, compID)
			}
			occRows = append(occRows, occurrenceRowV2{
				SourceRefs: sourceRefsOrNil(compID),

				ObjectID:       groups[i].Occurrences[j].ObjectID,
				DeliveryPaths:  groups[i].Occurrences[j].DeliveryPaths,
				EvidencePaths:  groups[i].Occurrences[j].EvidencePaths,
				EvidenceSource: groups[i].Occurrences[j].EvidenceSource,
				FoundBy:        groups[i].Occurrences[j].FoundBy,
			})
		}
		groupRefs = domain.SortedUniqueStrings(groupRefs)
		rows = append(rows, packageOccurrenceGroupV2{
			SourceRefs:      domain.NormalizeProjectionRefs(groupRefs),
			AnchorID:        groups[i].AnchorID,
			PackageName:     groups[i].PackageName,
			Version:         groups[i].Version,
			PURLs:           groups[i].PURLs,
			OccurrenceCount: len(groups[i].Occurrences),
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
func buildComponentFallbackProjectionRows(components []componentEntityV2) []packageOccurrenceGroupV2 {
	rows := make([]packageOccurrenceGroupV2, 0, len(components))
	for i := range components {
		purls := []string{}
		if components[i].PURL != "" {
			purls = append(purls, components[i].PURL)
		}
		rows = append(rows, packageOccurrenceGroupV2{
			SourceRefs:  []string{components[i].ID},
			AnchorID:    components[i].ID,
			PackageName: components[i].Name,
			Version:     components[i].Version,
			PURLs:       purls,
			OccurrenceCount: 1, // Fallback assumption
			Occurrences: []occurrenceRowV2{
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
