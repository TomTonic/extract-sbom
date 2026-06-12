package json

import (
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

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

	sortVulnerabilityRows(rows)
	return rows
}

// sortVulnerabilityRows orders rows by descending risk, then KEV, EPSS percentile,
// EPSS, severity rank, and finally name/id/key for deterministic output.
func sortVulnerabilityRows(rows []VulnerabilityRowV2) {
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

// buildComponentFallbackProjectionRows provides a projection when occurrence data is unavailable.
func buildComponentFallbackProjectionRows(components []componentEntityV2) []PackageOccurrenceGroupV2 {
	rows := make([]PackageOccurrenceGroupV2, 0, len(components))
	for i := range components {
		purls := []string{}
		if components[i].PURL != "" {
			purls = append(purls, components[i].PURL)
		}
		rows = append(rows, PackageOccurrenceGroupV2{
			SourceRefs:      []string{components[i].ID},
			AnchorID:        components[i].ID,
			PackageName:     components[i].Name,
			Version:         components[i].Version,
			PURLs:           purls,
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
