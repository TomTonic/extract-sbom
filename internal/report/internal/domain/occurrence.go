// Package domain holds report-domain aggregation logic shared by renderers.
package domain

import (
	"fmt"
	"path"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ComponentOccurrence is one normalized, reportable view of an SBOM component.
type ComponentOccurrence struct {
	ObjectID       string
	ComponentType  cdx.ComponentType
	PackageName    string
	Version        string
	PURL           string
	CPE            string
	DeliveryPaths  []string
	EvidencePaths  []string
	EvidenceSource string
	FoundBy        string
}

// PackageOccurrenceGroup groups multiple occurrences that represent one package.
type PackageOccurrenceGroup struct {
	AnchorID    string
	PackageName string
	Version     string
	PURLs       []string
	Occurrences []ComponentOccurrence
}

// ComponentIndexStats tracks filtering and indexing counters.
type ComponentIndexStats struct {
	TotalComponents               int
	MissingDeliveryPath           int
	FilteredContainerNodes        int
	FilteredAbsolutePathNames     int
	FilteredLowValueFileArtifacts int
	DuplicateMerged               int
	IndexedComponents             int
	IndexedWithPURL               int
	IndexedWithoutPURL            int
	IndexedWithEvidencePath       int
	IndexedWithEvidenceSourceOnly int
	IndexedWithoutEvidence        int
}

// CollectComponentOccurrences extracts reportable component occurrences from
// the final BOM, applies quality filters, and computes index statistics.
func CollectComponentOccurrences(bom *cdx.BOM) ([]ComponentOccurrence, ComponentIndexStats) {
	stats := ComponentIndexStats{}
	if bom == nil || bom.Components == nil {
		return nil, stats
	}

	occurrences := make([]ComponentOccurrence, 0, len(*bom.Components))
	for i := range *bom.Components {
		comp := (*bom.Components)[i]
		stats.TotalComponents++
		deliveryPaths := componentPropertyValues(comp, "extract-sbom:delivery-path")
		if len(deliveryPaths) == 0 {
			stats.MissingDeliveryPath++
			continue
		}
		if len(componentPropertyValues(comp, "extract-sbom:extraction-status")) > 0 {
			stats.FilteredContainerNodes++
			continue
		}

		foundBy := firstComponentPropertyValue(comp, "syft:package:foundBy")
		if strings.HasPrefix(comp.Name, "/") {
			stats.FilteredAbsolutePathNames++
			continue
		}
		if isLowValueFileArtifact(comp, foundBy) {
			stats.FilteredLowValueFileArtifacts++
			continue
		}

		occurrences = append(occurrences, ComponentOccurrence{
			ObjectID:       comp.BOMRef,
			ComponentType:  comp.Type,
			PackageName:    comp.Name,
			Version:        comp.Version,
			PURL:           comp.PackageURL,
			CPE:            comp.CPE,
			DeliveryPaths:  deliveryPaths,
			EvidencePaths:  componentPropertyValues(comp, "extract-sbom:evidence-path"),
			EvidenceSource: firstComponentPropertyValue(comp, "extract-sbom:evidence-source"),
			FoundBy:        foundBy,
		})
	}

	occurrences = mergeDuplicateOccurrences(occurrences, &stats)

	sort.Slice(occurrences, func(i, j int) bool {
		return compareOccurrence(occurrences[i], occurrences[j]) < 0
	})
	stats.IndexedComponents = len(occurrences)
	for i := range occurrences {
		occ := occurrences[i]
		if occ.PURL != "" {
			stats.IndexedWithPURL++
		} else {
			stats.IndexedWithoutPURL++
		}
		switch {
		case len(occ.EvidencePaths) > 0:
			stats.IndexedWithEvidencePath++
		case occ.EvidenceSource != "":
			stats.IndexedWithEvidenceSourceOnly++
		default:
			stats.IndexedWithoutEvidence++
		}
	}

	return occurrences, stats
}

// BuildPackageOccurrenceGroups groups occurrences by package name/version and
// assigns deterministic package-level anchors.
func BuildPackageOccurrenceGroups(occurrences []ComponentOccurrence) []PackageOccurrenceGroup {
	if len(occurrences) == 0 {
		return nil
	}

	type groupKey struct {
		name    string
		version string
	}

	byKey := make(map[groupKey][]ComponentOccurrence)
	order := make([]groupKey, 0)
	for i := range occurrences {
		key := groupKey{name: occurrences[i].PackageName, version: occurrences[i].Version}
		if _, ok := byKey[key]; !ok {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], occurrences[i])
	}

	groups := make([]PackageOccurrenceGroup, 0, len(order))
	for _, key := range order {
		groupOccurrences := append([]ComponentOccurrence(nil), byKey[key]...)
		sort.Slice(groupOccurrences, func(i, j int) bool {
			return compareOccurrence(groupOccurrences[i], groupOccurrences[j]) < 0
		})
		groups = append(groups, PackageOccurrenceGroup{
			PackageName: key.name,
			Version:     key.version,
			PURLs:       collectDistinctPURLs(groupOccurrences),
			Occurrences: groupOccurrences,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		leftPrimary := ComponentOccurrence{}
		if len(groups[i].Occurrences) > 0 {
			leftPrimary = groups[i].Occurrences[0]
		}
		rightPrimary := ComponentOccurrence{}
		if len(groups[j].Occurrences) > 0 {
			rightPrimary = groups[j].Occurrences[0]
		}
		if cmp := compareOccurrence(leftPrimary, rightPrimary); cmp != 0 {
			return cmp < 0
		}
		if groups[i].PackageName != groups[j].PackageName {
			return groups[i].PackageName < groups[j].PackageName
		}
		if groups[i].Version != groups[j].Version {
			return groups[i].Version < groups[j].Version
		}
		return strings.Join(groups[i].PURLs, "|") < strings.Join(groups[j].PURLs, "|")
	})

	usedAnchors := make(map[string]int)
	for i := range groups {
		base := packageAnchorBase(groups[i].PackageName, groups[i].Version)
		count := usedAnchors[base]
		usedAnchors[base] = count + 1
		if count == 0 {
			groups[i].AnchorID = base
			continue
		}
		groups[i].AnchorID = fmt.Sprintf("%s-%d", base, count+1)
	}

	return groups
}

// OccurrenceQualityScore ranks evidence strength; this ranking should stay
// aligned with suppression link resolution.
func OccurrenceQualityScore(occ ComponentOccurrence) int {
	score := 0
	if occ.PURL != "" {
		score += 4
	}
	if occ.FoundBy != "" {
		score += 3
	}
	if occ.Version != "" {
		score += 2
	}
	if occ.PackageName != "" && !strings.Contains(occ.PackageName, "/") {
		score++
	}
	return score
}

func compareOccurrence(a, b ComponentOccurrence) int {
	aPrimary := firstString(a.DeliveryPaths)
	bPrimary := firstString(b.DeliveryPaths)
	if aPrimary != bPrimary {
		if aPrimary < bPrimary {
			return -1
		}
		return 1
	}
	aEvidence := firstString(a.EvidencePaths)
	bEvidence := firstString(b.EvidencePaths)
	if aEvidence != bEvidence {
		if aEvidence < bEvidence {
			return -1
		}
		return 1
	}
	if a.PackageName != b.PackageName {
		if a.PackageName < b.PackageName {
			return -1
		}
		return 1
	}
	if a.Version != b.Version {
		if a.Version < b.Version {
			return -1
		}
		return 1
	}
	if a.PURL != b.PURL {
		if a.PURL < b.PURL {
			return -1
		}
		return 1
	}
	if a.FoundBy != b.FoundBy {
		if a.FoundBy < b.FoundBy {
			return -1
		}
		return 1
	}
	if a.ObjectID < b.ObjectID {
		return -1
	}
	if a.ObjectID > b.ObjectID {
		return 1
	}
	return 0
}

func mergeDuplicateOccurrences(occurrences []ComponentOccurrence, stats *ComponentIndexStats) []ComponentOccurrence {
	if len(occurrences) < 2 {
		return occurrences
	}

	groups := make(map[string][]ComponentOccurrence)
	keys := make([]string, 0)
	for i := range occurrences {
		occ := occurrences[i]
		key := occurrenceLocusKey(occ)
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], occ)
	}
	sort.Strings(keys)

	merged := make([]ComponentOccurrence, 0, len(occurrences))
	for _, key := range keys {
		group := groups[key]
		if len(group) == 1 {
			merged = append(merged, group[0])
			continue
		}

		best := pickBestOccurrence(group)
		if shouldCollapseDuplicateGroup(group, best) {
			merged = append(merged, best)
			stats.DuplicateMerged += len(group) - 1
			continue
		}

		merged = append(merged, group...)
	}

	return merged
}

func occurrenceLocusKey(occ ComponentOccurrence) string {
	dp := append([]string(nil), occ.DeliveryPaths...)
	sort.Strings(dp)
	evidence := append([]string(nil), occ.EvidencePaths...)
	sort.Strings(evidence)
	return strings.Join(dp, "\x1e") + "\x00" + strings.Join(evidence, "\x1f")
}

func pickBestOccurrence(group []ComponentOccurrence) ComponentOccurrence {
	best := group[0]
	bestScore := OccurrenceQualityScore(best)
	for i := 1; i < len(group); i++ {
		score := OccurrenceQualityScore(group[i])
		if score > bestScore || (score == bestScore && compareOccurrence(group[i], best) < 0) {
			best = group[i]
			bestScore = score
		}
	}
	return best
}

func shouldCollapseDuplicateGroup(group []ComponentOccurrence, best ComponentOccurrence) bool {
	if OccurrenceQualityScore(best) < 4 {
		return false
	}

	for i := range group {
		occ := group[i]
		if occ.ObjectID == best.ObjectID {
			continue
		}
		if !isWeakArtifactOccurrence(occ) {
			return false
		}
	}

	return true
}

func isWeakArtifactOccurrence(occ ComponentOccurrence) bool {
	if occ.PURL != "" || occ.FoundBy != "" || occ.Version != "" {
		return false
	}
	if occ.PackageName == "" {
		return true
	}
	if strings.Contains(occ.PackageName, "/") {
		return true
	}

	base := path.Base(firstString(occ.DeliveryPaths))
	baseNoExt := strings.TrimSuffix(base, path.Ext(base))
	return strings.EqualFold(occ.PackageName, base) || strings.EqualFold(occ.PackageName, baseNoExt)
}

func isLowValueFileArtifact(comp cdx.Component, foundBy string) bool {
	if comp.Type != cdx.ComponentTypeFile {
		return false
	}
	return comp.PackageURL == "" && comp.Version == "" && foundBy == ""
}

func componentPropertyValues(comp cdx.Component, name string) []string {
	if comp.Properties == nil {
		return nil
	}

	values := make([]string, 0)
	seen := make(map[string]struct{})
	for _, prop := range *comp.Properties {
		if prop.Name != name || prop.Value == "" {
			continue
		}
		if _, ok := seen[prop.Value]; ok {
			continue
		}
		seen[prop.Value] = struct{}{}
		values = append(values, prop.Value)
	}
	if name == "extract-sbom:delivery-path" || name == "extract-sbom:evidence-path" {
		return leafMostLogicalPaths(values)
	}
	return values
}

func leafMostLogicalPaths(values []string) []string {
	if len(values) < 2 {
		return values
	}

	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		cleaned = append(cleaned, path.Clean(value))
	}
	sort.Strings(cleaned)

	kept := make([]string, 0, len(cleaned))
	for i, candidate := range cleaned {
		redundant := false
		for j, other := range cleaned {
			if i == j {
				continue
			}
			if isAncestorLogicalPath(candidate, other) {
				redundant = true
				break
			}
		}
		if !redundant {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func isAncestorLogicalPath(ancestor, descendant string) bool {
	ancestor = strings.TrimSuffix(path.Clean(ancestor), "/")
	descendant = path.Clean(descendant)
	if ancestor == "" || ancestor == "." || ancestor == descendant {
		return false
	}
	return strings.HasPrefix(descendant, ancestor+"/")
}

func firstComponentPropertyValue(comp cdx.Component, name string) string {
	values := componentPropertyValues(comp, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func collectDistinctPURLs(occurrences []ComponentOccurrence) []string {
	if len(occurrences) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(occurrences))
	purls := make([]string, 0, len(occurrences))
	for i := range occurrences {
		if occurrences[i].PURL == "" {
			continue
		}
		if _, ok := seen[occurrences[i].PURL]; ok {
			continue
		}
		seen[occurrences[i].PURL] = struct{}{}
		purls = append(purls, occurrences[i].PURL)
	}
	sort.Strings(purls)
	return purls
}

func packageAnchorBase(name string, version string) string {
	base := "package"
	if slug := anchorSlugPart(name); slug != "" {
		base += "-" + slug
	}
	if slug := anchorSlugPart(version); slug != "" {
		base += "-" + slug
	}
	return strings.TrimRight(base, "-")
}

func anchorSlugPart(value string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
