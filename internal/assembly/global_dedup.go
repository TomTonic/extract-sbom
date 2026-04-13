package assembly

import (
	"path"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// deduplicateGlobalComponents performs cross-node deduplication on the final
// assembled component list. Components with the same PURL are collapsed into
// a single entry regardless of delivery path. The surviving component
// inherits all unique leaf-most delivery-path and evidence-path properties
// from the suppressed entries, and redundant ancestor container paths are
// dropped. Dependency graph references are rewritten so no dangling BOMRefs
// remain.
func deduplicateGlobalComponents(components []cdx.Component, dependencies []cdx.Dependency) ([]cdx.Component, []SuppressionRecord) {
	groups := make(map[string][]int)
	var keyOrder []string
	for i := range components {
		comp := components[i]
		purl := comp.PackageURL
		if purl == "" {
			continue
		}
		if comp.Type == cdx.ComponentTypeFile {
			continue
		}
		if _, exists := groups[purl]; !exists {
			keyOrder = append(keyOrder, purl)
		}
		groups[purl] = append(groups[purl], i)
	}

	suppress := make(map[int]struct{})
	refRewrite := make(map[string]string)
	var suppressions []SuppressionRecord

	for _, purl := range keyOrder {
		idxs := groups[purl]
		if len(idxs) < 2 {
			continue
		}

		bestIdx := idxs[0]
		for _, idx := range idxs[1:] {
			if globalComponentBetter(components[idx], components[bestIdx]) {
				bestIdx = idx
			}
		}

		mergedProps := collectMergedProperties(components, idxs)

		best := &components[bestIdx]
		replaceMultiValueProperties(best, mergedProps)

		for _, idx := range idxs {
			if idx == bestIdx {
				continue
			}
			suppress[idx] = struct{}{}
			refRewrite[components[idx].BOMRef] = best.BOMRef
			dp := componentPropertyValue(components[idx], "extract-sbom:delivery-path")
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionPURLDuplicate,
				Component:    components[idx],
				FoundBy:      firstComponentFoundByPropertyValue(components[idx]),
				DeliveryPath: dp,
				KeptName:     best.Name,
				KeptFoundBy:  firstComponentFoundByPropertyValue(*best),
			})
		}
	}

	if len(suppress) == 0 {
		return components, nil
	}

	filtered := make([]cdx.Component, 0, len(components)-len(suppress))
	for i := range components {
		if _, ok := suppress[i]; !ok {
			filtered = append(filtered, components[i])
		}
	}

	for i := range dependencies {
		if newRef, ok := refRewrite[dependencies[i].Ref]; ok {
			dependencies[i].Ref = newRef
		}
		if dependencies[i].Dependencies != nil {
			rewritten := make([]string, 0, len(*dependencies[i].Dependencies))
			seen := make(map[string]struct{})
			for _, ref := range *dependencies[i].Dependencies {
				if newRef, ok := refRewrite[ref]; ok {
					ref = newRef
				}
				if _, dup := seen[ref]; !dup {
					seen[ref] = struct{}{}
					rewritten = append(rewritten, ref)
				}
			}
			*dependencies[i].Dependencies = rewritten
		}
	}

	return filtered, suppressions
}

// collectMergedProperties gathers all unique values for the merged property
// names across the given component indices. For logical path properties it
// keeps only leaf-most values so an enclosing archive path does not survive
// alongside a more specific nested artifact path.
func collectMergedProperties(components []cdx.Component, idxs []int) map[string][]string {
	sets := make(map[string]map[string]struct{}, len(mergedPropertyNames))
	for _, name := range mergedPropertyNames {
		sets[name] = make(map[string]struct{})
	}

	for _, idx := range idxs {
		comp := components[idx]
		if comp.Properties == nil {
			continue
		}
		for _, prop := range *comp.Properties {
			if s, ok := sets[prop.Name]; ok && prop.Value != "" {
				s[prop.Value] = struct{}{}
			}
		}
	}

	result := make(map[string][]string, len(mergedPropertyNames))
	for _, name := range mergedPropertyNames {
		vals := make([]string, 0, len(sets[name]))
		for v := range sets[name] {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		vals = pruneMergedPathValues(name, vals)
		if len(vals) > 0 {
			result[name] = vals
		}
	}
	return result
}

// pruneMergedPathValues applies path-specific pruning rules for merged
// multi-value properties.
func pruneMergedPathValues(name string, values []string) []string {
	switch name {
	case "extract-sbom:delivery-path", "extract-sbom:evidence-path":
		return leafMostLogicalPaths(values)
	default:
		return values
	}
}

// leafMostLogicalPaths removes ancestor paths when a more specific descendant
// path from the same logical lineage is present.
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
	if len(cleaned) < 2 {
		return cleaned
	}

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

// isAncestorLogicalPath reports whether ancestor is a strict logical path
// ancestor of descendant.
func isAncestorLogicalPath(ancestor, descendant string) bool {
	ancestor = strings.TrimSuffix(path.Clean(ancestor), "/")
	descendant = path.Clean(descendant)
	if ancestor == "" || ancestor == "." || ancestor == descendant {
		return false
	}
	return strings.HasPrefix(descendant, ancestor+"/")
}

// replaceMultiValueProperties replaces the merged property names on comp with
// the union of values from the whole PURL group, preserving all other props.
func replaceMultiValueProperties(comp *cdx.Component, merged map[string][]string) {
	isReplaced := make(map[string]struct{}, len(mergedPropertyNames))
	for _, name := range mergedPropertyNames {
		isReplaced[name] = struct{}{}
	}

	var kept []cdx.Property
	if comp.Properties != nil {
		kept = make([]cdx.Property, 0, len(*comp.Properties))
		for _, prop := range *comp.Properties {
			if _, ok := isReplaced[prop.Name]; !ok {
				kept = append(kept, prop)
			}
		}
	}
	for _, name := range mergedPropertyNames {
		for _, val := range merged[name] {
			kept = append(kept, cdx.Property{Name: name, Value: val})
		}
	}
	kept = uniqueSortedProperties(kept)
	comp.Properties = &kept
}

// globalComponentBetter returns true if a is a better representative than b
// for a global PURL group. Prefers more evidence, then higher quality score,
// then earlier BOMRef for determinism.
func globalComponentBetter(a, b cdx.Component) bool {
	aEvidence := countPropertyValues(a, "extract-sbom:evidence-path")
	bEvidence := countPropertyValues(b, "extract-sbom:evidence-path")
	if aEvidence != bEvidence {
		return aEvidence > bEvidence
	}
	aScore := globalQualityScore(a)
	bScore := globalQualityScore(b)
	if aScore != bScore {
		return aScore > bScore
	}
	return a.BOMRef < b.BOMRef
}

// globalQualityScore ranks globally deduplicated candidates by identification
// strength and metadata richness.
func globalQualityScore(comp cdx.Component) int {
	score := 0
	if comp.PackageURL != "" {
		score += 4
	}
	foundBy := firstComponentFoundByPropertyValue(comp)
	if foundBy != "" {
		score += 3
	}
	if comp.Version != "" {
		score += 2
	}
	if comp.Name != "" {
		score++
	}
	return score
}

// componentPropertyValue returns the first property value for a given name.
func componentPropertyValue(comp cdx.Component, name string) string {
	if comp.Properties == nil {
		return ""
	}
	for _, prop := range *comp.Properties {
		if prop.Name == name {
			return prop.Value
		}
	}
	return ""
}

// countPropertyValues counts non-empty occurrences of a property name.
func countPropertyValues(comp cdx.Component, name string) int {
	if comp.Properties == nil {
		return 0
	}
	count := 0
	for _, prop := range *comp.Properties {
		if prop.Name == name && prop.Value != "" {
			count++
		}
	}
	return count
}
