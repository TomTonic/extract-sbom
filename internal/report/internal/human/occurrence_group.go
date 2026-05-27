package human

import (
	"fmt"
	"sort"
	"strings"
)

// buildPackageOccurrenceGroups groups occurrences by package name/version and
// assigns deterministic package-level anchors.
func buildPackageOccurrenceGroups(occurrences []componentOccurrence) []packageOccurrenceGroup {
	if len(occurrences) == 0 {
		return nil
	}

	type groupKey struct {
		name    string
		version string
	}

	byKey := make(map[groupKey][]componentOccurrence)
	order := make([]groupKey, 0)
	for i := range occurrences {
		key := groupKey{name: occurrences[i].PackageName, version: occurrences[i].Version}
		if _, ok := byKey[key]; !ok {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], occurrences[i])
	}

	groups := make([]packageOccurrenceGroup, 0, len(order))
	for _, key := range order {
		groupOccurrences := append([]componentOccurrence(nil), byKey[key]...)
		sort.Slice(groupOccurrences, func(i, j int) bool {
			return compareOccurrence(groupOccurrences[i], groupOccurrences[j]) < 0
		})
		groups = append(groups, packageOccurrenceGroup{
			PackageName: key.name,
			Version:     key.version,
			PURLs:       collectDistinctPURLs(groupOccurrences),
			Occurrences: groupOccurrences,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		leftPrimary := componentOccurrence{}
		if len(groups[i].Occurrences) > 0 {
			leftPrimary = groups[i].Occurrences[0]
		}
		rightPrimary := componentOccurrence{}
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

func collectDistinctPURLs(occurrences []componentOccurrence) []string {
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

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
