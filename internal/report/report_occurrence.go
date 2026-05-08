package report

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// writeScanNoPackageIdentitiesSubsection writes scan targets where Syft
// returned no component identities, which is a key coverage signal.
func writeScanNoPackageIdentitiesSubsection(w io.Writer, scn scanStats, t translations) {
	writeAnchoredHeading(w, 3, t.scanNoPackageIDsSection, anchorScanNoPackageIDs)
	if scn.NoComponentTasks == 0 {
		fmt.Fprintf(w, "- %s\n", t.noScanNoPackageIDs)
		return
	}

	paths := uniqueSortedPaths(scn.NoComponentPaths)
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.scanNoPackageIDsLead, len(paths)))
	const maxRows = 300
	for i, p := range paths {
		if i >= maxRows {
			fmt.Fprintf(w, "- ... (%s)\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, len(paths)-maxRows))
			break
		}
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

// uniqueSortedPaths removes empty/duplicate paths and returns a sorted copy.
func uniqueSortedPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}
	sort.Strings(unique)
	return unique
}

// writeExtensionFilterSection documents which file extensions were configured
// to be skipped and which logical paths were affected.
func writeExtensionFilterSection(w io.Writer, data ReportData, ext extractionStats, t translations) {
	fmt.Fprintln(w, t.extensionFilterLead)
	fmt.Fprintln(w)

	if len(data.Config.SkipExtensions) > 0 {
		extensions := make([]string, len(data.Config.SkipExtensions))
		copy(extensions, data.Config.SkipExtensions)
		sort.Strings(extensions)
		quoted := make([]string, len(extensions))
		for i, e := range extensions {
			quoted[i] = "`" + e + "`"
		}
		fmt.Fprintf(w, "**%s:** %s\n\n", t.extensionFilterExtensionsLabel, strings.Join(quoted, ", "))
	} else {
		fmt.Fprintln(w, t.noExtensionFilteredFiles)
		return
	}

	fmt.Fprintf(w, "**%s (%d):**\n\n", t.extensionFilterSkippedLabel, ext.ExtensionFiltered)
	if ext.ExtensionFiltered == 0 {
		fmt.Fprintf(w, "- %s\n", t.noExtensionFilteredFiles)
		return
	}

	paths := make([]string, len(ext.ExtensionFilteredPaths))
	copy(paths, ext.ExtensionFilteredPaths)
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

// writeComponentOccurrenceIndex renders the appendix index grouped by package
// (name+version) and lists concrete component occurrences underneath.
func writeComponentOccurrenceIndex(w io.Writer, occurrences []componentOccurrence, idx componentIndexStats, v *vulnscan.Result, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentIndexLead)

	if len(occurrences) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noIndexedComponents)
		return
	}
	groups := buildPackageOccurrenceGroups(occurrences)

	// Split package groups into with-PURL and without-PURL sections.
	var withPURL, withoutPURL []packageOccurrenceGroup
	for i := range groups {
		if len(groups[i].PURLs) > 0 {
			withPURL = append(withPURL, groups[i])
		} else {
			withoutPURL = append(withoutPURL, groups[i])
		}
	}

	// Write with-PURL subsection.
	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.componentIndexWithPURLSubsection, idx.IndexedWithPURL), anchorComponentsWithPURL)
	if len(withPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withPURL {
			writePackageGroupEntry(w, withPURL[i], v, t)
		}
	}

	// Write without-PURL subsection.
	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.componentIndexWithoutPURLSubsection, idx.IndexedWithoutPURL), anchorComponentsWithoutPURL)
	if len(withoutPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withoutPURL {
			writePackageGroupEntry(w, withoutPURL[i], v, t)
		}
	}
}

// writePackageGroupEntry renders one package group and its nested occurrences.
func writePackageGroupEntry(w io.Writer, group packageOccurrenceGroup, v *vulnscan.Result, t translations) {
	title := strings.TrimSpace(group.PackageName)
	if title == "" {
		title = t.noneValue
	}
	if strings.TrimSpace(group.Version) != "" {
		title += " " + group.Version
	}
	writeAnchoredHeading(w, 4, title, group.AnchorID)
	fmt.Fprintf(w, "- %s: `%s`\n", t.packageName, valueOrDash(group.PackageName))
	fmt.Fprintf(w, "- %s: `%s`\n", t.version, valueOrDash(group.Version))
	if len(group.PURLs) == 1 {
		fmt.Fprintf(w, "- %s: `%s`\n", t.purl, group.PURLs[0])
	} else if len(group.PURLs) > 1 {
		for _, p := range group.PURLs {
			fmt.Fprintf(w, "- %s: `%s`\n", t.purlsLabel, p)
		}
	}

	sharedVulnLines, perOccurrenceVulnLines := resolvePackageVulnerabilityBlocks(group, v, t)

	for i := range group.Occurrences {
		writeOccurrenceListEntry(w, group.Occurrences[i], t, perOccurrenceVulnLines[group.Occurrences[i].ObjectID])
	}
	writeVulnerabilityLines(w, sharedVulnLines, "")
	fmt.Fprintln(w)
}

// writeOccurrenceListEntry renders one normalized occurrence as nested list
// item inside a package-group entry.
func writeOccurrenceListEntry(w io.Writer, occ componentOccurrence, t translations, vulnLines []string) {
	fmt.Fprintf(w, "- %s: <a id=\"%s\"></a>`%s`\n", t.componentIDLabel, occurrenceAnchorID(occ.ObjectID), occ.ObjectID)
	for _, dp := range occ.DeliveryPaths {
		fmt.Fprintf(w, "  - %s: `%s`\n", t.deliveryPath, dp)
	}
	switch {
	case len(occ.EvidencePaths) > 0:
		for _, evidencePath := range occ.EvidencePaths {
			fmt.Fprintf(w, "  - %s: `%s`\n", t.evidencePath, evidencePath)
		}
	case occ.EvidenceSource != "":
		fmt.Fprintf(w, "  - %s: `%s`\n", t.evidencePath, occ.EvidenceSource)
	default:
		fmt.Fprintf(w, "  - %s: %s\n", t.evidencePath, t.noEvidenceRecorded)
	}
	if occ.FoundBy != "" {
		fmt.Fprintf(w, "  - %s: `%s`\n", t.foundBy, occ.FoundBy)
	}
	writeVulnerabilityLines(w, vulnLines, "  ")
}

func writeVulnerabilityLines(w io.Writer, lines []string, indent string) {
	for _, line := range lines {
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}
}

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

// collectComponentOccurrences extracts reportable component occurrences from
// the final BOM, applies quality filters, and computes index statistics.
func collectComponentOccurrences(bom *cdx.BOM) ([]componentOccurrence, componentIndexStats) {
	stats := componentIndexStats{}
	if bom == nil || bom.Components == nil {
		return nil, stats
	}

	occurrences := make([]componentOccurrence, 0, len(*bom.Components))
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

		occurrences = append(occurrences, componentOccurrence{
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

// compareOccurrence defines deterministic ordering for occurrence output.
func compareOccurrence(a, b componentOccurrence) int {
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

// mergeDuplicateOccurrences groups occurrences by logical locus and retains
// the strongest representative when duplicates are safely collapsible.
func mergeDuplicateOccurrences(occurrences []componentOccurrence, stats *componentIndexStats) []componentOccurrence {
	if len(occurrences) < 2 {
		return occurrences
	}

	groups := make(map[string][]componentOccurrence)
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

	merged := make([]componentOccurrence, 0, len(occurrences))
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

// occurrenceLocusKey builds the grouping key used for duplicate detection.
func occurrenceLocusKey(occ componentOccurrence) string {
	dp := append([]string(nil), occ.DeliveryPaths...)
	sort.Strings(dp)
	evidence := append([]string(nil), occ.EvidencePaths...)
	sort.Strings(evidence)
	return strings.Join(dp, "\x1e") + "\x00" + strings.Join(evidence, "\x1f")
}

// pickBestOccurrence selects the highest-quality representative in a group.
func pickBestOccurrence(group []componentOccurrence) componentOccurrence {
	best := group[0]
	bestScore := occurrenceQualityScore(best)
	for i := 1; i < len(group); i++ {
		score := occurrenceQualityScore(group[i])
		if score > bestScore || (score == bestScore && compareOccurrence(group[i], best) < 0) {
			best = group[i]
			bestScore = score
		}
	}
	return best
}

// occurrenceQualityScore ranks evidence strength; this ranking should stay
// aligned with suppressionLinkCandidateScore.
func occurrenceQualityScore(occ componentOccurrence) int {
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

// shouldCollapseDuplicateGroup decides whether lower-value duplicates can be
// dropped without losing meaningful provenance.
func shouldCollapseDuplicateGroup(group []componentOccurrence, best componentOccurrence) bool {
	if occurrenceQualityScore(best) < 4 {
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

// isWeakArtifactOccurrence classifies minimal file-artifact records that can
// be collapsed when a stronger package-level record exists for the same locus.
func isWeakArtifactOccurrence(occ componentOccurrence) bool {
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

// isLowValueFileArtifact returns true for file components that carry no package
// identity metadata and add little audit value.
func isLowValueFileArtifact(comp cdx.Component, foundBy string) bool {
	if comp.Type != cdx.ComponentTypeFile {
		return false
	}
	return comp.PackageURL == "" && comp.Version == "" && foundBy == ""
}

// componentPropertyValues collects unique property values for one key and
// normalizes logical path properties to leaf-most entries.
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

// leafMostLogicalPaths removes ancestor paths when a deeper descendant path is
// also present, preserving the most specific provenance pointers.
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

// isAncestorLogicalPath reports whether ancestor is a proper logical-path
// ancestor of descendant.
func isAncestorLogicalPath(ancestor, descendant string) bool {
	ancestor = strings.TrimSuffix(path.Clean(ancestor), "/")
	descendant = path.Clean(descendant)
	if ancestor == "" || ancestor == "." || ancestor == descendant {
		return false
	}
	return strings.HasPrefix(descendant, ancestor+"/")
}

// firstComponentPropertyValue returns the first normalized value for a BOM
// property key.
func firstComponentPropertyValue(comp cdx.Component, name string) string {
	values := componentPropertyValues(comp, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// firstString returns the first element or an empty string.
func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
