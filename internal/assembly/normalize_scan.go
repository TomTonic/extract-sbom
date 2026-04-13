package assembly

import (
	"path"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// isFileCatalogerArtifact returns true for Syft file-cataloger entries that
// represent the file itself rather than an identified package. These have
// type=file and an absolute filesystem path (the temp extraction directory)
// as the component name. Filtering them out avoids temp-path leaks and
// duplicates with the properly-identified library-type entry.
func isFileCatalogerArtifact(comp cdx.Component) bool {
	return comp.Type == cdx.ComponentTypeFile && strings.HasPrefix(comp.Name, "/")
}

// syftLocationPath extracts the syft:location:0:path property from a
// component. This path indicates where Syft found the file within the
// scanned directory and can be used to refine the delivery-path.
func syftLocationPath(comp cdx.Component) string {
	if comp.Properties == nil {
		return ""
	}
	for _, prop := range *comp.Properties {
		if prop.Name == "syft:location:0:path" {
			return prop.Value
		}
	}
	return ""
}

// componentDeliveryPath resolves the best logical delivery path for a scanned
// component. For extracted-directory scans, syft:location refines the node path
// to the nearest concrete artifact location.
func componentDeliveryPath(node *extract.ExtractionNode, comp cdx.Component) string {
	if node == nil {
		return ""
	}

	deliveryPath := node.Path
	if node.Status == extract.StatusExtracted {
		if loc := syftLocationPath(comp); loc != "" {
			deliveryPath = node.Path + "/" + strings.TrimPrefix(loc, "/")
		}
	}
	return deliveryPath
}

// normalizeScanComponents filters low-value artifacts, enriches provenance, and
// applies local deduplication for one scan result.
//
// The returned candidates are sorted deterministically for stable BOMRef
// assignment and reproducible SBOM output.
func normalizeScanComponents(node *extract.ExtractionNode, sr *scan.ScanResult) ([]scanComponentCandidate, []SuppressionRecord) {
	if node == nil || sr == nil || sr.BOM == nil || sr.BOM.Components == nil {
		return nil, nil
	}

	var suppressions []SuppressionRecord
	candidates := make([]scanComponentCandidate, 0, len(*sr.BOM.Components))
	for i := range *sr.BOM.Components {
		comp := (*sr.BOM.Components)[i]
		deliveryPath := componentDeliveryPath(node, comp)
		foundBy := firstComponentFoundByPropertyValue(comp)
		if isFileCatalogerArtifact(comp) {
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionFSArtifact,
				Component:    comp,
				FoundBy:      foundBy,
				DeliveryPath: deliveryPath,
			})
			continue
		}

		if isLowValueFileArtifact(comp, foundBy) {
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionLowValueFile,
				Component:    comp,
				FoundBy:      foundBy,
				DeliveryPath: deliveryPath,
			})
			continue
		}

		rawEvidence := sr.EvidencePaths[comp.BOMRef]
		evidence := make([]string, 0, len(rawEvidence))
		for _, ep := range rawEvidence {
			// Skip evidence that equals the delivery path; it adds no information.
			if ep != deliveryPath {
				evidence = append(evidence, ep)
			}
		}
		sort.Strings(evidence)

		candidates = append(candidates, scanComponentCandidate{
			component:    comp,
			deliveryPath: deliveryPath,
			evidence:     evidence,
			foundBy:      foundBy,
			order:        i,
		})
	}

	merged, mergeSuppressed := mergeDuplicateScanCandidates(candidates)
	suppressions = append(suppressions, mergeSuppressed...)

	merged, purlSuppressed := mergePURLDuplicateScanCandidates(merged)
	suppressions = append(suppressions, purlSuppressed...)

	sort.Slice(merged, func(i, j int) bool {
		return compareScanCandidates(merged[i], merged[j]) < 0
	})

	return merged, suppressions
}

// mergeDuplicateScanCandidates groups candidates by delivery/evidence locus and
// suppresses weak placeholders when a clearly better entry exists.
func mergeDuplicateScanCandidates(candidates []scanComponentCandidate) ([]scanComponentCandidate, []SuppressionRecord) {
	if len(candidates) < 2 {
		return candidates, nil
	}

	groups := make(map[string][]scanComponentCandidate)
	keys := make([]string, 0)
	for i := range candidates {
		key := scanCandidateLocusKey(candidates[i])
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], candidates[i])
	}
	sort.Strings(keys)

	var suppressions []SuppressionRecord
	merged := make([]scanComponentCandidate, 0, len(candidates))
	for _, key := range keys {
		group := groups[key]
		if len(group) == 1 {
			merged = append(merged, group[0])
			continue
		}

		best := pickBestScanCandidate(group)
		if shouldCollapseScanCandidateGroup(group, best) {
			merged = append(merged, best)
			for i := range group {
				if group[i].component.BOMRef == best.component.BOMRef && group[i].order == best.order {
					continue
				}
				suppressions = append(suppressions, SuppressionRecord{
					Reason:       SuppressionWeakDuplicate,
					Component:    group[i].component,
					FoundBy:      group[i].foundBy,
					DeliveryPath: group[i].deliveryPath,
					KeptName:     best.component.Name,
					KeptFoundBy:  best.foundBy,
				})
			}
			continue
		}

		merged = append(merged, group...)
	}

	return merged, suppressions
}

// scanCandidateLocusKey identifies the physical detection locus used for local
// duplicate grouping.
func scanCandidateLocusKey(candidate scanComponentCandidate) string {
	return candidate.deliveryPath + "\x00" + strings.Join(candidate.evidence, "\x1f")
}

// mergePURLDuplicateScanCandidates performs a second-pass deduplication that
// collapses candidates with the same PURL and delivery path regardless of
// evidence differences. Syft occasionally emits two entries for the same
// physical JAR: one cataloged from the filename pattern (no evidence) and
// one from its MANIFEST.MF (with evidence). Both carry the same PURL and
// delivery path but different evidence sets; the first pass cannot catch them
// because its locus key includes evidence. This pass groups by
// (PURL, deliveryPath) and keeps the candidate with the most evidence.
func mergePURLDuplicateScanCandidates(candidates []scanComponentCandidate) ([]scanComponentCandidate, []SuppressionRecord) {
	if len(candidates) < 2 {
		return candidates, nil
	}

	type purlLocusKey struct{ purl, deliveryPath string }
	groups := make(map[purlLocusKey][]int)
	var keyOrder []purlLocusKey

	for i := range candidates {
		if candidates[i].component.PackageURL == "" {
			continue
		}
		k := purlLocusKey{candidates[i].component.PackageURL, candidates[i].deliveryPath}
		if _, exists := groups[k]; !exists {
			keyOrder = append(keyOrder, k)
		}
		groups[k] = append(groups[k], i)
	}

	suppress := make(map[int]struct{})
	var suppressions []SuppressionRecord

	for _, k := range keyOrder {
		idxs := groups[k]
		if len(idxs) < 2 {
			continue
		}

		// Pick the candidate with the most evidence; break ties by quality
		// score, then order.
		bestIdx := idxs[0]
		for _, idx := range idxs[1:] {
			c := candidates[idx]
			b := candidates[bestIdx]
			if len(c.evidence) > len(b.evidence) {
				bestIdx = idx
			} else if len(c.evidence) == len(b.evidence) {
				cs := scanCandidateQualityScore(c)
				bs := scanCandidateQualityScore(b)
				if cs > bs || (cs == bs && c.order < b.order) {
					bestIdx = idx
				}
			}
		}

		best := candidates[bestIdx]
		for _, idx := range idxs {
			if idx == bestIdx {
				continue
			}
			suppress[idx] = struct{}{}
			suppressions = append(suppressions, SuppressionRecord{
				Reason:       SuppressionPURLDuplicate,
				Component:    candidates[idx].component,
				FoundBy:      candidates[idx].foundBy,
				DeliveryPath: candidates[idx].deliveryPath,
				KeptName:     best.component.Name,
				KeptFoundBy:  best.foundBy,
			})
		}
	}

	if len(suppress) == 0 {
		return candidates, suppressions
	}

	merged := make([]scanComponentCandidate, 0, len(candidates)-len(suppress))
	for i := range candidates {
		if _, ok := suppress[i]; !ok {
			merged = append(merged, candidates[i])
		}
	}
	return merged, suppressions
}

// pickBestScanCandidate chooses the strongest representative from one local
// duplicate group using quality score and deterministic tie-breakers.
func pickBestScanCandidate(group []scanComponentCandidate) scanComponentCandidate {
	best := group[0]
	bestScore := scanCandidateQualityScore(best)
	for i := 1; i < len(group); i++ {
		score := scanCandidateQualityScore(group[i])
		if score > bestScore || (score == bestScore && compareScanCandidates(group[i], best) < 0) {
			best = group[i]
			bestScore = score
		}
	}
	return best
}

// compareScanCandidates defines a total ordering for candidates used in
// deterministic output and tie-breaking.
func compareScanCandidates(a, b scanComponentCandidate) int {
	if a.deliveryPath != b.deliveryPath {
		if a.deliveryPath < b.deliveryPath {
			return -1
		}
		return 1
	}
	aEvidence := ""
	if len(a.evidence) > 0 {
		aEvidence = a.evidence[0]
	}
	bEvidence := ""
	if len(b.evidence) > 0 {
		bEvidence = b.evidence[0]
	}
	if aEvidence != bEvidence {
		if aEvidence < bEvidence {
			return -1
		}
		return 1
	}
	if a.component.Name != b.component.Name {
		if a.component.Name < b.component.Name {
			return -1
		}
		return 1
	}
	if a.component.Version != b.component.Version {
		if a.component.Version < b.component.Version {
			return -1
		}
		return 1
	}
	if a.component.PackageURL != b.component.PackageURL {
		if a.component.PackageURL < b.component.PackageURL {
			return -1
		}
		return 1
	}
	if a.foundBy != b.foundBy {
		if a.foundBy < b.foundBy {
			return -1
		}
		return 1
	}
	if a.component.BOMRef != b.component.BOMRef {
		if a.component.BOMRef < b.component.BOMRef {
			return -1
		}
		return 1
	}
	if a.order < b.order {
		return -1
	}
	if a.order > b.order {
		return 1
	}
	return 0
}

// scanCandidateQualityScore ranks component candidates by identification value
// (PURL/foundBy/version/name quality).
func scanCandidateQualityScore(candidate scanComponentCandidate) int {
	score := 0
	if candidate.component.PackageURL != "" {
		score += 4
	}
	if candidate.foundBy != "" {
		score += 3
	}
	if candidate.component.Version != "" {
		score += 2
	}
	if candidate.component.Name != "" && !strings.Contains(candidate.component.Name, "/") {
		score++
	}
	return score
}

// shouldCollapseScanCandidateGroup returns true when all non-best candidates in
// a locus group are weak placeholders and can be safely suppressed.
func shouldCollapseScanCandidateGroup(group []scanComponentCandidate, best scanComponentCandidate) bool {
	if scanCandidateQualityScore(best) < 4 {
		return false
	}

	for i := range group {
		candidate := group[i]
		if candidate.component.BOMRef == best.component.BOMRef && candidate.order == best.order {
			continue
		}
		if !isWeakScanCandidate(candidate) {
			return false
		}
	}

	return true
}

// isWeakScanCandidate flags entries that have little identification value and
// likely mirror the physical file name rather than package identity.
func isWeakScanCandidate(candidate scanComponentCandidate) bool {
	if candidate.component.PackageURL != "" || candidate.foundBy != "" || candidate.component.Version != "" {
		return false
	}
	name := candidate.component.Name
	if name == "" {
		return true
	}
	if strings.Contains(name, "/") {
		return true
	}

	base := path.Base(candidate.deliveryPath)
	baseNoExt := strings.TrimSuffix(base, path.Ext(base))
	return strings.EqualFold(name, base) || strings.EqualFold(name, baseNoExt)
}

// isLowValueFileArtifact identifies type=file components without any metadata
// that would support useful package-level vulnerability correlation.
func isLowValueFileArtifact(comp cdx.Component, foundBy string) bool {
	if comp.Type != cdx.ComponentTypeFile {
		return false
	}
	return comp.PackageURL == "" && comp.Version == "" && foundBy == ""
}

// firstComponentFoundByPropertyValue returns the first non-empty
// syft:package:foundBy property value.
func firstComponentFoundByPropertyValue(comp cdx.Component) string {
	if comp.Properties == nil {
		return ""
	}
	for _, prop := range *comp.Properties {
		if prop.Name == "syft:package:foundBy" && prop.Value != "" {
			return prop.Value
		}
	}
	return ""
}
