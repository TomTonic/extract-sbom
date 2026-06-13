package markdown

import (
	"fmt"
	"io"
	"sort"
	"strings"

	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeScanNoPackageIdentitiesSubsection writes scan targets where Syft
// returned no component identities, which is a key coverage signal.
func writeScanNoPackageIdentitiesSubsection(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	writeAnchoredHeading(w, 3, t.ScanNoPackageIDsSection, anchorScanNoPackageIDs)
	if len(proj.Summary.ScanNoPackagePaths) == 0 {
		fmt.Fprintf(w, "- %s\n", t.NoScanNoPackageIDs)
		return
	}

	paths := proj.Summary.ScanNoPackagePaths
	fmt.Fprintf(w, "%s\n\n", fmt.Sprintf(t.ScanNoPackageIDsLead, len(paths)))
	const maxRows = 300
	for i, p := range paths {
		if i >= maxRows {
			fmt.Fprintf(w, "- ... (%s)\n", fmt.Sprintf(t.AdditionalEntriesOmittedTemplate, len(paths)-maxRows))
			break
		}
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

// writeExtensionFilterSection documents which file extensions were configured
// to be skipped and which logical paths were affected.
func writeExtensionFilterSection(w io.Writer, skipExtensions []string, proj reportjson.ProjectionsV2, t translations) {
	fmt.Fprintln(w, t.ExtensionFilterLead)
	fmt.Fprintln(w)

	if len(skipExtensions) > 0 {
		extensions := make([]string, len(skipExtensions))
		copy(extensions, skipExtensions)
		sort.Strings(extensions)
		quoted := make([]string, len(extensions))
		for i, e := range extensions {
			quoted[i] = "`" + e + "`"
		}
		fmt.Fprintf(w, "**%s:** %s\n\n", t.ExtensionFilterExtensionsLabel, strings.Join(quoted, ", "))
	} else {
		fmt.Fprintln(w, t.NoExtensionFilteredFiles)
		return
	}

	fmt.Fprintf(w, "**%s (%d):**\n\n", t.ExtensionFilterSkippedLabel, len(proj.Summary.ExtensionFilteredPaths))
	if len(proj.Summary.ExtensionFilteredPaths) == 0 {
		fmt.Fprintf(w, "- %s\n", t.NoExtensionFilteredFiles)
		return
	}

	paths := make([]string, len(proj.Summary.ExtensionFilteredPaths))
	copy(paths, proj.Summary.ExtensionFilteredPaths)
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(w, "- `%s`\n", p)
	}
}

// writeComponentOccurrenceIndex renders the appendix index grouped by package
// (name+version) and lists concrete component occurrences underneath.
func writeComponentOccurrenceIndex(w io.Writer, proj reportjson.ProjectionsV2, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.ComponentIndexLead)

	if len(proj.ComponentIndex) == 0 {
		fmt.Fprintf(w, "- %s\n", t.NoIndexedComponents)
		return
	}
	groups := proj.ComponentIndex

	var withPURL, withoutPURL []reportjson.PackageOccurrenceGroupV2
	for i := range groups {
		if len(groups[i].PURLs) > 0 {
			withPURL = append(withPURL, groups[i])
		} else {
			withoutPURL = append(withoutPURL, groups[i])
		}
	}

	enrichmentDone := proj.Summary.VulnerabilityEnrichmentState == "completed"

	sort.Slice(withPURL, func(i, j int) bool {
		ni, nj := strings.ToLower(withPURL[i].PackageName), strings.ToLower(withPURL[j].PackageName)
		if ni != nj {
			return ni < nj
		}
		return strings.ToLower(withPURL[i].Version) < strings.ToLower(withPURL[j].Version)
	})
	sort.Slice(withoutPURL, func(i, j int) bool {
		ni, nj := strings.ToLower(withoutPURL[i].PackageName), strings.ToLower(withoutPURL[j].PackageName)
		if ni != nj {
			return ni < nj
		}
		return strings.ToLower(withoutPURL[i].Version) < strings.ToLower(withoutPURL[j].Version)
	})

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.ComponentIndexWithPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithPURL), anchorComponentsWithPURL)
	if len(withPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.NoIndexedComponents)
	} else {
		for i := range withPURL {
			writePackageGroupEntry(w, withPURL[i], t, enrichmentDone)
		}
	}

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.ComponentIndexWithoutPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithoutPURL), anchorComponentsWithoutPURL)
	if len(withoutPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.NoIndexedComponents)
	} else {
		for i := range withoutPURL {
			writePackageGroupEntry(w, withoutPURL[i], t, enrichmentDone)
		}
	}
}

// writePackageGroupEntry renders one package group and its nested occurrences.
// enrichmentDone controls whether vulnerability status lines are emitted.
func writePackageGroupEntry(w io.Writer, group reportjson.PackageOccurrenceGroupV2, t translations, enrichmentDone bool) {
	title := strings.TrimSpace(group.PackageName)
	if title == "" {
		title = t.NoneValue
	}
	if strings.TrimSpace(group.Version) != "" {
		title += " " + group.Version
	}
	writeAnchoredHeading(w, 4, escapeMarkdownText(title), group.AnchorID)
	fmt.Fprintf(w, "- %s: `%s`\n", t.PackageName, valueOrDash(group.PackageName))
	fmt.Fprintf(w, "- %s: `%s`\n", t.Version, valueOrDash(group.Version))
	if len(group.PURLs) == 1 {
		fmt.Fprintf(w, "- %s: `%s`\n", t.Purl, group.PURLs[0])
	} else if len(group.PURLs) > 1 {
		for _, p := range group.PURLs {
			fmt.Fprintf(w, "- %s: `%s`\n", t.PurlsLabel, p)
		}
	}

	perOccurrenceVuln := false
	if enrichmentDone && len(group.Occurrences) > 0 {
		allFound, anyFound := true, false
		for i := range group.Occurrences {
			if group.Occurrences[i].VulnCount > 0 {
				anyFound = true
			} else {
				allFound = false
			}
		}
		if allFound && anyFound {
			fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.VulnStatusFoundTemplate, group.VulnUniqueCount))
		} else if anyFound {
			perOccurrenceVuln = true
		}
	}

	for i := range group.Occurrences {
		writeOccurrenceListEntry(w, group.Occurrences[i], t, perOccurrenceVuln)
	}
	fmt.Fprintln(w)
}

// writeOccurrenceListEntry renders one normalized occurrence as a nested list
// item inside a package-group entry. renderVulnStatus controls per-occurrence vuln lines.
func writeOccurrenceListEntry(w io.Writer, occ reportjson.OccurrenceRowV2, t translations, renderVulnStatus bool) {
	fmt.Fprintf(w, "- %s: <a id=\"%s\"></a>`%s`\n", t.ComponentIDLabel, domain.OccurrenceAnchorID(occ.ObjectID), occ.ObjectID)
	for _, dp := range occ.DeliveryPaths {
		fmt.Fprintf(w, "  - %s: `%s`\n", t.DeliveryPath, dp)
	}
	switch {
	case len(occ.EvidencePaths) > 0:
		for _, evidencePath := range occ.EvidencePaths {
			fmt.Fprintf(w, "  - %s: `%s`\n", t.EvidencePath, evidencePath)
		}
	case occ.EvidenceSource != "":
		fmt.Fprintf(w, "  - %s: `%s`\n", t.EvidencePath, occ.EvidenceSource)
	default:
		fmt.Fprintf(w, "  - %s: %s\n", t.EvidencePath, t.NoEvidenceRecorded)
	}
	if occ.FoundBy != "" {
		fmt.Fprintf(w, "  - %s: `%s`\n", t.FoundBy, occ.FoundBy)
	}
	if renderVulnStatus {
		if occ.VulnCount > 0 {
			fmt.Fprintf(w, "  - %s\n", fmt.Sprintf(t.VulnStatusFoundTemplate, occ.VulnCount))
		} else {
			fmt.Fprintf(w, "  - %s\n", t.VulnStatusNone)
		}
	}
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
