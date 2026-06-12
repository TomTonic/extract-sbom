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
	writeAnchoredHeading(w, 3, t.scanNoPackageIDsSection, anchorScanNoPackageIDs)
	if len(proj.Summary.ScanNoPackagePaths) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noScanNoPackageIDs)
		return
	}

	paths := proj.Summary.ScanNoPackagePaths
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

// writeExtensionFilterSection documents which file extensions were configured
// to be skipped and which logical paths were affected.
func writeExtensionFilterSection(w io.Writer, skipExtensions []string, proj reportjson.ProjectionsV2, t translations) {
	fmt.Fprintln(w, t.extensionFilterLead)
	fmt.Fprintln(w)

	if len(skipExtensions) > 0 {
		extensions := make([]string, len(skipExtensions))
		copy(extensions, skipExtensions)
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

	fmt.Fprintf(w, "**%s (%d):**\n\n", t.extensionFilterSkippedLabel, len(proj.Summary.ExtensionFilteredPaths))
	if len(proj.Summary.ExtensionFilteredPaths) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noExtensionFilteredFiles)
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
	fmt.Fprintf(w, "%s\n\n", t.componentIndexLead)

	if len(proj.ComponentIndex) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noIndexedComponents)
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

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.componentIndexWithPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithPURL), anchorComponentsWithPURL)
	if len(withPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
	} else {
		for i := range withPURL {
			writePackageGroupEntry(w, withPURL[i], t, enrichmentDone)
		}
	}

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.componentIndexWithoutPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithoutPURL), anchorComponentsWithoutPURL)
	if len(withoutPURL) == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noIndexedComponents)
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

	perOccurrenceVuln := false
	if enrichmentDone && len(group.Occurrences) > 0 {
		allFound, anyFound := true, false
		for _, occ := range group.Occurrences {
			if occ.VulnCount > 0 {
				anyFound = true
			} else {
				allFound = false
			}
		}
		if allFound && anyFound {
			fmt.Fprintf(w, "- %s\n", fmt.Sprintf(t.vulnStatusFoundTemplate, group.VulnUniqueCount))
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
	fmt.Fprintf(w, "- %s: <a id=\"%s\"></a>`%s`\n", t.componentIDLabel, domain.OccurrenceAnchorID(occ.ObjectID), occ.ObjectID)
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
	if renderVulnStatus {
		if occ.VulnCount > 0 {
			fmt.Fprintf(w, "  - %s\n", fmt.Sprintf(t.vulnStatusFoundTemplate, occ.VulnCount))
		} else {
			fmt.Fprintf(w, "  - %s\n", t.vulnStatusNone)
		}
	}
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
