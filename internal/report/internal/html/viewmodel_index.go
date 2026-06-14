package html

import (
	"fmt"
	"sort"
	"strings"

	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func buildComponentIndex(proj reportjson.ProjectionsV2, t i18npkg.Bundle) componentIndexSection {
	s := componentIndexSection{
		Heading:           t.ComponentIndexSection,
		Anchor:            anchorComponentIndex,
		Lead:              i18npkg.RenderInlineHTML(t.ComponentIndexLead),
		EmptyText:         t.NoIndexedComponents,
		WithPURLAnchor:    anchorComponentsWithPURL,
		WithoutPURLAnchor: anchorComponentsWithoutPURL,
	}
	if len(proj.ComponentIndex) == 0 {
		s.Empty = true
		return s
	}
	enrichmentDone := proj.Summary.VulnerabilityEnrichmentState == "completed"

	var withPURL, withoutPURL []reportjson.PackageOccurrenceGroupV2
	for i := range proj.ComponentIndex {
		if len(proj.ComponentIndex[i].PURLs) > 0 {
			withPURL = append(withPURL, proj.ComponentIndex[i])
		} else {
			withoutPURL = append(withoutPURL, proj.ComponentIndex[i])
		}
	}
	sortGroups(withPURL)
	sortGroups(withoutPURL)

	s.WithPURLTitle = fmt.Sprintf("%s (%d)", t.ComponentIndexWithPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithPURL)
	s.WithoutPURLTitle = fmt.Sprintf("%s (%d)", t.ComponentIndexWithoutPURLSubsection, proj.Summary.ComponentIndexStats.IndexedWithoutPURL)
	for i := range withPURL {
		s.WithPURL = append(s.WithPURL, buildGroup(withPURL[i], t, enrichmentDone))
	}
	for i := range withoutPURL {
		s.WithoutPURL = append(s.WithoutPURL, buildGroup(withoutPURL[i], t, enrichmentDone))
	}
	return s
}

func sortGroups(g []reportjson.PackageOccurrenceGroupV2) {
	sort.Slice(g, func(i, j int) bool {
		ni, nj := strings.ToLower(g[i].PackageName), strings.ToLower(g[j].PackageName)
		if ni != nj {
			return ni < nj
		}
		return strings.ToLower(g[i].Version) < strings.ToLower(g[j].Version)
	})
}

func buildGroup(group reportjson.PackageOccurrenceGroupV2, t i18npkg.Bundle, enrichmentDone bool) packageGroup {
	title := strings.TrimSpace(group.PackageName)
	if title == "" {
		title = t.NoneValue
	}
	if strings.TrimSpace(group.Version) != "" {
		title += " " + group.Version
	}
	pg := packageGroup{
		AnchorID: group.AnchorID,
		Title:    title,
		Name:     valueOrDash(group.PackageName),
		Version:  group.Version,
		PURLs:    group.PURLs,
		Labels: occurrenceLabels{
			ComponentID:  t.ComponentIDLabel,
			DeliveryPath: t.DeliveryPath,
			EvidencePath: t.EvidencePath,
			FoundBy:      t.FoundBy,
		},
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
			pg.VulnLine = fmt.Sprintf(t.VulnStatusFoundTemplate, group.VulnUniqueCount)
		} else if anyFound {
			perOccurrenceVuln = true
		}
	}

	for i := range group.Occurrences {
		occ := &group.Occurrences[i]
		o := occurrence{
			AnchorID:      domain.OccurrenceAnchorID(occ.ObjectID),
			ObjectID:      occ.ObjectID,
			DeliveryPaths: occ.DeliveryPaths,
			FoundBy:       emptyDash(occ.FoundBy),
		}
		switch {
		case len(occ.EvidencePaths) > 0:
			o.Evidence = occ.EvidencePaths
		case occ.EvidenceSource != "":
			o.Evidence = []string{occ.EvidenceSource}
		default:
			o.Evidence = []string{t.NoEvidenceRecorded}
		}
		if perOccurrenceVuln {
			if occ.VulnCount > 0 {
				o.VulnLine = fmt.Sprintf(t.VulnStatusFoundTemplate, occ.VulnCount)
			} else {
				o.VulnLine = t.VulnStatusNone
			}
		}
		pg.Occurrences = append(pg.Occurrences, o)
	}
	return pg
}
