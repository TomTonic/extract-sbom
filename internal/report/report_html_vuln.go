package report

import (
	"sort"
	"strings"
)

// collectHTMLVulns flattens the Grype match map into a deterministically sorted,
// deduplicated slice of HTML vulnerability rows. Each (vulnerability ID, bom-ref)
// pair is rendered once.
func collectHTMLVulns(data ReportData) []htmlVuln {
	if data.Vulnerabilities == nil || len(data.Vulnerabilities.MatchesByBOMRef) == 0 {
		return nil
	}

	// Build a component bom-ref -> name/version lookup.
	bomRefName := make(map[string]string)
	bomRefVersion := make(map[string]string)
	if data.BOM != nil && data.BOM.Components != nil {
		comps := *data.BOM.Components
		for i := range comps {
			bomRefName[comps[i].BOMRef] = comps[i].Name
			bomRefVersion[comps[i].BOMRef] = comps[i].Version
		}
	}

	// Collect the distinct (id, bom-ref) keys, then sort for stable output.
	type vulnKey struct{ id, bomRef string }
	seen := make(map[vulnKey]bool)
	var keys []vulnKey
	for bomRef, matches := range data.Vulnerabilities.MatchesByBOMRef {
		for i := range matches {
			k := vulnKey{id: matches[i].VulnerabilityID, bomRef: bomRef}
			if seen[k] {
				continue
			}
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].id != keys[j].id {
			return keys[i].id < keys[j].id
		}
		return keys[i].bomRef < keys[j].bomRef
	})

	vulns := make([]htmlVuln, 0, len(keys))
	for _, k := range keys {
		matches := data.Vulnerabilities.MatchesByBOMRef[k.bomRef]
		for i := range matches {
			if matches[i].VulnerabilityID != k.id {
				continue
			}
			desc := matches[i].Description
			if len([]rune(desc)) > 120 {
				desc = string([]rune(desc)[:120]) + "…"
			}
			vulns = append(vulns, htmlVuln{
				ID:          matches[i].VulnerabilityID,
				Severity:    matches[i].Severity,
				SeverityCSS: severityCSSClass(strings.ToLower(matches[i].Severity)),
				Package:     bomRefName[k.bomRef],
				Version:     bomRefVersion[k.bomRef],
				Description: desc,
			})
			break
		}
	}
	return vulns
}

// severityCSSClass maps a lowercase severity string to a CSS class name.
func severityCSSClass(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown-sev"
	}
}
