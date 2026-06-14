package html

import (
	"fmt"
	htmltmpl "html/template"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func buildNormalization(groups reportjson.SuppressionGroupsV2, t i18npkg.Bundle) normalizationSection {
	total := len(groups.FSArtifacts) + len(groups.LowValue) + len(groups.WeakDups) + len(groups.PURLDups)
	s := normalizationSection{
		Heading:   t.ComponentNormalizationSection,
		Anchor:    anchorSuppression,
		Lead:      i18npkg.RenderInlineHTML(t.ComponentNormalizationLead),
		EmptyText: t.NoSuppressions,
		Empty:     total == 0,
		SummaryTable: normalizationSummaryTable{
			Headers: []string{t.ReasonLabel, t.CountLabel, t.DescriptionLabel},
			Rows: []normalizationSummaryRow{
				{t.SuppressionReasonFSArtifact, fmt.Sprintf("%d", len(groups.FSArtifacts)), t.SuppressionDescriptionFSArtifact},
				{t.SuppressionReasonLowValueFile, fmt.Sprintf("%d", len(groups.LowValue)), t.SuppressionDescriptionLowValueFile},
				{t.SuppressionReasonWeakDuplicate, fmt.Sprintf("%d", len(groups.WeakDups)), t.SuppressionDescriptionWeakDuplicate},
				{t.SuppressionReasonPURLDuplicate, fmt.Sprintf("%d", len(groups.PURLDups)), t.SuppressionDescriptionPURLDuplicate},
			},
		},
	}
	s.Groups = []suppressionGroup{
		buildSuppressionGroup(t.SuppressionReasonFSArtifact, anchorSuppressionFS, groups.FSArtifacts, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalFS), i18npkg.RenderInlineHTML(t.SuppressionOperationalFSFollowUp)),
		buildSuppressionGroup(t.SuppressionReasonLowValueFile, anchorSuppressionLowValue, groups.LowValue, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalLowValue)),
		buildSuppressionGroup(t.SuppressionReasonWeakDuplicate, anchorSuppressionWeakDups, groups.WeakDups, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalWeakDup)),
		buildSuppressionGroup(t.SuppressionReasonPURLDuplicate, anchorSuppressionPURLDups, groups.PURLDups, t,
			i18npkg.RenderInlineHTML(t.SuppressionOperationalPURLDup)),
	}
	return s
}

func buildSuppressionGroup(reason, anchor string, rows []reportjson.SuppressionRowV2, t i18npkg.Bundle, operational ...htmltmpl.HTML) suppressionGroup {
	g := suppressionGroup{
		AnchorID:    anchor,
		Title:       fmt.Sprintf("%s (%d)", reason, len(rows)),
		Operational: operational,
		Headers:     []string{t.SuppressionTableDeliveryPath, t.SuppressionTableComponentName, t.SuppressionTableSuppressedBy},
	}
	for i := range rows {
		if i >= suppressionTableMaxRows {
			g.Truncated = fmt.Sprintf(t.AdditionalEntriesOmittedTemplate, len(rows)-suppressionTableMaxRows)
			break
		}
		row := &rows[i]
		name := row.ComponentName
		if name == "" {
			name = "-"
		}
		g.Rows = append(g.Rows, buildSuppRow(row, name, t))
	}
	return g
}

// buildSuppRow models the "suppressed by" cell. KeptName/KeptAnchor are plain
// strings auto-escaped by the template. Reason is a trusted i18n prose string
// that may contain inline Markdown links, so it is rendered to HTML here.
func buildSuppRow(row *reportjson.SuppressionRowV2, name string, t i18npkg.Bundle) suppRow {
	sr := suppRow{DeliveryPath: row.DeliveryPath, Name: name}
	if row.ResolutionStatus == "resolved" && row.KeptComponentName != "" {
		sr.KeptName = row.KeptComponentName
		sr.KeptAnchor = row.KeptAnchorID
		return sr
	}
	sr.Reason = i18npkg.RenderInlineHTML(t.SuppressedByNoIndexedMatch)
	return sr
}
