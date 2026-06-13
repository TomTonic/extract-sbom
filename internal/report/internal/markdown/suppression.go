package markdown

import (
	"fmt"
	"io"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeSuppressionReport renders normalisation/suppression evidence grouped by
// reason so deduplication remains auditable.
func writeSuppressionReport(w io.Writer, groups reportjson.SuppressionGroupsV2, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.ComponentNormalizationLead)

	total := len(groups.FSArtifacts) + len(groups.LowValue) + len(groups.WeakDups) + len(groups.PURLDups)
	if total == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.NoSuppressions)
	}

	fmt.Fprintf(w, "| %s | %s |\n", t.ReasonLabel, t.CountLabel)
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %d |\n", t.SuppressionReasonFSArtifact, len(groups.FSArtifacts))
	fmt.Fprintf(w, "| %s | %d |\n", t.SuppressionReasonLowValueFile, len(groups.LowValue))
	fmt.Fprintf(w, "| %s | %d |\n", t.SuppressionReasonWeakDuplicate, len(groups.WeakDups))
	fmt.Fprintf(w, "| %s | %d |\n", t.SuppressionReasonPURLDuplicate, len(groups.PURLDups))
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.SuppressionReasonFSArtifact, len(groups.FSArtifacts)), anchorSuppressionFSArtifacts)
	fmt.Fprintln(w, t.SuppressionOperationalFS)
	fmt.Fprintln(w)
	fmt.Fprintln(w, t.SuppressionOperationalFSFollowUp)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.FSArtifacts, t)

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.SuppressionReasonLowValueFile, len(groups.LowValue)), anchorSuppressionLowValue)
	fmt.Fprintln(w, t.SuppressionOperationalLowValue)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.LowValue, t)

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.SuppressionReasonWeakDuplicate, len(groups.WeakDups)), anchorSuppressionWeakDups)
	fmt.Fprintln(w, t.SuppressionOperationalWeakDup)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.WeakDups, t)

	writeAnchoredHeading(w, 3, fmt.Sprintf("%s (%d)", t.SuppressionReasonPURLDuplicate, len(groups.PURLDups)), anchorSuppressionPURLDups)
	fmt.Fprintln(w, t.SuppressionOperationalPURLDup)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.PURLDups, t)
}

// writeSuppressionTable prints a bounded, deterministic table for one suppression group.
func writeSuppressionTable(w io.Writer, rows []reportjson.SuppressionRowV2, t translations) {
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.SuppressionTableDeliveryPath, t.SuppressionTableComponentName, t.SuppressionTableSuppressedBy)
	fmt.Fprintln(w, "|---|---|---|")
	if len(rows) == 0 {
		fmt.Fprintln(w, "| - | - | - |")
		fmt.Fprintln(w)
		return
	}

	const maxRows = 30
	for i := range rows {
		if i >= maxRows {
			fmt.Fprintf(w, "| ... | ... | %s |\n", fmt.Sprintf(t.AdditionalEntriesOmittedTemplate, len(rows)-maxRows))
			break
		}
		row := &rows[i]
		name := row.ComponentName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(w, "| `%s` | `%s` | %s |\n",
			escapeMarkdownCell(row.DeliveryPath),
			escapeMarkdownCell(name),
			suppressedByCell(row, t),
		)
	}
	fmt.Fprintln(w)
}

// suppressedByCell formats the "suppressed by" column with a link to the kept
// component when resolution succeeded, or an explanatory fallback otherwise.
func suppressedByCell(row *reportjson.SuppressionRowV2, t translations) string {
	if row.ResolutionStatus == "resolved" && row.KeptComponentName != "" {
		if row.KeptAnchorID != "" {
			return componentAnchorLink(escapeMarkdownCell(row.KeptComponentName), row.KeptAnchorID)
		}
		return fmt.Sprintf("`%s`", escapeMarkdownCell(row.KeptComponentName))
	}
	reason := suppressionResolveReasonText(row.ResolutionReason, t)
	if reason == "" {
		reason = t.SuppressedByNoIndexedMatch
	}
	return fmt.Sprintf("*%s*", escapeMarkdownCell(reason))
}

func suppressionResolveReasonText(code string, t translations) string {
	switch code {
	case "suppressed component not present in canonical component set":
		return t.SuppressedByNoIndexedMatch
	default:
		return ""
	}
}
