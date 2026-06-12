package markdown

import (
	"fmt"
	"io"
	"strings"

	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writeSuppressionReport renders normalisation/suppression evidence grouped by
// reason so deduplication remains auditable.
func writeSuppressionReport(w io.Writer, groups reportjson.SuppressionGroupsV2, t translations) {
	fmt.Fprintf(w, "%s\n\n", t.componentNormalizationLead)

	total := len(groups.FSArtifacts) + len(groups.LowValue) + len(groups.WeakDups) + len(groups.PURLDups)
	if total == 0 {
		fmt.Fprintf(w, "- %s\n\n", t.noSuppressions)
	}

	fmt.Fprintf(w, "| %s | %s |\n", t.reasonLabel, t.countLabel)
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonFSArtifact, len(groups.FSArtifacts))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonLowValueFile, len(groups.LowValue))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonWeakDuplicate, len(groups.WeakDups))
	fmt.Fprintf(w, "| %s | %d |\n", t.suppressionReasonPURLDuplicate, len(groups.PURLDups))
	fmt.Fprintln(w)

	writeAnchoredHeading(w, 4, fmt.Sprintf("%s (%d)", t.suppressionReasonFSArtifact, len(groups.FSArtifacts)), anchorSuppressionFSArtifacts)
	fmt.Fprintln(w, t.suppressionOperationalFS)
	fmt.Fprintln(w)
	fmt.Fprintln(w, t.suppressionOperationalFSFollowUp)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.FSArtifacts, t)

	writeAnchoredHeading(w, 4, fmt.Sprintf("%s (%d)", t.suppressionReasonLowValueFile, len(groups.LowValue)), anchorSuppressionLowValue)
	fmt.Fprintln(w, t.suppressionOperationalLowValue)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.LowValue, t)

	fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonWeakDuplicate, len(groups.WeakDups))
	fmt.Fprintln(w, t.suppressionOperationalWeakDup)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.WeakDups, t)

	fmt.Fprintf(w, "#### %s (%d)\n\n", t.suppressionReasonPURLDuplicate, len(groups.PURLDups))
	fmt.Fprintln(w, t.suppressionOperationalPURLDup)
	fmt.Fprintln(w)
	writeSuppressionTable(w, groups.PURLDups, t)
}

// writeSuppressionTable prints a bounded, deterministic table for one suppression group.
func writeSuppressionTable(w io.Writer, rows []reportjson.SuppressionRowV2, t translations) {
	fmt.Fprintf(w, "| %s | %s | %s |\n", t.suppressionTableDeliveryPath, t.suppressionTableComponentName, t.suppressionTableSuppressedBy)
	fmt.Fprintln(w, "|---|---|---|")
	if len(rows) == 0 {
		fmt.Fprintln(w, "| - | - | - |")
		fmt.Fprintln(w)
		return
	}

	const maxRows = 30
	for i, row := range rows {
		if i >= maxRows {
			fmt.Fprintf(w, "| ... | ... | %s |\n", fmt.Sprintf(t.additionalEntriesOmittedTemplate, len(rows)-maxRows))
			break
		}
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
func suppressedByCell(row reportjson.SuppressionRowV2, t translations) string {
	if row.ResolutionStatus == "resolved" && row.KeptComponentName != "" {
		if row.KeptAnchorID != "" {
			return fmt.Sprintf("[%s](#%s)", escapeMarkdownCell(row.KeptComponentName), strings.ReplaceAll(row.KeptAnchorID, ":", "-"))
		}
		return fmt.Sprintf("`%s`", escapeMarkdownCell(row.KeptComponentName))
	}
	reason := suppressionResolveReasonText(row.ResolutionReason, t)
	if reason == "" {
		reason = t.suppressedByNoIndexedMatch
	}
	return fmt.Sprintf("*%s*", escapeMarkdownCell(reason))
}

func suppressionResolveReasonText(code string, t translations) string {
	switch code {
	case "suppressed component not present in canonical component set":
		return t.suppressedByNoIndexedMatch
	default:
		return ""
	}
}
