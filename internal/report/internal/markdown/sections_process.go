package markdown

import (
	"fmt"
	"io"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/policy"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// writePolicyDecisions lists policy-engine decisions captured during runtime.
func writePolicyDecisions(w io.Writer, decisions []policy.Decision, t translations) {
	if len(decisions) == 0 {
		fmt.Fprintf(w, "- %s\n", t.noPolicyDecisions)
		return
	}

	for _, d := range decisions {
		fmt.Fprintf(w, "- **%s** %s `%s`: %s -> %s\n", d.Trigger, t.policyDecisionAt, d.NodePath, d.Detail, d.Action)
	}
}

// writeProcessingIssues prints a bounded table of pipeline/extraction/scan
// issues for auditable troubleshooting.
func writeProcessingIssues(w io.Writer, data ReportData, proj reportjson.ProjectionsV2, t translations) {
        fmt.Fprintf(w, "- %s: %d\n", t.processingPipelineLabel, len(proj.Issues))
        
        var extractionIssues []reportjson.ExtractionLogRowV2
        var extFailed, extBlocked, extMissing int
        for _, row := range proj.ExtractionLog {
        	if row.Status != "success" && row.Status != "skipped" {
        		extractionIssues = append(extractionIssues, row)
        		switch row.Status {
        		case "failed": extFailed++
        		case "blocked": extBlocked++
        		case "tool_missing": extMissing++
        		}
        	}
        }
        fmt.Fprintf(w, "- %s: %d\n", t.processingExtractionFailedLabel, extFailed)
        fmt.Fprintf(w, "- %s: %d\n", t.processingSecurityBlockedLabel, extBlocked)
        fmt.Fprintf(w, "- %s: %d\n", t.processingToolMissingLabel, extMissing)

        if len(proj.Issues) == 0 && len(extractionIssues) == 0 {
                fmt.Fprintf(w, "\n- %s\n", t.noProcessingIssues)
                return
        }

        fmt.Fprintln(w)
        fmt.Fprintf(w, "| Stage | Message |\n|---|---|\n")
        
        for _, issue := range proj.Issues {
        	fmt.Fprintf(w, "| %s | %s |\n", escapeMarkdownCell(issue.Stage), escapeMarkdownCell(issue.Message))
        }
        
        for _, extIssue := range extractionIssues {
        	fmt.Fprintf(w, "| extraction | %s (%s) %s |\n", escapeMarkdownCell(extIssue.Path), escapeMarkdownCell(extIssue.Status), escapeMarkdownCell(extIssue.Detail))
        }
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
