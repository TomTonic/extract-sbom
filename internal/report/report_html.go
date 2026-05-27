package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// htmlReportData is the template data structure for the HTML report. It bundles
// the localized label set (M) with the report values. All string fields hold
// plain text; the html/template engine performs context-aware escaping when
// the template is executed.
type htmlReportData struct {
	M           htmlMessages
	Generated   string
	Generator   string
	Tools       string
	InputFile   string
	InputSize   int64
	InputSHA256 string
	Duration    string
	SBOMPath    string
	SandboxName string
	Language    string

	ExtractionTotal     int
	ExtractionExtracted int
	ExtractionFailed    int
	ExtractionSkipped   int

	ComponentCount int
	VulnCount      int
	IssueCount     int

	// VulnState is the enrichment outcome classification used to render the
	// Vulnerabilities summary cell: "not-requested", "unavailable", or
	// "assessed". See htmlVulnState.
	VulnState string

	Vulns     []htmlVuln
	Issues    []htmlIssue
	ExtrNodes []htmlNode
}

// htmlVuln is one vulnerability-table row.
type htmlVuln struct {
	ID          string
	Severity    string
	SeverityCSS string
	Package     string
	Version     string
	Description string
}

// htmlIssue is one processing-issue table row.
type htmlIssue struct {
	Stage   string
	Message string
}

// htmlNode is one extraction-log table row.
type htmlNode struct {
	Depth  int
	Path   string
	Status string
	Format string
	Tool   string
	Detail string
}

const htmlReportCSS = `
body{font-family:system-ui,sans-serif;margin:0;padding:1rem 2rem;color:#1a1a1a;background:#fff}
h1{font-size:1.6rem;margin-bottom:0.3rem;border-bottom:2px solid #333;padding-bottom:0.3rem}
h2{font-size:1.2rem;margin-top:1.5rem;margin-bottom:0.5rem;border-bottom:1px solid #ccc}
.meta{color:#555;font-size:0.85rem;margin-bottom:1rem}
table{border-collapse:collapse;width:100%;margin-bottom:1rem;font-size:0.9rem}
th{background:#f0f0f0;text-align:left;padding:0.4rem 0.6rem;border:1px solid #ccc}
td{padding:0.35rem 0.6rem;border:1px solid #ddd;vertical-align:top}
tr:nth-child(even){background:#f9f9f9}
.badge{display:inline-block;padding:0.15rem 0.4rem;border-radius:3px;font-size:0.8rem;font-weight:bold;color:#fff}
.critical{background:#c0392b}.high{background:#e67e22}.medium{background:#f1c40f;color:#333}
.low{background:#2980b9}.negligible{background:#7f8c8d}.unknown-sev{background:#7f8c8d}
.ok{color:#27ae60;font-weight:bold}.err{color:#c0392b;font-weight:bold}.muted{color:#888;font-style:italic}
details>summary{cursor:pointer;padding:0.3rem 0}
details summary h2{display:inline;margin:0}
code{background:#f4f4f4;padding:0.1rem 0.3rem;border-radius:2px;font-size:0.85rem}
.d0{padding-left:0}.d1{padding-left:1rem}.d2{padding-left:2rem}
.d3{padding-left:3rem}.d4{padding-left:4rem}.d5{padding-left:5rem}
`

const htmlReportTemplateText = `<!DOCTYPE html>
<html lang="{{.Language}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.M.ReportTitle}}</title>
<style>` + htmlReportCSS + `</style>
</head>
<body>
<h1>{{.M.ReportTitle}}</h1>
<div class="meta">{{.M.GeneratedLabel}}: {{.Generated}} &nbsp;|&nbsp; {{.M.GeneratorLabel}}: {{.Generator}}</div>

<h2>{{.M.SummaryHeading}}</h2>
<table>
<tr><th>{{.M.FieldHeading}}</th><th>{{.M.ValueHeading}}</th></tr>
<tr><td>{{.M.InputFileLabel}}</td><td>{{.InputFile}}</td></tr>
<tr><td>{{.M.InputSizeLabel}}</td><td>{{.InputSize}} {{.M.BytesUnit}}</td></tr>
<tr><td>{{.M.SHA256Label}}</td><td><code>{{.InputSHA256}}</code></td></tr>
<tr><td>{{.M.DurationLabel}}</td><td>{{.Duration}}</td></tr>
<tr><td>{{.M.SBOMOutputLabel}}</td><td>{{if .SBOMPath}}{{.SBOMPath}}{{else}}&#8212;{{end}}</td></tr>
<tr><td>{{.M.SandboxLabel}}</td><td>{{.SandboxName}}</td></tr>
<tr><td>{{.M.ToolsLabel}}</td><td>{{if .Tools}}{{.Tools}}{{else}}&#8212;{{end}}</td></tr>
<tr><td>{{.M.ComponentsLabel}}</td><td>{{.ComponentCount}}</td></tr>
<tr><td>{{.M.VulnsLabel}}</td><td>{{if eq .VulnState "not-requested"}}<span class="muted">{{.M.VulnNotRequested}}</span>{{else if eq .VulnState "unavailable"}}<span class="err">{{.M.VulnUnavailable}}</span>{{else if gt .VulnCount 0}}<span class="badge high">{{.VulnCount}}</span>{{else}}<span class="ok">0</span>{{end}}</td></tr>
<tr><td>{{.M.IssuesLabel}}</td><td>{{if gt .IssueCount 0}}<span class="badge err">{{.IssueCount}}</span>{{else}}<span class="ok">0</span>{{end}}</td></tr>
</table>

<h2>{{.M.ExtractionHeading}}</h2>
<table>
<tr><th>{{.M.StatusHeading}}</th><th>{{.M.CountHeading}}</th></tr>
<tr><td>{{.M.ExtractedLabel}}</td><td>{{.ExtractionExtracted}}</td></tr>
<tr><td>{{.M.FailedLabel}}</td><td>{{if gt .ExtractionFailed 0}}<span class="err">{{.ExtractionFailed}}</span>{{else}}0{{end}}</td></tr>
<tr><td>{{.M.SkippedLabel}}</td><td>{{.ExtractionSkipped}}</td></tr>
<tr><td>{{.M.TotalNodesLabel}}</td><td>{{.ExtractionTotal}}</td></tr>
</table>

{{if .Vulns}}
<details open>
<summary><h2>{{.M.VulnTableHeading}} ({{len .Vulns}} {{.M.VulnMatchesWord}})</h2></summary>
<table>
<tr><th>{{.M.IDHeading}}</th><th>{{.M.SeverityHeading}}</th><th>{{.M.PackageHeading}}</th><th>{{.M.VersionHeading}}</th><th>{{.M.DescriptionHeading}}</th></tr>
{{range .Vulns}}<tr>
<td>{{.ID}}</td>
<td><span class="badge {{.SeverityCSS}}">{{.Severity}}</span></td>
<td>{{.Package}}</td>
<td>{{.Version}}</td>
<td>{{.Description}}</td>
</tr>{{end}}
</table>
</details>
{{end}}

{{if .Issues}}
<details open>
<summary><h2>{{.M.IssuesHeading}} ({{len .Issues}})</h2></summary>
<table>
<tr><th>{{.M.StageHeading}}</th><th>{{.M.MessageHeading}}</th></tr>
{{range .Issues}}<tr><td>{{.Stage}}</td><td>{{.Message}}</td></tr>{{end}}
</table>
</details>
{{end}}

{{if .ExtrNodes}}
<details>
<summary><h2>{{.M.ExtractionLogHeading}}</h2></summary>
<table>
<tr><th>{{.M.PathHeading}}</th><th>{{.M.FormatHeading}}</th><th>{{.M.StatusHeading}}</th><th>{{.M.ToolHeading}}</th><th>{{.M.DetailHeading}}</th></tr>
{{range .ExtrNodes}}<tr>
<td class="d{{.Depth}}">{{.Path}}</td>
<td>{{.Format}}</td>
<td>{{.Status}}</td>
<td>{{.Tool}}</td>
<td>{{.Detail}}</td>
</tr>{{end}}
</table>
</details>
{{end}}
</body>
</html>`

var htmlReportTmpl = template.Must(template.New("html-report").Parse(htmlReportTemplateText))

// GenerateHTML writes a self-contained HTML audit report to w.
//
// String values are passed to the template as plain text; the html/template
// engine performs context-aware escaping, so no value needs to be escaped by
// hand before being placed into htmlReportData.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - language: the output language code ("en" or "de"); unrecognized values
//     fall back to English
//   - w: the writer to write the HTML report to
//
// Returns an error if writing fails.
func GenerateHTML(data ReportData, language string, w io.Writer) error {
	extStats := collectExtractionStats(data.Tree)

	compCount := 0
	if data.BOM != nil && data.BOM.Components != nil {
		compCount = len(*data.BOM.Components)
	}

	vulns := collectHTMLVulns(data)

	// Collect processing issues.
	var issues []htmlIssue
	for _, iss := range data.ProcessingIssues {
		issues = append(issues, htmlIssue(iss))
	}

	// Collect extraction log nodes (flatten tree).
	var nodes []htmlNode
	flattenExtractionNodes(data.Tree, 0, &nodes)

	td := htmlReportData{
		M:                   htmlMessagesFor(language),
		Generated:           time.Now().Format("2006-01-02 15:04:05"),
		Generator:           data.Generator.String(),
		Tools:               htmlToolVersions(data.ToolVersions),
		InputFile:           data.Input.Filename,
		InputSize:           data.Input.Size,
		InputSHA256:         data.Input.SHA256,
		Duration:            data.EndTime.Sub(data.StartTime).Round(time.Millisecond).String(),
		SBOMPath:            data.SBOMPath,
		SandboxName:         data.SandboxInfo.Name,
		Language:            language,
		ExtractionTotal:     extStats.Total,
		ExtractionExtracted: extStats.Extracted,
		ExtractionFailed:    extStats.Failed,
		ExtractionSkipped:   extStats.Skipped + extStats.ToolMissing,
		ComponentCount:      compCount,
		VulnCount:           len(vulns),
		IssueCount:          len(issues),
		VulnState:           htmlVulnState(data.Vulnerabilities),
		Vulns:               vulns,
		Issues:              issues,
		ExtrNodes:           nodes,
	}

	return htmlReportTmpl.Execute(w, td)
}

// htmlVulnState classifies the vulnerability-enrichment outcome for the HTML
// summary. It exists so the report can distinguish "no vulnerabilities found"
// from "enrichment was not requested" or "Grype was unavailable" — the same
// audit distinction the Markdown report preserves. A plain "0" would conflate
// all three. Returns one of "not-requested", "unavailable", or "assessed".
func htmlVulnState(v *vulnscan.Result) string {
	if !vulnerabilityRequested(v) {
		return "not-requested"
	}
	if v.State == vulnscan.StateUnavailable {
		return "unavailable"
	}
	return "assessed"
}

// htmlToolVersions joins the detected external-tool version strings into a
// single " | "-separated line for the summary table. An empty result means no
// external tool reported a version during this run.
func htmlToolVersions(tv ToolVersions) string {
	var parts []string
	if tv.Grype != "" {
		entry := tv.Grype
		if tv.GrypeDB != "" {
			entry += " (" + tv.GrypeDB + ")"
		}
		parts = append(parts, entry)
	}
	if tv.SevenZip != "" {
		parts = append(parts, tv.SevenZip)
	}
	if tv.Unshield != "" {
		parts = append(parts, tv.Unshield)
	}
	if tv.Unsquashfs != "" {
		parts = append(parts, tv.Unsquashfs)
	}
	return strings.Join(parts, " | ")
}

// collectHTMLVulns flattens the Grype match map into a deterministically sorted,
// deduplicated slice of HTML vulnerability rows. Each (vulnerability ID, bom-ref)
// pair is rendered once.
func collectHTMLVulns(data ReportData) []htmlVuln {
	if data.Vulnerabilities == nil || len(data.Vulnerabilities.MatchesByBOMRef) == 0 {
		return nil
	}

	// Build a component bom-ref → name/version lookup.
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

// flattenExtractionNodes recursively collects extraction nodes for display.
func flattenExtractionNodes(node *extract.ExtractionNode, depth int, out *[]htmlNode) {
	if node == nil {
		return
	}
	d := depth
	if d > 5 {
		d = 5
	}
	*out = append(*out, htmlNode{
		Depth:  d,
		Path:   node.Path,
		Status: node.Status.String(),
		Format: node.Format.Format.String(),
		Tool:   node.Tool,
		Detail: node.StatusDetail,
	})
	for _, child := range node.Children {
		flattenExtractionNodes(child, depth+1, out)
	}
}
