package html

import htmltmpl "html/template"

// reportTemplate is the compiled HTML report template.
var reportTemplate = htmltmpl.Must(htmltmpl.New("report").Parse(htmlReportTemplateText))

const htmlReportCSS = `
:root{--fg:#1a1a1a;--muted:#666;--border:#ccc;--border-soft:#e2e2e2;--accent:#2c3e50;--bg-alt:#f9f9f9}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;color:var(--fg);background:#fff;line-height:1.5}
.wrap{display:flex;align-items:flex-start;max-width:1400px;margin:0 auto}
nav.toc{position:sticky;top:0;align-self:flex-start;flex:0 0 270px;max-height:100vh;overflow:auto;padding:1rem;font-size:0.82rem;border-right:1px solid var(--border-soft);background:#fafafa}
nav.toc h2{font-size:0.9rem;margin:0 0 0.5rem}
nav.toc a{display:block;text-decoration:none;color:var(--accent);padding:0.1rem 0}
nav.toc a:hover{text-decoration:underline}
nav.toc .lvl1{padding-left:0.9rem}
nav.toc .lvl2{padding-left:1.8rem;color:#555}
main{flex:1 1 auto;min-width:0;padding:1rem 2rem 4rem}
h1{font-size:1.7rem;margin:0 0 0.3rem;border-bottom:2px solid var(--accent);padding-bottom:0.3rem}
h2{font-size:1.25rem;margin:2rem 0 0.6rem;border-bottom:1px solid var(--border);padding-bottom:0.2rem;scroll-margin-top:0.5rem}
h3{font-size:1.05rem;margin:1.3rem 0 0.5rem;scroll-margin-top:0.5rem}
.meta{color:var(--muted);font-size:0.85rem;margin-bottom:0.6rem}
p{margin:0.6rem 0}
table{border-collapse:collapse;width:100%;margin:0.6rem 0;font-size:0.88rem}
th{background:#f0f0f0;text-align:left;padding:0.4rem 0.6rem;border:1px solid var(--border);position:sticky;top:0}
td{padding:0.35rem 0.6rem;border:1px solid var(--border-soft);vertical-align:top}
tr:nth-child(even) td{background:var(--bg-alt)}
code{background:#f4f4f4;padding:0.05rem 0.3rem;border-radius:3px;font-size:0.85em;word-break:break-all}
a{color:var(--accent)}
ul{margin:0.5rem 0;padding-left:1.3rem}
li{margin:0.15rem 0}
.badge{display:inline-block;padding:0.12rem 0.45rem;border-radius:3px;font-size:0.8rem;font-weight:600;color:#fff;white-space:nowrap}
.critical{background:#c0392b}.high{background:#e67e22}.medium{background:#f1c40f;color:#333}
.low{background:#2980b9}.negligible{background:#7f8c8d}.unknown-sev{background:#95a5a6}
.ok{color:#27ae60;font-weight:600}.err{color:#c0392b;font-weight:600}.muted{color:var(--muted);font-style:italic}
details{border:1px solid var(--border-soft);border-radius:4px;margin:0.4rem 0;padding:0 0.6rem}
details[open]{padding-bottom:0.5rem}
summary{cursor:pointer;padding:0.45rem 0;font-weight:600}
summary:hover{color:var(--accent)}
details.group summary{font-weight:500}
details.bucket>summary{font-size:1.02rem}
.count{color:var(--muted);font-weight:400}
.note{background:#fff8e1;border-left:3px solid #f1c40f;padding:0.4rem 0.7rem;margin:0.5rem 0;font-size:0.9rem}
.prose{margin:0.6rem 0}
.pathlist{font-family:ui-monospace,monospace;font-size:0.82rem;word-break:break-all}
.d0{padding-left:0}.d1{padding-left:1.2rem}.d2{padding-left:2.4rem}
.d3{padding-left:3.6rem}.d4{padding-left:4.8rem}.d5{padding-left:6rem}
.kvtable td:first-child{width:230px;color:#444;font-weight:500}
.pkg-meta{margin:0.3rem 0 0.5rem;padding-left:1.3rem}
.occ{border-top:1px solid var(--border-soft);padding:0.45rem 0 0.2rem}
.occ-hdr{font-size:0.88rem}
.occ-hdr code{font-size:0.83rem}
.occ-paths{margin:0.2rem 0 0;padding-left:1rem;list-style:disc;font-size:0.82rem;font-family:ui-monospace,monospace}
.occ-paths em{font-style:normal;color:#555;font-family:system-ui,-apple-system,sans-serif}
.scantable{table-layout:fixed;width:100%}
.scantable th:first-child,.scantable td:first-child{width:42%;word-break:break-all}
.scantable th:nth-child(2),.scantable td:nth-child(2){width:10%}
.scantable th:last-child,.scantable td:last-child{width:48%}
table.sortable th{cursor:pointer;user-select:none}
table.sortable th:hover{background:#e0e0e0}
`

// htmlReportTemplateText is the full report template. Named sub-templates keep
// the repeated table/group markup readable.
const htmlReportTemplateText = `<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>` + htmlReportCSS + `</style>
</head>
<body>
<div class="wrap">
<nav class="toc">
<h2>{{.TOCHeading}}</h2>
{{range .TOC}}<a class="lvl{{.Level}}" href="#{{.Anchor}}">{{.Title}}</a>
{{end}}
</nav>
<main>
<h1>{{.Title}}</h1>
<div class="meta">{{.Meta}}</div>
{{if .Tools}}<div class="meta">{{.Tools}}</div>{{end}}

<h2 id="{{.SummaryAnchor}}">{{.SummaryHeading}}</h2>
<p class="prose">{{.SummaryLead}}</p>
<h3 id="{{.AnalysisAnchor}}">{{.AnalysisHeading}}</h3>
{{range .AnalysisParas}}<p class="prose">{{.}}</p>
{{end}}
{{template "vuln" .Vuln}}

<h2 id="{{.RunScopeAnchor}}">{{.RunScopeHeading}}</h2>
<p>{{.RunScopeLead}}</p>
<h3 id="{{.InputAnchor}}">{{.InputHeading}}</h3>
{{template "kvtable" .InputRows}}
<h3 id="{{.ConfigAnchor}}">{{.ConfigHeading}}</h3>
{{template "kvtable" .ConfigRows}}
<h3 id="{{.SandboxAnchor}}">{{.SandboxHeading}}</h3>
{{with .Sandbox}}{{if .Prose}}<p class="prose">{{.Prose}}</p>{{else}}{{template "kvtable" .Rows}}{{if .Note}}<div class="note">{{.Note}}</div>{{end}}{{end}}{{end}}

<h2 id="{{.Method.Anchor}}">{{.Method.Heading}}</h2>
<p class="prose">{{.Method.Lead}}</p>
<ul>{{range .Method.Bullets}}<li>{{.}}</li>{{end}}</ul>

<h2 id="{{.Processing.Anchor}}">{{.Processing.Heading}}</h2>
{{with .Processing}}{{if .Empty}}<p class="muted">{{.EmptyText}}</p>{{else}}{{template "matrix" .}}{{end}}{{end}}

<h2 id="{{.ResidualAnchor}}">{{.ResidualHeading}}</h2>
<p>{{.ResidualText}}</p>
<ul>{{range .ResidualBullets}}<li>{{.}}</li>{{end}}</ul>

<h2 id="{{.AppendixAnchor}}">{{.AppendixHeading}}</h2>
<p>{{.AppendixLead}}</p>

<h3 id="{{.ComponentIndex.Anchor}}">{{.ComponentIndex.Heading}}</h3>
<p class="prose">{{.ComponentIndex.Lead}}</p>
{{with .ComponentIndex}}{{if .Empty}}<p class="muted">{{.EmptyText}}</p>{{else}}
<details class="bucket" open><summary id="{{.WithPURLAnchor}}">{{.WithPURLTitle}}</summary>
{{range .WithPURL}}{{template "group" .}}{{end}}
</details>
<details class="bucket"><summary id="{{.WithoutPURLAnchor}}">{{.WithoutPURLTitle}}</summary>
{{range .WithoutPURL}}{{template "group" .}}{{end}}
</details>
{{end}}{{end}}

<h3 id="{{.Normalization.Anchor}}">{{.Normalization.Heading}}</h3>
<p class="prose">{{.Normalization.Lead}}</p>
{{with .Normalization}}{{if .Empty}}<p class="muted">{{.EmptyText}}</p>{{end}}
{{template "kvtable2" .SummaryTable}}
{{range .Groups}}<details class="bucket"><summary id="{{.AnchorID}}">{{.Title}}</summary>
{{range .Operational}}<p class="prose">{{.}}</p>{{end}}
{{if .Rows}}<table><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr><td><code>{{.DeliveryPath}}</code></td><td><code>{{.Name}}</code></td><td>{{if .KeptName}}{{if .KeptAnchor}}<a href="#{{.KeptAnchor}}">{{.KeptName}}</a>{{else}}<code>{{.KeptName}}</code>{{end}}{{else}}<em>{{.Reason}}</em>{{end}}</td></tr>
{{end}}</table>{{if .Truncated}}<p class="muted">{{.Truncated}}</p>{{end}}{{else}}<p class="muted">—</p>{{end}}
</details>
{{end}}{{end}}

<h3 id="{{.ExtensionFilter.Anchor}}">{{.ExtensionFilter.Heading}}</h3>
{{with .ExtensionFilter}}<p>{{.Lead}}</p>
{{if .Empty}}<p class="muted">{{.EmptyText}}</p>{{else}}
<p><strong>{{.ExtensionsLabel}}:</strong> {{.Extensions}}</p>
<details class="group"><summary>{{.SkippedLabel}} ({{len .SkippedPaths}})</summary>
<ul class="pathlist">{{range .SkippedPaths}}<li>{{.}}</li>{{end}}</ul>
</details>{{end}}{{end}}

<h3 id="{{.RootMetadata.Anchor}}">{{.RootMetadata.Heading}}</h3>
{{template "matrix" .RootMetadata}}

<h3 id="{{.Policy.Anchor}}">{{.Policy.Heading}}</h3>
{{with .Policy}}{{if .Empty}}<p class="muted">{{.EmptyText}}</p>{{else}}{{template "matrix" .}}{{end}}{{end}}

<h3 id="{{.ScanLog.Anchor}}">{{.ScanLog.Heading}}</h3>
{{with .ScanLog}}<p>{{.Lead}}</p>
<details class="group"><summary>{{.Heading}} ({{len .Rows}})</summary>
<table class="scantable"><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr><td><code>{{.NodePath}}</code></td><td>{{if .Error}}<span class="err">{{.Error}}</span>{{else}}{{.Count}}{{end}}</td><td><ul class="pathlist">{{range .Evidence}}<li>{{.}}</li>{{end}}</ul></td></tr>
{{end}}</table>
</details>
<h4 id="{{.NoPkgAnchor}}">{{.NoPkgHeading}}</h4>
{{if .NoPkgEmpty}}<p class="muted">{{.NoPkgEmptyText}}</p>{{else}}<p>{{.NoPkgLead}}</p>
<details class="group"><summary>{{.NoPkgHeading}} ({{len .NoPkgPaths}})</summary>
<ul class="pathlist">{{range .NoPkgPaths}}<li>{{.}}</li>{{end}}</ul>
</details>{{end}}{{end}}

<h3 id="{{.Extraction.Anchor}}">{{.Extraction.Heading}}</h3>
{{with .Extraction}}<details class="group" open><summary>{{.Heading}} ({{len .Rows}})</summary>
<table><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr><td class="d{{.Depth}}" title="{{.Path}}"><code>{{.ShortPath}}</code></td><td>{{.Format}}</td><td>{{.Status}}</td><td>{{.Tool}}</td><td>{{.Sandbox}}</td><td>{{.Detail}}</td></tr>
{{end}}</table>
</details>{{end}}

<p class="muted">{{.EndNote}}</p>
</main>
</div>
<script>
(function(){
  document.querySelectorAll('table.sortable').forEach(function(tbl){
    var ths=tbl.querySelectorAll('tr:first-child th');
    ths.forEach(function(th,ci){
      th.addEventListener('click',function(){
        var asc=th.dataset.dir!=='asc';
        ths.forEach(function(h){h.dataset.dir='';h.textContent=h.textContent.replace(/ [▲▼]$/,'')});
        th.dataset.dir=asc?'asc':'desc';
        th.textContent+=asc?' ▲':' ▼';
        var rows=Array.from(tbl.querySelectorAll('tr:not(:first-child)'));
        function key(r){var c=r.cells[ci];if(!c)return '';var d=c.getAttribute('data-sort');return d!==null?d:(c.textContent||'');}
        rows.sort(function(a,b){
          var n=key(a).localeCompare(key(b),undefined,{numeric:true,sensitivity:'base'});
          return asc?n:-n;
        });
        rows.forEach(function(r){tbl.appendChild(r)});
      });
    });
  });
})();
</script>
</body>
</html>

{{define "kvtable"}}<table class="kvtable"><tbody>
{{range .}}<tr><td>{{.K}}</td><td>{{.V}}</td></tr>
{{end}}</tbody></table>{{end}}

{{define "kvtable2"}}<table><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr><td>{{.Reason}}</td><td>{{.Count}}</td><td>{{.Description}}</td></tr>
{{end}}</table>{{end}}

{{define "matrix"}}<table><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>
{{end}}</table>{{end}}

{{define "vuln"}}<h3 id="{{.Anchor}}">{{.Heading}}</h3>
{{if not .Requested}}<p class="muted">{{.SummaryLine}}</p>
{{else}}<p>{{.StateLine}}</p>
<p>{{.FindingLine}}</p>
{{if .Rows}}<details class="group" open><summary>{{.Heading}} ({{len .Rows}})</summary>
<table class="sortable"><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr><td>{{.ID}}</td><td data-sort="{{.SeverityRank}}"><span class="badge {{.SeverityCSS}}">{{.Severity}}</span></td><td>{{if .NameAnchor}}<a href="#{{.NameAnchor}}">{{.Name}}</a>{{else}}{{.Name}}{{end}}</td><td>{{.Installed}}</td><td>{{.FixedIn}}</td><td>{{.EPSS}}</td><td>{{.Risk}}</td><td>{{.KEV}}</td><td>{{.Description}}</td></tr>
{{end}}</table>
</details>{{end}}{{end}}{{end}}

{{define "group"}}<details class="group" id="{{.AnchorID}}"><summary>{{.Title}} <span class="count">({{len .Occurrences}})</span></summary>
<ul class="pkg-meta">
<li>{{.Labels.ComponentID}} — <strong>{{.Name}}</strong>{{if .Version}} {{.Version}}{{end}}</li>
{{range .PURLs}}<li><code>{{.}}</code></li>{{end}}
{{if .VulnLine}}<li>{{.VulnLine}}</li>{{end}}
</ul>
{{$g := .}}{{range .Occurrences}}<div class="occ" id="{{.AnchorID}}">
<div class="occ-hdr"><code>{{.ObjectID}}</code> <span class="muted">· {{$g.Labels.FoundBy}}: {{.FoundBy}}{{if .VulnLine}} · {{.VulnLine}}{{end}}</span></div>
<ul class="occ-paths">
{{range .DeliveryPaths}}<li><em>{{$g.Labels.DeliveryPath}}:</em> {{.}}</li>
{{end}}{{range .Evidence}}<li><em>{{$g.Labels.EvidencePath}}:</em> {{.}}</li>
{{end}}</ul>
</div>
{{end}}</details>{{end}}
`
