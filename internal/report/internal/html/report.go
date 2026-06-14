package html

import "io"

// Generate writes a self-contained HTML audit report to w. The HTML report
// mirrors the content of the Markdown report (sharing the i18n catalog) while
// presenting it with tables and collapsible <details> sections.
func Generate(data ReportData, language string, w io.Writer) error {
	return reportTemplate.Execute(w, buildPage(data, language))
}
