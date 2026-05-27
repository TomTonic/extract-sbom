package report

import (
	"io"

	humanpkg "github.com/TomTonic/extract-sbom/internal/report/internal/human"
)

// GenerateHumanWithTemplate writes the human report through an optional
// text/template wrapper. The wrapper receives one field, Body, containing the
// complete deterministic Markdown report produced by the default writer engine.
//
// When wrapperTemplate is empty, "{{.Body}}" is used.
func GenerateHumanWithTemplate(data ReportData, lang string, w io.Writer, wrapperTemplate string) error {
	return humanpkg.GenerateHumanWithTemplate(data, lang, w, wrapperTemplate)
}

// GenerateHumanWithTemplateDocument renders the human report using a
// caller-provided text/template fed with pre-rendered Markdown section blocks.
//
// This optional API enables structural customization (for example reordered
// sections or custom framing) while preserving deterministic section content
// generation from the canonical writer helpers.
func GenerateHumanWithTemplateDocument(data ReportData, lang string, w io.Writer, documentTemplate string) error {
	return humanpkg.GenerateHumanWithTemplateDocument(data, lang, w, documentTemplate)
}
