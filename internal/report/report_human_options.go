package report

import (
	"io"

	humanpkg "github.com/TomTonic/extract-sbom/internal/report/internal/human"
)

// HumanRenderEngine selects the backend used for human Markdown rendering.
type HumanRenderEngine = humanpkg.RenderEngine

const (
	// HumanRenderEngineWriter uses the canonical deterministic writer backend.
	HumanRenderEngineWriter HumanRenderEngine = humanpkg.RenderEngineWriter
	// HumanRenderEngineTemplateWrapper wraps the canonical report body via a
	// text/template wrapper.
	HumanRenderEngineTemplateWrapper HumanRenderEngine = humanpkg.RenderEngineTemplateWrapper
	// HumanRenderEngineTemplateDocument renders from a caller-supplied
	// document template with pre-rendered section blocks.
	HumanRenderEngineTemplateDocument HumanRenderEngine = humanpkg.RenderEngineTemplateDocument
)

// HumanRenderOptions configures optional human report rendering backends.
//
// Zero value means deterministic default writer rendering.
type HumanRenderOptions = humanpkg.RenderOptions

// GenerateHumanWithOptions writes the human report using the selected rendering
// backend. Unknown engine values return an error.
func GenerateHumanWithOptions(data ReportData, lang string, w io.Writer, opts HumanRenderOptions) error {
	return humanpkg.GenerateHumanWithOptions(data, lang, w, opts)
}
