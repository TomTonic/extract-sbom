package human

import (
	"fmt"
	"io"
)

// RenderEngine selects the backend used for human Markdown rendering.
type RenderEngine string

const (
	// RenderEngineWriter uses the canonical deterministic writer backend.
	RenderEngineWriter RenderEngine = "writer"
	// RenderEngineTemplateWrapper wraps the canonical report body via a
	// text/template wrapper.
	RenderEngineTemplateWrapper RenderEngine = "template-wrapper"
	// RenderEngineTemplateDocument renders from a caller-supplied
	// document template with pre-rendered section blocks.
	RenderEngineTemplateDocument RenderEngine = "template-document"
)

// RenderOptions configures optional human report rendering backends.
//
// Zero value means deterministic default writer rendering.
type RenderOptions struct {
	Engine RenderEngine
	// WrapperTemplate is used when Engine is template-wrapper.
	WrapperTemplate string
	// DocumentTemplate is used when Engine is template-document.
	DocumentTemplate string
}

// GenerateHumanWithOptions writes the human report using the selected rendering
// backend. Unknown engine values return an error.
func GenerateHumanWithOptions(data ReportData, lang string, w io.Writer, opts RenderOptions) error {
	vm := buildHumanReportViewModel(data, lang)
	engine := opts.Engine
	if engine == "" {
		engine = RenderEngineWriter
	}

	switch engine {
	case RenderEngineWriter:
		return markdownWriterHumanRenderer{}.Render(w, vm)
	case RenderEngineTemplateWrapper:
		return templateWrapperHumanRenderer{wrapperTemplate: opts.WrapperTemplate}.Render(w, vm)
	case RenderEngineTemplateDocument:
		if opts.DocumentTemplate == "" {
			return fmt.Errorf("report: document template must not be empty")
		}
		model := buildHumanTemplateDocumentModel(vm)
		return executeHumanDocumentTemplate(w, model, opts.DocumentTemplate)
	default:
		return fmt.Errorf("report: unsupported human render engine %q", engine)
	}
}
