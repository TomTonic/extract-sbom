package report

import (
	"fmt"
	"io"
)

// HumanRenderEngine selects the backend used for human Markdown rendering.
type HumanRenderEngine string

const (
	// HumanRenderEngineWriter uses the canonical deterministic writer backend.
	HumanRenderEngineWriter HumanRenderEngine = "writer"
	// HumanRenderEngineTemplateWrapper wraps the canonical report body via a
	// text/template wrapper.
	HumanRenderEngineTemplateWrapper HumanRenderEngine = "template-wrapper"
	// HumanRenderEngineTemplateDocument renders from a caller-supplied
	// document template with pre-rendered section blocks.
	HumanRenderEngineTemplateDocument HumanRenderEngine = "template-document"
)

// HumanRenderOptions configures optional human report rendering backends.
//
// Zero value means deterministic default writer rendering.
type HumanRenderOptions struct {
	Engine HumanRenderEngine
	// WrapperTemplate is used when Engine is template-wrapper.
	WrapperTemplate string
	// DocumentTemplate is used when Engine is template-document.
	DocumentTemplate string
}

// GenerateHumanWithOptions writes the human report using the selected rendering
// backend. Unknown engine values return an error.
func GenerateHumanWithOptions(data ReportData, lang string, w io.Writer, opts HumanRenderOptions) error {
	vm := buildHumanReportViewModel(data, lang)
	engine := opts.Engine
	if engine == "" {
		engine = HumanRenderEngineWriter
	}

	switch engine {
	case HumanRenderEngineWriter:
		return markdownWriterHumanRenderer{}.Render(w, vm)
	case HumanRenderEngineTemplateWrapper:
		return templateWrapperHumanRenderer{wrapperTemplate: opts.WrapperTemplate}.Render(w, vm)
	case HumanRenderEngineTemplateDocument:
		if opts.DocumentTemplate == "" {
			return fmt.Errorf("report: document template must not be empty")
		}
		model := buildHumanTemplateDocumentModel(vm)
		return executeHumanDocumentTemplate(w, model, opts.DocumentTemplate)
	default:
		return fmt.Errorf("report: unsupported human render engine %q", engine)
	}
}
