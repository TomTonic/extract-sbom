package orchestrator

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/config"
)

// writeReportFile creates path, calls genFn to fill it, and closes it. On
// success it returns true and, when first is non-nil and still empty, sets
// *first to path. On any failure it calls addIssue and updates *fatalErr.
func writeReportFile(
	label, path string,
	first *string,
	fatalErr *error,
	addIssue func(string, error),
	genFn func(io.Writer) error,
) bool {
	f, err := os.Create(path)
	if err != nil {
		addIssue("create-report-"+label, err)
		if *fatalErr == nil {
			*fatalErr = fmt.Errorf("create %s report: %w", label, err)
		}
		return false
	}
	if werr := genFn(f); werr != nil {
		_ = f.Close()
		addIssue("write-report-"+label, werr)
		if *fatalErr == nil {
			*fatalErr = fmt.Errorf("write %s report: %w", label, werr)
		}
		return false
	}
	if cerr := f.Close(); cerr != nil {
		addIssue("close-report-"+label, cerr)
		if *fatalErr == nil {
			*fatalErr = fmt.Errorf("close %s report: %w", label, cerr)
		}
		return false
	}
	if first != nil && *first == "" {
		*first = path
	}
	return true
}

// sbomExtension returns the file extension for the given SBOM format string.
func sbomExtension(format string) string {
	switch format {
	case "cyclonedx-xml":
		return ".cdx.xml"
	case "spdx-json":
		return ".spdx.json"
	default:
		return ".cdx.json"
	}
}

// markdownRenderConfig holds resolved Markdown report renderer options.
type markdownRenderConfig struct {
	Engine   string
	Template string
}

// markdownRenderOptionsFromConfig resolves Markdown report renderer options from
// runtime configuration, including optional template file loading.
func markdownRenderOptionsFromConfig(cfg config.Config) (markdownRenderConfig, error) {
	engine := strings.TrimSpace(cfg.MarkdownRenderEngine)
	if engine == "" || engine == "writer" {
		return markdownRenderConfig{}, nil
	}

	opts := markdownRenderConfig{}
	switch engine {
	case "template-wrapper":
		opts.Engine = "template-wrapper"
	case "template-document":
		opts.Engine = "template-document"
	default:
		return markdownRenderConfig{}, fmt.Errorf("unsupported markdown render engine: %q", engine)
	}

	templateFile := strings.TrimSpace(cfg.MarkdownTemplateFile)
	if templateFile == "" {
		return opts, nil
	}

	raw, err := os.ReadFile(templateFile)
	if err != nil {
		return markdownRenderConfig{}, fmt.Errorf("read markdown template file %q: %w", templateFile, err)
	}
	opts.Template = string(raw)
	return opts, nil
}
