// Package report generates audit reports from the processing state.
// It supports human-readable Markdown output and machine-readable JSON output,
// in English or German. The report documents everything that was processed,
// how, and with what limitations — enabling a third party to assess the
// completeness and reliability of the inspection.
package report

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	htmlpkg "github.com/TomTonic/extract-sbom/internal/report/internal/html"
	humanpkg "github.com/TomTonic/extract-sbom/internal/report/internal/human"
)

// ComputeInputSummary computes the file hashes and metadata for the input file.
// This is called once by the orchestrator before any processing begins.
//
// Parameters:
//   - path: the filesystem path to the input file
//
// Returns an InputSummary with filename, size, SHA-256, and SHA-512 hashes
// (all lowercase hex), or an error if the file cannot be read.
func ComputeInputSummary(path string) (InputSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return InputSummary{}, fmt.Errorf("report: open input: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return InputSummary{}, fmt.Errorf("report: stat input: %w", err)
	}

	h256 := sha256.New()
	h512 := sha512.New()
	w := io.MultiWriter(h256, h512)

	if _, err := io.Copy(w, f); err != nil {
		return InputSummary{}, fmt.Errorf("report: hash input: %w", err)
	}

	return InputSummary{
		Filename: info.Name(),
		Size:     info.Size(),
		SHA256:   hex.EncodeToString(h256.Sum(nil)),
		SHA512:   hex.EncodeToString(h512.Sum(nil)),
	}, nil
}

// GenerateHuman writes a human-readable Markdown audit report to the writer.
// The report follows the structure required by DESIGN.md §10.4.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - lang: the output language ("en" or "de")
//   - w: the writer to write the Markdown report to
//
// Returns an error if writing fails.
func GenerateHuman(data ReportData, lang string, w io.Writer) error {
	return GenerateHumanWithOptions(data, lang, w, HumanRenderOptions{})
}

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

// GenerateHTML writes a self-contained HTML audit report to w.
func GenerateHTML(data ReportData, language string, w io.Writer) error {
	return htmlpkg.Generate(data, language, w)
}
