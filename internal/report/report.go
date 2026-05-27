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
	"runtime/debug"
	"strings"
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
	vm := buildHumanReportViewModel(data, lang)
	return markdownWriterHumanRenderer{}.Render(w, vm)
}

// generatorGitHubURL returns a GitHub URL for the given generator version string.
// For clean release tags (e.g. v1.2.3) it points to the release page;
// for pseudo-versions (e.g. v0.4.1-0.20260508110356-abcdef012345) it points
// to the specific commit. A +dirty suffix is stripped before evaluation.
func generatorGitHubURL(version string) string {
	const repoBase = "https://github.com/TomTonic/extract-sbom"
	v := strings.TrimSuffix(version, "+dirty")
	// Pseudo-version: vX.Y.Z-0.YYYYMMDDHHMMSS-COMMITHASH — hash is the last segment.
	if idx := strings.LastIndex(v, "-"); idx != -1 {
		hash := v[idx+1:]
		if len(hash) >= 12 {
			return repoBase + "/commit/" + hash
		}
	}
	// Clean release tag or unrecognised pattern.
	if strings.HasPrefix(v, "v") {
		return repoBase + "/releases/tag/" + v
	}
	return repoBase
}

// getSyftVersion reads the Syft dependency version from build info at runtime.
// If Syft is not found in the dependencies, returns an empty string.
func getSyftVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		return ""
	}
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/anchore/syft" {
			return dep.Path + " " + dep.Version
		}
	}
	return ""
}
