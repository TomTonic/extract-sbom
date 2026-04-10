// Package scan invokes Syft in library mode to catalog software components.
// It operates on two distinct node types from the extraction tree:
//   - SyftNative leaves: Syft scans the original file (e.g., JAR, RPM)
//   - Extracted directories: Syft scans the extraction output directory
//
// The scan module produces per-node CycloneDX BOMs that are later merged
// by the assembly module into a single consolidated SBOM.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"

	"github.com/sbom-sentry/internal/config"
	"github.com/sbom-sentry/internal/extract"
)

// ScanResult holds the CycloneDX BOM produced by scanning a single
// extraction node, along with metadata linking it back to the tree.
type ScanResult struct { //nolint:revive // stuttering is acceptable for clarity
	NodePath string   // matches ExtractionNode.Path
	BOM      *cdx.BOM // CycloneDX BOM for this subtree/file
	Error    error    // non-nil if scanning failed
}

// Version is the sbom-sentry version string, set at build time.
var Version = "dev"

// ScanAll walks the extraction tree and invokes Syft on each scannable node.
// SyftNative leaves are scanned using the original file path; extracted
// directories are scanned at their extraction output path.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - root: the root of the extraction tree from extract.Extract
//   - cfg: the run configuration
//
// Returns a slice of ScanResults (one per scannable node) and an error
// only if the overall scan operation cannot proceed. Per-node failures
// are captured in individual ScanResult.Error fields.
func ScanAll(ctx context.Context, root *extract.ExtractionNode, cfg config.Config) ([]ScanResult, error) { //nolint:revive // stuttering is acceptable
	var results []ScanResult
	collectScanTargets(root, &results)

	for i := range results {
		scanNode(ctx, &results[i], root)
	}

	return results, nil
}

// collectScanTargets walks the extraction tree and identifies nodes that
// should be scanned by Syft.
func collectScanTargets(node *extract.ExtractionNode, results *[]ScanResult) {
	if node == nil {
		return
	}

	switch node.Status {
	case extract.StatusSyftNative:
		*results = append(*results, ScanResult{NodePath: node.Path})
	case extract.StatusExtracted:
		*results = append(*results, ScanResult{NodePath: node.Path})
	}

	for _, child := range node.Children {
		collectScanTargets(child, results)
	}
}

// findNode locates a node in the tree by path.
func findNode(root *extract.ExtractionNode, path string) *extract.ExtractionNode {
	if root.Path == path {
		return root
	}
	for _, child := range root.Children {
		if n := findNode(child, path); n != nil {
			return n
		}
	}
	return nil
}

// scanNode performs the actual Syft scan for a single node.
func scanNode(ctx context.Context, result *ScanResult, root *extract.ExtractionNode) {
	node := findNode(root, result.NodePath)
	if node == nil {
		result.Error = fmt.Errorf("scan: node %s not found in tree", result.NodePath)
		return
	}

	// Determine the target path for Syft.
	var target string
	switch node.Status {
	case extract.StatusSyftNative:
		target = node.OriginalPath
	case extract.StatusExtracted:
		target = node.ExtractedDir
	default:
		result.Error = fmt.Errorf("scan: node %s has unexpected status %s", node.Path, node.Status)
		return
	}

	// Verify target exists.
	if _, err := os.Stat(target); err != nil {
		result.Error = fmt.Errorf("scan: target %s does not exist: %w", target, err)
		return
	}

	// Create Syft source.
	src, err := syft.GetSource(ctx, target, nil)
	if err != nil {
		result.Error = fmt.Errorf("scan: get source for %s: %w", target, err)
		return
	}
	defer src.Close()

	// Create SBOM using Syft.
	syftSBOM, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		result.Error = fmt.Errorf("scan: syft SBOM creation for %s: %w", target, err)
		return
	}

	// Encode Syft's internal SBOM to CycloneDX JSON.
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		result.Error = fmt.Errorf("scan: create CycloneDX encoder: %w", err)
		return
	}

	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *syftSBOM); err != nil {
		result.Error = fmt.Errorf("scan: encode SBOM to CycloneDX JSON for %s: %w", target, err)
		return
	}

	// Decode CycloneDX JSON into cyclonedx-go types.
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		// Try plain JSON decode as fallback.
		bom = new(cdx.BOM)
		if jerr := json.Unmarshal(buf.Bytes(), bom); jerr != nil {
			result.Error = fmt.Errorf("scan: decode CycloneDX BOM for %s: %w (json fallback: %v)", target, err, jerr)
			return
		}
	}

	result.BOM = bom
}
