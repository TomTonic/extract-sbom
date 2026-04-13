package extract

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/identify"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

// Extract recursively processes the given file according to configuration.
// It builds and returns the root ExtractionNode tree representing the
// full extraction state. The tree is the single source of truth for what
// was processed, how, and with what outcome.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - inputPath: absolute filesystem path to the input file
//   - cfg: the run configuration (limits, policy, interpretation mode)
//   - sb: the sandbox to use for external tool invocations
//
// Returns the root ExtractionNode or an error if the initial file cannot
// be processed at all.
func Extract(ctx context.Context, inputPath string, cfg config.Config, sb sandbox.Sandbox) (*ExtractionNode, error) {
	baseName := filepath.Base(inputPath)
	root := &ExtractionNode{
		Path:         baseName,
		OriginalPath: inputPath,
	}

	stats := &safeguard.ExtractionStats{}
	if err := extractRecursive(ctx, root, inputPath, baseName, 0, cfg, sb, stats); err != nil {
		// If we have a tree at all, return it with the error info.
		return root, err
	}

	return root, nil
}

// extractRecursive processes exactly one artifact node and, when extraction
// succeeds, descends into its extracted directory.
//
// Why this exists:
// It centralizes status assignment order (syft-native, extracted, skipped,
// failed, security-blocked, tool-missing) so behavior is consistent with
// DESIGN.md and SCAN_APPROACH.md semantics.
//
// Constraints:
// - depth limit is enforced before format handling
// - hard security errors are propagated (policy may decide continuation)
// - per-extraction timeout applies to one archive operation
func extractRecursive(ctx context.Context, node *ExtractionNode, filePath string, deliveryPath string,
	depth int, cfg config.Config, sb sandbox.Sandbox, stats *safeguard.ExtractionStats) error {
	if depth > cfg.Limits.MaxDepth {
		node.Status = StatusSkipped
		node.StatusDetail = fmt.Sprintf("depth limit %d exceeded", cfg.Limits.MaxDepth)
		return &safeguard.ResourceLimitError{
			Limit:   "max-depth",
			Current: int64(depth),
			Max:     int64(cfg.Limits.MaxDepth),
			Path:    deliveryPath,
		}
	}

	info, err := identify.Identify(ctx, filePath)
	if err != nil {
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("format identification failed: %v", err)
		return nil
	}
	node.Format = info

	if isSkippedExtension(filePath, cfg.SkipExtensions) {
		ext := strings.ToLower(filepath.Ext(filePath))
		node.Status = StatusSkipped
		node.StatusDetail = "extension filter: " + ext + " is excluded from extraction"
		return nil
	}

	if info.SyftNative {
		node.Status = StatusSyftNative
		node.Tool = "syft"
		node.StatusDetail = fmt.Sprintf("Syft-native format (%s), passed directly to Syft", info.Format)
		return nil
	}

	if info.Format == identify.Unknown {
		node.Status = StatusSkipped
		node.StatusDetail = "not a recognized container format"
		return nil
	}

	start := time.Now()

	extractCtx := ctx
	if cfg.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		extractCtx, cancel = context.WithTimeout(ctx, cfg.Limits.Timeout)
		defer cancel()
	}

	switch info.Format {
	case identify.ZIP:
		err = extractZIP(extractCtx, node, filePath, cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.TAR:
		err = extractTAR(extractCtx, node, filePath, nil, cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.GzipTAR:
		err = extractCompressedTAR(extractCtx, node, filePath, "gzip", cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.Bzip2TAR:
		err = extractCompressedTAR(extractCtx, node, filePath, "bzip2", cfg.WorkDir, cfg.Limits, stats, cfg)
	case identify.XzTAR, identify.ZstdTAR:
		err = extract7z(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	case identify.CAB, identify.SevenZip, identify.RAR:
		err = extract7z(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	case identify.MSI:
		if meta, msiErr := ReadMSIMetadata(filePath, cfg.Limits.MaxEntrySize); msiErr == nil {
			node.Metadata = meta
		}
		if cfg.InterpretMode == config.InterpretInstallerSemantic && node.Metadata != nil {
			node.InstallerHint = "msi-file-table-remapping-available"
		}
		err = extract7z(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	case identify.InstallShieldCAB:
		err = extractUnshield(extractCtx, node, filePath, sb, cfg.WorkDir, cfg.Limits)
	default:
		node.Status = StatusSkipped
		node.StatusDetail = fmt.Sprintf("no extraction handler for format %s", info.Format)
		return nil
	}

	node.Duration = time.Since(start)

	if err != nil {
		if extractCtx.Err() == context.DeadlineExceeded {
			node.Status = StatusFailed
			node.StatusDetail = fmt.Sprintf("per-extraction timeout (%s) exceeded", cfg.Limits.Timeout)
			return &safeguard.ResourceLimitError{
				Limit:   "timeout",
				Current: int64(node.Duration.Seconds()),
				Max:     int64(cfg.Limits.Timeout.Seconds()),
				Path:    deliveryPath,
			}
		}
		if _, ok := err.(*safeguard.HardSecurityError); ok {
			node.Status = StatusSecurityBlocked
			node.StatusDetail = err.Error()
			return err
		}
		if _, ok := err.(*safeguard.ResourceLimitError); ok {
			node.Status = StatusFailed
			node.StatusDetail = err.Error()
			return err
		}
		if node.Status == StatusPending {
			node.Status = StatusFailed
			node.StatusDetail = err.Error()
		}
		return nil
	}

	if node.ExtractedDir != "" {
		if walkErr := recurseIntoDir(ctx, node, node.ExtractedDir, deliveryPath, depth+1, cfg, sb, stats); walkErr != nil {
			return walkErr
		}
	}

	return nil
}

// recurseIntoDir enumerates extracted files and attaches child container nodes
// to the current parent node.
//
// Why this exists:
// It enforces policy behavior (strict vs partial) for resource/security errors
// at child level while keeping an auditable tree of encountered artifacts.
func recurseIntoDir(ctx context.Context, parent *ExtractionNode, dir string, parentDeliveryPath string,
	depth int, cfg config.Config, sb sandbox.Sandbox, stats *safeguard.ExtractionStats) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("extract: read dir %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subDir := filepath.Join(dir, entry.Name())
			if walkErr := recurseIntoDir(ctx, parent, subDir, parentDeliveryPath+"/"+entry.Name(), depth, cfg, sb, stats); walkErr != nil {
				return walkErr
			}
			continue
		}

		childPath := filepath.Join(dir, entry.Name())
		childDeliveryPath := parentDeliveryPath + "/" + entry.Name()

		child := &ExtractionNode{Path: childDeliveryPath, OriginalPath: childPath}

		if err := extractRecursive(ctx, child, childPath, childDeliveryPath, depth, cfg, sb, stats); err != nil {
			if _, ok := err.(*safeguard.HardSecurityError); ok {
				child.Status = StatusSecurityBlocked
				child.StatusDetail = err.Error()
				if cfg.PolicyMode == config.PolicyPartial {
					parent.Children = append(parent.Children, child)
					continue
				}
				parent.Children = append(parent.Children, child)
				return err
			}
			if _, ok := err.(*safeguard.ResourceLimitError); ok {
				if cfg.PolicyMode == config.PolicyPartial {
					parent.Children = append(parent.Children, child)
					continue
				}
				parent.Children = append(parent.Children, child)
				return err
			}
		}

		if child.Status == StatusSkipped && strings.HasPrefix(child.StatusDetail, "extension filter:") {
			parent.ExtensionFilteredPaths = append(parent.ExtensionFilteredPaths, child.Path)
			continue
		}

		if child.Status != StatusSkipped || len(child.Children) > 0 {
			parent.Children = append(parent.Children, child)
		}
	}

	return nil
}

// CleanupNode removes all temporary directories created during extraction.
// It walks the tree and removes ExtractedDir for each node that was extracted.
// Call this after all processing (scan, assembly, report) is complete.
//
// Parameters:
//   - node: the root of the extraction tree to clean up
func CleanupNode(node *ExtractionNode) {
	if node == nil {
		return
	}
	if node.ExtractedDir != "" {
		os.RemoveAll(node.ExtractedDir)
	}
	for _, child := range node.Children {
		CleanupNode(child)
	}
}
