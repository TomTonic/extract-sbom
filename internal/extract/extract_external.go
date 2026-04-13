package extract

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
	"github.com/TomTonic/extract-sbom/internal/sandbox"
)

// extract7z extracts CAB, MSI, 7z, or RAR files using 7-Zip via the sandbox.
// After extraction, the output directory is validated by safeguard to detect
// path traversal, symlinks, special files, and resource limit violations.
func extract7z(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits) error {
	if !isToolAvailable("7zz") {
		node.Status = StatusToolMissing
		node.StatusDetail = "7zz (7-Zip) is not installed; cannot extract " + node.Format.Format.String()
		node.Tool = "7zz"
		return nil
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-7z-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = "7zz"
	node.SandboxUsed = sb.Name()

	args := []string{"x", filePath, "-o" + outDir, "-y"}
	if err := sb.Run(ctx, "7zz", args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("7zz extraction failed: %v", err)
		return nil
	}

	return finalizeExternalExtraction(node, outDir, limits)
}

// extractUnshield extracts InstallShield CABs using unshield via the sandbox.
// After extraction, the output directory is validated by safeguard to detect
// path traversal, symlinks, special files, and resource limit violations.
func extractUnshield(ctx context.Context, node *ExtractionNode, filePath string, sb sandbox.Sandbox, workDir string, limits config.Limits) error {
	if !isToolAvailable("unshield") {
		node.Status = StatusToolMissing
		node.StatusDetail = "unshield is not installed; cannot extract InstallShield CAB"
		node.Tool = "unshield"
		return nil
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-unshield-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}

	node.Tool = "unshield"
	node.SandboxUsed = sb.Name()

	args := []string{"-d", outDir, "x", filePath}
	if err := sb.Run(ctx, "unshield", args, filePath, outDir); err != nil {
		os.RemoveAll(outDir)
		node.Status = StatusFailed
		node.StatusDetail = fmt.Sprintf("unshield extraction failed: %v", err)
		return nil
	}

	return finalizeExternalExtraction(node, outDir, limits)
}

// finalizeExternalExtraction validates and summarizes an output directory created
// by an external extractor before attaching it to the extraction tree.
func finalizeExternalExtraction(node *ExtractionNode, outDir string, limits config.Limits) error {
	if err := safeguard.ValidatePostExtraction(outDir, limits); err != nil {
		os.RemoveAll(outDir)
		return err
	}

	entriesCount, totalSize, err := summarizeExtractedDir(outDir)
	if err != nil {
		os.RemoveAll(outDir)
		return fmt.Errorf("extract: summarize external extraction output: %w", err)
	}

	node.ExtractedDir = outDir
	node.EntriesCount = entriesCount
	node.TotalSize = totalSize
	node.Status = StatusExtracted
	node.StatusDetail = fmt.Sprintf("extracted %d entries", entriesCount)

	return nil
}

// summarizeExtractedDir walks an extracted directory and returns the count and
// total size of regular files so external-tool extraction metrics match the
// in-process ZIP and TAR extractors.
func summarizeExtractedDir(outDir string) (int, int64, error) {
	entriesCount := 0
	totalSize := int64(0)

	err := filepath.Walk(outDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		entriesCount++
		totalSize += info.Size()
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	return entriesCount, totalSize, nil
}

// isToolAvailable checks whether an external tool can be resolved from PATH.
func isToolAvailable(tool string) bool {
	_, err := lookPath(tool)
	return err == nil
}

// IsToolAvailable exposes tool availability checks for other modules.
func IsToolAvailable(tool string) bool {
	return isToolAvailable(tool)
}

// lookPath is injected in tests to simulate tool presence.
var lookPath = execLookPath

// execLookPath delegates to lookPathImpl to keep a test-swappable boundary.
func execLookPath(file string) (string, error) {
	return lookPathImpl(file)
}

// lookPathImpl performs a minimal PATH search without shelling out.
func lookPathImpl(file string) (string, error) {
	path := os.Getenv("PATH")
	for _, dir := range strings.Split(path, string(os.PathListSeparator)) {
		full := filepath.Join(dir, file)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("executable file not found in $PATH: %s", file)
}
