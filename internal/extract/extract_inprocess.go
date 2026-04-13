package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/safeguard"
)

const extractionProgressInterval = 2 * time.Second

// extractZIP extracts a ZIP archive using Go archive/zip.
// Each entry header is validated by safeguard before any bytes are written.
func extractZIP(ctx context.Context, node *ExtractionNode, filePath string, workDir string, limits config.Limits, stats *safeguard.ExtractionStats, cfg config.Config) error {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return fmt.Errorf("extract: open zip %s: %w", filePath, err)
	}
	defer r.Close()

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-zip-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}
	var zipOK bool
	defer func() {
		if !zipOK {
			os.RemoveAll(outDir)
		}
	}()

	node.Tool = "archive/zip"
	sanitizedNames := 0
	nextProgress := time.Now().Add(extractionProgressInterval)

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entryName := sanitizeArchiveEntryName(f.Name)
		if entryName != f.Name {
			sanitizedNames++
		}

		if err := safeguard.ValidatePath(f.Name, outDir); err != nil {
			return err
		}
		if err := safeguard.ValidatePath(entryName, outDir); err != nil {
			return err
		}

		header := safeguard.EntryHeader{
			Name:             entryName,
			UncompressedSize: safeUint64ToInt64(f.UncompressedSize64),
			CompressedSize:   safeUint64ToInt64(f.CompressedSize64),
			Mode:             f.Mode(),
			IsDir:            f.FileInfo().IsDir(),
			IsSymlink:        f.Mode()&os.ModeSymlink != 0,
		}

		if err := safeguard.ValidateEntry(header, limits, stats); err != nil {
			return err
		}

		targetPath := filepath.Join(outDir, filepath.Clean(entryName))

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("extract: create dir %s: %w", targetPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
			return fmt.Errorf("extract: create parent dir for %s: %w", targetPath, err)
		}

		if err := extractZIPEntry(f, targetPath, limits); err != nil {
			return err
		}

		node.EntriesCount++
		node.TotalSize += safeUint64ToInt64(f.UncompressedSize64)

		if time.Now().After(nextProgress) {
			totalGiB := float64(node.TotalSize) / (1024.0 * 1024.0 * 1024.0)
			cfg.EmitProgress(config.ProgressNormal, "[extract] %s: %d files extracted, %.2f GiB unpacked", node.Path, node.EntriesCount, totalGiB)
			nextProgress = time.Now().Add(extractionProgressInterval)
		}
	}

	node.ExtractedDir = outDir
	node.Status = StatusExtracted
	node.StatusDetail = fmt.Sprintf("extracted %d entries", node.EntriesCount)
	if sanitizedNames > 0 {
		node.StatusDetail = fmt.Sprintf("%s (sanitized %d ZIP entry names for filesystem compatibility)", node.StatusDetail, sanitizedNames)
	}
	zipOK = true

	return nil
}

// sanitizeArchiveEntryName converts invalid UTF-8 bytes in archive entry names
// into stable replacement sequences so strict filesystems can materialize them.
func sanitizeArchiveEntryName(name string) string {
	if utf8.ValidString(name) {
		return name
	}

	normalized := strings.ToValidUTF8(name, "_")
	normalized = strings.ReplaceAll(normalized, "\\", "/")
	cleaned := path.Clean(normalized)
	if cleaned == "." {
		return "_"
	}
	return cleaned
}

// extractZIPEntry writes a single ZIP entry to disk with size-bounded copying.
func extractZIPEntry(f *zip.File, targetPath string, limits config.Limits) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("extract: open zip entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("extract: create file %s: %w", targetPath, err)
	}
	defer out.Close()

	limited := io.LimitReader(rc, limits.MaxEntrySize+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("extract: write zip entry %s: %w", f.Name, err)
	}

	if written > limits.MaxEntrySize {
		return &safeguard.ResourceLimitError{
			Limit:   "max-entry-size-actual",
			Current: written,
			Max:     limits.MaxEntrySize,
			Path:    f.Name,
		}
	}

	return nil
}

// extractTAR extracts a TAR archive using Go archive/tar.
// If reader is nil, the file is opened directly.
func extractTAR(ctx context.Context, node *ExtractionNode, filePath string, reader io.Reader, workDir string, limits config.Limits, stats *safeguard.ExtractionStats, cfg config.Config) error {
	if reader == nil {
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("extract: open tar %s: %w", filePath, err)
		}
		defer f.Close()
		reader = f
	}

	outDir, err := os.MkdirTemp(workDir, "extract-sbom-tar-*")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}
	var tarOK bool
	defer func() {
		if !tarOK {
			os.RemoveAll(outDir)
		}
	}()

	node.Tool = "archive/tar"
	nextProgress := time.Now().Add(extractionProgressInterval)

	tr := tar.NewReader(reader)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("extract: read tar entry: %w", err)
		}

		if err := safeguard.ValidatePath(hdr.Name, outDir); err != nil {
			return err
		}

		header := safeguard.EntryHeader{
			Name:             hdr.Name,
			UncompressedSize: hdr.Size,
			Mode:             tarHeaderFileMode(hdr.Mode),
			IsDir:            hdr.Typeflag == tar.TypeDir || strings.HasSuffix(hdr.Name, "/"),
			IsSymlink:        hdr.Typeflag == tar.TypeSymlink,
			LinkTarget:       hdr.Linkname,
		}
		if err := safeguard.ValidateEntry(header, limits, stats); err != nil {
			return err
		}

		targetPath := filepath.Join(outDir, filepath.Clean(hdr.Name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("extract: create dir %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
				return fmt.Errorf("extract: create parent dir for %s: %w", targetPath, err)
			}
			if err := extractTAREntry(tr, targetPath, hdr.Size, limits); err != nil {
				return err
			}
			node.EntriesCount++
			node.TotalSize += hdr.Size
			if time.Now().After(nextProgress) {
				totalGiB := float64(node.TotalSize) / (1024.0 * 1024.0 * 1024.0)
				cfg.EmitProgress(config.ProgressNormal, "[extract] %s: %d files extracted, %.2f GiB unpacked", node.Path, node.EntriesCount, totalGiB)
				nextProgress = time.Now().Add(extractionProgressInterval)
			}
		default:
			continue
		}
	}

	node.ExtractedDir = outDir
	node.Status = StatusExtracted
	node.StatusDetail = fmt.Sprintf("extracted %d entries", node.EntriesCount)
	tarOK = true

	return nil
}

// tarHeaderFileMode converts raw TAR mode bits into os.FileMode while clamping
// to host-supported bit width. This avoids overflow artifacts on malformed
// headers and keeps safeguard checks deterministic.
func tarHeaderFileMode(mode int64) os.FileMode {
	if mode <= 0 {
		return 0
	}

	maxMode := uint64(^os.FileMode(0))
	unsignedMode := uint64(mode)
	if unsignedMode > maxMode {
		unsignedMode = maxMode
	}

	return os.FileMode(unsignedMode)
}

// extractTAREntry writes one regular TAR entry with size-bounded copying.
func extractTAREntry(tr *tar.Reader, targetPath string, size int64, limits config.Limits) error {
	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("extract: create file %s: %w", targetPath, err)
	}
	defer out.Close()

	limited := io.LimitReader(tr, limits.MaxEntrySize+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("extract: write tar entry %s: %w", targetPath, err)
	}

	if written > limits.MaxEntrySize {
		return &safeguard.ResourceLimitError{
			Limit:   "max-entry-size-actual",
			Current: written,
			Max:     limits.MaxEntrySize,
			Path:    targetPath,
		}
	}
	_ = size

	return nil
}

// extractCompressedTAR handles gzip and bzip2 compressed TAR archives.
func extractCompressedTAR(ctx context.Context, node *ExtractionNode, filePath string, compression string, workDir string, limits config.Limits, stats *safeguard.ExtractionStats, cfg config.Config) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("extract: open %s: %w", filePath, err)
	}
	defer f.Close()

	var reader io.Reader
	switch compression {
	case "gzip":
		gr, gerr := gzip.NewReader(f)
		if gerr != nil {
			return fmt.Errorf("extract: create gzip reader: %w", gerr)
		}
		defer gr.Close()
		reader = gr
	case "bzip2":
		reader = bzip2.NewReader(f)
	default:
		return fmt.Errorf("extract: unsupported compression %s", compression)
	}

	return extractTAR(ctx, node, filePath, reader, workDir, limits, stats, cfg)
}

// safeUint64ToInt64 converts uint64 to int64 with clamping to prevent overflow.
func safeUint64ToInt64(v uint64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if v > uint64(maxInt64) {
		return maxInt64
	}
	return int64(v)
}

// isSkippedExtension reports whether filePath ends with an extension present
// in skipList. Matching is case-insensitive.
func isSkippedExtension(filePath string, skipList []string) bool {
	if len(skipList) == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return false
	}
	for _, s := range skipList {
		if strings.EqualFold(s, ext) {
			return true
		}
	}
	return false
}
