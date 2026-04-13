package extract

import (
	"time"

	"github.com/TomTonic/extract-sbom/internal/identify"
)

// ExtractionStatus represents the outcome of processing an extraction node.
type ExtractionStatus int

const (
	// StatusPending indicates the node has not been processed yet.
	StatusPending ExtractionStatus = iota
	// StatusSyftNative indicates the file is handled directly by Syft.
	StatusSyftNative
	// StatusExtracted indicates the file was successfully extracted.
	StatusExtracted
	// StatusSkipped indicates extraction was skipped due to policy.
	StatusSkipped
	// StatusFailed indicates extraction failed.
	StatusFailed
	// StatusSecurityBlocked indicates extraction was blocked by a hard security violation.
	StatusSecurityBlocked
	// StatusToolMissing indicates the required extraction tool is not available.
	StatusToolMissing
)

// String returns the human-readable name of the extraction status.
func (s ExtractionStatus) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusSyftNative:
		return "syft-native"
	case StatusExtracted:
		return "extracted"
	case StatusSkipped:
		return "skipped"
	case StatusFailed:
		return "failed"
	case StatusSecurityBlocked:
		return "security-blocked"
	case StatusToolMissing:
		return "tool-missing"
	default:
		return "unknown"
	}
}

// ContainerMetadata holds structured product information extracted from
// container formats that carry it (currently: MSI Property table).
type ContainerMetadata struct {
	ProductName    string
	Manufacturer   string
	ProductVersion string
	ProductCode    string
	UpgradeCode    string
	Language       string
}

// ExtractionNode is the central processing data structure.
// Each node represents a container artifact encountered during traversal.
// The tree of nodes forms the extraction state from which both the SBOM
// and audit report are derived.
type ExtractionNode struct {
	Path         string              // physical artifact path relative to delivery root
	OriginalPath string              // absolute filesystem path of the original file
	Format       identify.FormatInfo // detected format of this artifact
	Status       ExtractionStatus    // processing outcome
	StatusDetail string              // human-readable explanation
	ExtractedDir string              // filesystem path of extracted contents (empty if SyftNative)
	Children     []*ExtractionNode   // child nodes from recursive extraction
	Metadata     *ContainerMetadata  // non-nil for formats with structured metadata (MSI)
	// InstallerHint is set when installer-semantic interpretation can provide
	// richer modeling than purely physical extraction paths.
	InstallerHint string
	Tool          string        // extraction tool used
	SandboxUsed   string        // sandbox mechanism used
	Duration      time.Duration // time taken for extraction
	EntriesCount  int           // number of entries extracted
	TotalSize     int64         // total uncompressed size of extracted entries
	// ExtensionFilteredPaths lists delivery paths of direct-child files that were
	// excluded by the configured SkipExtensions filter. They are kept here rather
	// than in Children so the tree stays compact while the audit trail is complete.
	ExtensionFilteredPaths []string
}
