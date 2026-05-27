// Package report implements extract-sbom audit report generation.
//
// This file defines report-internal helper types and canonical anchor
// constants. Root report contract types are aliased from the internal model
// package so the root package can act as a thin facade.
package report

import (
	cdx "github.com/CycloneDX/cyclonedx-go"

	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
)

// ToolVersions aliases the shared report tool-version contract from model.
type ToolVersions = model.ToolVersions

// InputSummary aliases the shared input summary contract from model.
type InputSummary = model.InputSummary

// SandboxSummary aliases the shared sandbox summary contract from model.
type SandboxSummary = model.SandboxSummary

// ProcessingIssue aliases the shared processing-issue contract from model.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract from model.
//
//nolint:revive // Stutter is kept intentionally for the root facade API during package extraction.
type ReportData = model.ReportData

// componentOccurrence is one normalized, reportable view of an SBOM component
// with delivery/evidence provenance already flattened for Markdown output.
type componentOccurrence struct {
	// ObjectID is the CycloneDX BOM reference (bom-ref). It is expected to be
	// non-empty for stable anchoring.
	ObjectID string
	// ComponentType is the CycloneDX component type category.
	ComponentType cdx.ComponentType
	// PackageName is the normalized component name used in report output.
	PackageName string
	// Version is the normalized component version. Empty means unknown.
	Version string
	// PURL is the package URL. Empty means this occurrence cannot be matched by
	// package URL-based tooling.
	PURL string
	// CPE is the normalized CPE string when present on the SBOM component.
	// It is used for vulnerability-assessability decisions.
	CPE string
	// DeliveryPaths are logical supplier-delivery paths ("/"-separated,
	// leaf-most, deduplicated). Empty is invalid for indexed occurrences.
	DeliveryPaths []string
	// EvidencePaths are logical evidence file paths ("/"-separated, leaf-most,
	// deduplicated). Empty means no concrete evidence path was recorded.
	EvidencePaths []string
	// EvidenceSource is a plain-text generic evidence statement used when no
	// concrete EvidencePaths are available.
	EvidenceSource string
	// FoundBy identifies the cataloger/source module (for example
	// "java-archive-cataloger"). Empty means unknown.
	FoundBy string
}

// packageOccurrenceGroup groups multiple occurrences that represent the same
// software package identity (name+version) in the delivery.
type packageOccurrenceGroup struct {
	// AnchorID is the package-level report anchor referenced from summary tables.
	AnchorID string
	// PackageName is the normalized package name for this group.
	PackageName string
	// Version is the normalized package version shared by grouped occurrences.
	Version string
	// PURLs contains distinct non-empty package URLs observed across occurrences.
	PURLs []string
	// Occurrences are grouped component occurrences sorted deterministically.
	Occurrences []componentOccurrence
}

// componentIndexStats tracks filtering and indexing counters used to explain
// why certain SBOM components are absent from the occurrence appendix.
type componentIndexStats struct {
	// TotalComponents is the number of BOM components seen before index filters.
	TotalComponents int
	// MissingDeliveryPath counts components skipped because they had no
	// extract-sbom:delivery-path property.
	MissingDeliveryPath int
	// FilteredContainerNodes counts structural extraction/container nodes that
	// are excluded from occurrence indexing.
	FilteredContainerNodes int
	// FilteredAbsolutePathNames counts low-quality components where Name looked
	// like an absolute filesystem path.
	FilteredAbsolutePathNames int
	// FilteredLowValueFileArtifacts counts file entries with insufficient package
	// identity metadata.
	FilteredLowValueFileArtifacts int
	// DuplicateMerged counts occurrences removed by duplicate-collapse rules.
	DuplicateMerged int
	// IndexedComponents is the final number of occurrence entries rendered.
	IndexedComponents int
	// IndexedWithPURL counts rendered occurrences with non-empty PURL.
	IndexedWithPURL int
	// IndexedWithoutPURL counts rendered occurrences with empty PURL.
	IndexedWithoutPURL int
	// IndexedWithEvidencePath counts rendered occurrences with concrete path
	// evidence.
	IndexedWithEvidencePath int
	// IndexedWithEvidenceSourceOnly counts rendered occurrences that have only a
	// generic evidence source text.
	IndexedWithEvidenceSourceOnly int
	// IndexedWithoutEvidence counts rendered occurrences with neither concrete
	// evidence paths nor generic evidence source.
	IndexedWithoutEvidence int
}

// extractionStats summarizes extraction outcomes and records relevant paths for
// each non-success category.
type extractionStats struct {
	// Total is the total number of extraction nodes visited.
	Total int
	// Extracted counts nodes with status extract.StatusExtracted.
	Extracted int
	// TotalFileEntries is the sum of EntriesCount across all extracted nodes,
	// representing the total number of files contained in all extracted archives.
	TotalFileEntries int
	// SyftNative counts nodes handled directly by Syft-native extraction paths.
	SyftNative int
	// Failed counts nodes with terminal extraction failure.
	Failed int
	// Skipped counts nodes skipped by policy/limits.
	Skipped int
	// ToolMissing counts nodes requiring unavailable helper tools.
	ToolMissing int
	// SecurityBlocked counts nodes blocked by security safeguards.
	SecurityBlocked int
	// Pending counts nodes left in pending state.
	Pending int
	// Other counts nodes with an unknown/unmapped status.
	Other int
	// ExtensionFiltered counts files excluded by extension filter across all
	// visited extraction nodes.
	ExtensionFiltered int
	// ExtensionFilteredPaths lists logical paths excluded by extension filter.
	// Values are plain text and may contain duplicates before downstream sorting.
	ExtensionFilteredPaths []string
	// FailedPaths lists logical node paths with failed extraction status.
	FailedPaths []string
	// ToolMissingPaths lists logical node paths requiring unavailable tools.
	ToolMissingPaths []string
	// SecurityBlockedPaths lists logical node paths blocked by security checks.
	SecurityBlockedPaths []string
}

// scanStats summarizes per-node scan outcomes and scan-level coverage gaps.
type scanStats struct {
	// Total is the number of scan tasks in the run.
	Total int
	// Successful is the number of scan tasks without error.
	Successful int
	// Errors is the number of scan tasks with non-nil error.
	Errors int
	// TotalComponents is the sum of component counts over successful scan tasks.
	TotalComponents int
	// NoComponentTasks counts successful scans that produced zero components.
	NoComponentTasks int
	// ErrorPaths lists task node paths for scan failures.
	ErrorPaths []string
	// NoComponentPaths lists task node paths where scans succeeded but returned
	// no package identities.
	NoComponentPaths []string
}

// suppressionStats groups assembly suppression records by normalization reason.
type suppressionStats struct {
	// FSArtifacts counts suppressions flagged as filesystem artifacts.
	FSArtifacts int
	// LowValueFiles counts suppressions flagged as low-value file artifacts.
	LowValueFiles int
	// WeakDuplicate counts suppressions where a stronger sibling record exists.
	WeakDuplicate int
	// PURLDuplicate counts suppressions collapsed by package identity (PURL).
	PURLDuplicate int
}

// policyStats aggregates policy engine decisions for summary tables.
type policyStats struct {
	// Total is the number of policy decisions emitted.
	Total int
	// Continue is the number of decisions with ActionContinue.
	Continue int
	// Skip is the number of decisions with ActionSkip.
	Skip int
	// Abort is the number of decisions with ActionAbort.
	Abort int
}

// processingEntry is a flattened log row used in the processing-issues table.
type processingEntry struct {
	// Source is the producer category: "pipeline", "extraction", or "scan".
	Source string
	// Location is a stage name or logical node path, depending on Source.
	Location string
	// Classification is a compact machine- and human-readable error class.
	Classification string
	// Status is the extraction status name for extraction-source rows.
	Status string
	// DetectedFormat is the detected archive/container format.
	DetectedFormat string
	// Tool is the extractor/scanner tool relevant for this row.
	Tool string
	// ArchiveType is the 7-Zip-reported Type field.
	ArchiveType string
	// ArchiveMethod is the 7-Zip-reported Method field(s).
	ArchiveMethod string
	// Encrypted is a compact yes/no marker from 7-Zip listing metadata.
	Encrypted string
	// PhysicalSize is the 7-Zip-reported physical archive size.
	PhysicalSize string
	// Detail is plain-text diagnostic content.
	Detail string
}

// reportSection defines one TOC entry and heading anchor in the human report.
//
//nolint:unused // Retained for legacy root helpers until remaining human tests move.
type reportSection struct {
	// title is the localized section heading text (plain text).
	title string
	// anchor is the HTML/Markdown anchor id without leading '#'.
	anchor string
	// level encodes nesting depth in the TOC and heading hierarchy.
	// Valid values: 0 (##), 1 (###), 2 (####).
	level int
}

//nolint:unused // Retained for legacy root helpers until remaining human tests move.
const (
	scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

	anchorMethodOverview         = "method-at-a-glance"
	anchorAppendix               = "appendix"
	anchorInputFile              = "input-file"
	anchorConfig                 = "configuration"
	anchorExtensionFilter        = "extension-filter"
	anchorRootMetadata           = "root-sbom-metadata"
	anchorSandbox                = "sandbox-configuration"
	anchorSummary                = "summary"
	anchorProcessingErrors       = "processing-errors"
	anchorResidualRisk           = "residual-risk-and-limitations"
	anchorPolicy                 = "policy-decisions"
	anchorComponentIndex         = "component-occurrence-index"
	anchorComponentsWithPURL     = "components-with-purl"
	anchorComponentsWithoutPURL  = "components-without-purl"
	anchorSuppression            = "component-normalization"
	anchorSuppressionFSArtifacts = "suppression-fs-artifacts"
	anchorSuppressionLowValue    = "suppression-low-value-file-artifacts"
	anchorScan                   = "scan-results"
	anchorScanNoPackageIDs       = "content-items-without-package-identities"
	anchorExtraction             = "extraction-log"
	anchorSummaryAnalysis        = "analysis-overview"
	anchorSummaryKeyFindings     = "key-findings"
	anchorSummaryVuln            = "vulnerability-summary"
)
