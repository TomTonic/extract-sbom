// Package human implements the active Markdown-based human report renderer.
package human

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
type ReportData = model.ReportData

// componentOccurrence is one normalized, reportable view of an SBOM component.
type componentOccurrence struct {
	ObjectID       string
	ComponentType  cdx.ComponentType
	PackageName    string
	Version        string
	PURL           string
	CPE            string
	DeliveryPaths  []string
	EvidencePaths  []string
	EvidenceSource string
	FoundBy        string
}

// packageOccurrenceGroup groups multiple occurrences that represent one package.
type packageOccurrenceGroup struct {
	AnchorID    string
	PackageName string
	Version     string
	PURLs       []string
	Occurrences []componentOccurrence
}

// componentIndexStats tracks filtering and indexing counters.
type componentIndexStats struct {
	TotalComponents               int
	MissingDeliveryPath           int
	FilteredContainerNodes        int
	FilteredAbsolutePathNames     int
	FilteredLowValueFileArtifacts int
	DuplicateMerged               int
	IndexedComponents             int
	IndexedWithPURL               int
	IndexedWithoutPURL            int
	IndexedWithEvidencePath       int
	IndexedWithEvidenceSourceOnly int
	IndexedWithoutEvidence        int
}

// extractionStats summarizes extraction outcomes and relevant paths.
type extractionStats struct {
	Total                  int
	Extracted              int
	TotalFileEntries       int
	SyftNative             int
	Failed                 int
	Skipped                int
	ToolMissing            int
	SecurityBlocked        int
	Pending                int
	Other                  int
	ExtensionFiltered      int
	ExtensionFilteredPaths []string
	FailedPaths            []string
	ToolMissingPaths       []string
	SecurityBlockedPaths   []string
}

// scanStats summarizes per-node scan outcomes and coverage gaps.
type scanStats struct {
	Total            int
	Successful       int
	Errors           int
	TotalComponents  int
	NoComponentTasks int
	ErrorPaths       []string
	NoComponentPaths []string
}

// suppressionStats groups suppression records by reason.
type suppressionStats struct {
	FSArtifacts   int
	LowValueFiles int
	WeakDuplicate int
	PURLDuplicate int
}

// policyStats aggregates policy decisions for summary reporting.
type policyStats struct {
	Total    int
	Continue int
	Skip     int
	Abort    int
}

// processingEntry is a flattened log row for the processing-issues table.
type processingEntry struct {
	Source         string
	Location       string
	Classification string
	Status         string
	DetectedFormat string
	Tool           string
	ArchiveType    string
	ArchiveMethod  string
	Encrypted      string
	PhysicalSize   string
	Detail         string
}

// reportSection defines one TOC entry and heading anchor in the human report.
type reportSection struct {
	title  string
	anchor string
	level  int
}

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
