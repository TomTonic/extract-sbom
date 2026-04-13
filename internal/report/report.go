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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/buildinfo"
	"github.com/TomTonic/extract-sbom/internal/config"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// InputSummary describes the inspected input artifact.
//
// Field constraints:
//   - All hash fields use lowercase hexadecimal encoding.
//   - Size is the exact byte count from os.FileInfo and is never negative.
//   - Empty string values indicate missing input metadata and should not occur
//     in normal orchestrator-driven report generation.
type InputSummary struct {
	// Filename is the base name of the inspected file (no directory prefix).
	// It is copied from os.FileInfo.Name and is plain text.
	Filename string
	// Size is the input size in bytes. Valid range: >= 0.
	Size int64
	// SHA256 is the lowercase hex-encoded SHA-256 digest (64 chars).
	SHA256 string
	// SHA512 is the lowercase hex-encoded SHA-512 digest (128 chars).
	SHA512 string
}

// SandboxSummary describes runtime sandbox behavior for this run.
type SandboxSummary struct {
	// Name identifies the sandbox strategy in plain text (for example
	// "bubblewrap", "nsjail", "passthrough"). It can be empty if unknown.
	Name string
	// Available reports whether the configured sandbox backend was detected and
	// usable at runtime.
	Available bool
	// UnsafeOvr is true when the user explicitly disabled sandbox isolation with
	// --unsafe. This is independent from Available.
	UnsafeOvr bool
}

// ProcessingIssue captures a non-nil error encountered in a pipeline stage.
// The orchestrator collects these so reports document failures deterministically.
type ProcessingIssue struct {
	// Stage is a stable stage identifier (for example "assembly", "scan",
	// "extract"). It is plain text and intended for filtering/grouping.
	Stage string `json:"stage"`
	// Message is the human-readable error detail from the producing module.
	// It is plain text (not Markdown) and may include wrapped upstream errors.
	Message string `json:"message"`
}

// ReportData holds all information needed to generate the audit report.
// It is a read-only snapshot of the processing state taken after all
// extraction, scanning, and assembly is complete.
type ReportData struct { //nolint:revive // stuttering is acceptable for clarity
	// Input is the immutable input fingerprint for this run.
	Input InputSummary
	// Generator is extract-sbom build metadata (version/revision/time/dirty).
	Generator buildinfo.Info
	// Config is the effective runtime configuration snapshot used for processing.
	Config config.Config
	// Tree is the extraction result tree root. Nil means extraction did not
	// produce a root node.
	Tree *extract.ExtractionNode
	// Scans contains one entry per submitted scan task. It may be empty.
	Scans []scan.ScanResult
	// PolicyDecisions contains all policy outcomes in chronological processing
	// order. It may be empty.
	PolicyDecisions []policy.Decision
	// SandboxInfo captures the sandbox mode that was active during this run.
	SandboxInfo SandboxSummary
	// ProcessingIssues contains pipeline-level issues that are not represented
	// solely by extraction or scan status fields. It may be empty.
	ProcessingIssues []ProcessingIssue
	// StartTime is the run start timestamp.
	StartTime time.Time
	// EndTime is the run end timestamp. EndTime should be >= StartTime.
	EndTime time.Time
	// BOM is the assembled final CycloneDX BOM used for component sections.
	// Nil means no final BOM was produced.
	BOM *cdx.BOM
	// SBOMPath is the output path to the written SBOM artifact. It is plain text
	// and may be empty when no SBOM file was written.
	SBOMPath string
	// Suppressions records every component that assembly removed from the SBOM
	// during normalization or deduplication. The report must document each one.
	Suppressions []assembly.SuppressionRecord
}

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
	// Detail is plain-text diagnostic content.
	Detail string
}

// reportSection defines one TOC entry and heading anchor in the human report.
type reportSection struct {
	// title is the localized section heading text (plain text).
	title string
	// anchor is the HTML/Markdown anchor id without leading '#'.
	anchor string
	// level encodes nesting depth in the TOC and heading hierarchy.
	// Valid values: 0 (##), 1 (###), 2 (####).
	level int
}

const (
	scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

	anchorHowToUse               = "how-to-use-this-report"
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
	anchorScanNoPackageIDs       = "scan-tasks-without-package-identities"
	anchorExtraction             = "extraction-log"
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
	t := getTranslations(lang)
	sections := reportSections(t)
	occurrences, indexStats := collectComponentOccurrences(data.BOM)
	extStats := collectExtractionStats(data.Tree)
	scnStats := collectScanStats(data.Scans)
	polStats := collectPolicyStats(data.PolicyDecisions)
	fmt.Fprintf(w, "# %s\n\n", t.title)
	fmt.Fprintf(w, "## %s\n\n", t.tableOfContentsSection)
	writeTableOfContents(w, sections)
	fmt.Fprintln(w)

	// Executive summary and reader guidance.
	writeSectionHeading(w, t.summarySection, anchorSummary)
	writeSummary(w, data, extStats, scnStats, polStats, indexStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.howToUseSection, anchorHowToUse)
	writeHowToUseReport(w, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.methodOverviewSection, anchorMethodOverview)
	writeMethodOverview(w, t)
	fmt.Fprintln(w)

	// Actionable limitations and known blind spots.
	writeSectionHeading(w, t.processingIssuesSection, anchorProcessingErrors)
	writeProcessingIssues(w, data, extStats, scnStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.residualRiskSection, anchorResidualRisk)
	writeResidualRisk(w, data, extStats, scnStats, indexStats, t)
	fmt.Fprintln(w)

	// Appendix: complete raw audit trail.
	writeSectionHeading(w, t.appendixSection, anchorAppendix)
	fmt.Fprintln(w, t.appendixLead)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentIndexSection, anchorComponentIndex)
	writeComponentOccurrenceIndex(w, occurrences, indexStats, t)
	fmt.Fprintln(w)

	writeSectionHeading(w, t.componentNormalizationSection, anchorSuppression)
	writeSuppressionReport(w, data.Suppressions, data.BOM, t)
	fmt.Fprintln(w)

	// Input identification.
	writeSectionHeading(w, t.inputSection, anchorInputFile)
	fmt.Fprintf(w, "| %s | %s |\n", t.field, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | `%s` |\n", t.filename, data.Input.Filename)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.filesize, data.Input.Size, t.unitBytes)
	fmt.Fprintf(w, "| SHA-256 | `%s` |\n", data.Input.SHA256)
	fmt.Fprintf(w, "| SHA-512 | `%s` |\n", data.Input.SHA512)
	fmt.Fprintln(w)

	// Configuration snapshot.
	writeSectionHeading(w, t.configSection, anchorConfig)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.policyMode, data.Config.PolicyMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.interpretMode, data.Config.InterpretMode)
	fmt.Fprintf(w, "| %s | %s |\n", t.language, data.Config.Language)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxDepth, data.Config.Limits.MaxDepth)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxFiles, data.Config.Limits.MaxFiles)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxTotalSize, data.Config.Limits.MaxTotalSize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d %s |\n", t.maxEntrySize, data.Config.Limits.MaxEntrySize, t.unitBytes)
	fmt.Fprintf(w, "| %s | %d |\n", t.maxRatio, data.Config.Limits.MaxRatio)
	fmt.Fprintf(w, "| %s | %s |\n", t.timeout, data.Config.Limits.Timeout)
	fmt.Fprintf(w, "| %s | %s |\n", t.skipExtensions, configSkipExtensionsDisplay(data.Config.SkipExtensions))
	fmt.Fprintf(w, "| %s | %s |\n", t.generator, data.Generator.String())
	fmt.Fprintf(w, "| %s | %s |\n", t.progressLevel, data.Config.ProgressLevel.String())
	fmt.Fprintln(w)

	// Extension filter section: configured list and files excluded in this run.
	writeSectionHeading(w, t.extensionFilterSection, anchorExtensionFilter)
	writeExtensionFilterSection(w, data, extStats, t)
	fmt.Fprintln(w)

	// Root SBOM metadata.
	writeSectionHeading(w, t.rootMetadataSection, anchorRootMetadata)
	writeRootMetadata(w, data, t)

	// Sandbox information.
	writeSectionHeading(w, t.sandboxSection, anchorSandbox)
	fmt.Fprintf(w, "| %s | %s |\n", t.setting, t.value)
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| %s | %s |\n", t.sandboxName, data.SandboxInfo.Name)
	fmt.Fprintf(w, "| %s | %v |\n", t.sandboxAvail, data.SandboxInfo.Available)
	if data.SandboxInfo.UnsafeOvr {
		fmt.Fprintf(w, "| **%s** | **%s** |\n", t.unsafeWarning, t.unsafeActive)
	}
	fmt.Fprintln(w)

	// Policy decisions.
	writeSectionHeading(w, t.policySection, anchorPolicy)
	writePolicyDecisions(w, data.PolicyDecisions, t)
	fmt.Fprintln(w)

	// Scan results.
	writeSectionHeading(w, t.scanSection, anchorScan)
	fmt.Fprintln(w, t.scanSectionLead)
	fmt.Fprintln(w)
	for _, sr := range data.Scans {
		evidencePaths := scan.FlattenEvidencePaths(sr)
		switch {
		case sr.Error != nil:
			fmt.Fprintf(w, "- **%s**: %s %v\n", sr.NodePath, t.scanError, sr.Error)
		case sr.BOM != nil && sr.BOM.Components != nil:
			fmt.Fprintf(w, "- **%s**: %d %s\n", sr.NodePath, len(*sr.BOM.Components), t.componentsFound)
			for _, evidencePath := range evidencePaths {
				fmt.Fprintf(w, "  - %s: `%s`\n", t.scanTaskEvidenceLabel, evidencePath)
			}
		default:
			fmt.Fprintf(w, "- **%s**: %s\n", sr.NodePath, t.noComponents)
		}
	}
	fmt.Fprintln(w)
	writeScanNoPackageIdentitiesSubsection(w, scnStats, t)
	fmt.Fprintln(w)

	// Extraction log.
	writeSectionHeading(w, t.extractionSection, anchorExtraction)
	writeExtractionTree(w, data.Tree, 0, t)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", t.endOfReport)

	return nil
}

// GenerateMachine writes a structured JSON audit report to the writer.
// The JSON schema matches the human-readable report sections for
// downstream automation.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - w: the writer to write the JSON report to
//
// Returns an error if writing fails.
func GenerateMachine(data ReportData, w io.Writer) error {
	report := machineReport{
		SchemaVersion: "1.0.0",
		Input:         data.Input,
		Generator: machineGenerator{
			Version:  data.Generator.Version,
			Revision: data.Generator.Revision,
			Time:     data.Generator.Time,
			Modified: data.Generator.Modified,
			Display:  data.Generator.String(),
		},
		Config: machineConfig{
			PolicyMode:    data.Config.PolicyMode.String(),
			InterpretMode: data.Config.InterpretMode.String(),
			Language:      data.Config.Language,
			Limits: machineLimits{
				MaxDepth:     data.Config.Limits.MaxDepth,
				MaxFiles:     data.Config.Limits.MaxFiles,
				MaxTotalSize: data.Config.Limits.MaxTotalSize,
				MaxEntrySize: data.Config.Limits.MaxEntrySize,
				MaxRatio:     data.Config.Limits.MaxRatio,
				Timeout:      data.Config.Limits.Timeout.String(),
			},
		},
		RootMetadata: machineRootMetadata{
			Manufacturer: data.Config.RootMetadata.Manufacturer,
			Name:         data.Config.RootMetadata.Name,
			Version:      data.Config.RootMetadata.Version,
			DeliveryDate: data.Config.RootMetadata.DeliveryDate,
			Properties:   data.Config.RootMetadata.Properties,
		},
		Sandbox: machineSandbox{
			Name:      data.SandboxInfo.Name,
			Available: data.SandboxInfo.Available,
			Unsafe:    data.SandboxInfo.UnsafeOvr,
		},
		Extraction: buildMachineTree(data.Tree),
		Scans:      buildMachineScans(data.Scans),
		Decisions:  buildMachineDecisions(data.PolicyDecisions),
		Issues:     data.ProcessingIssues,
		StartTime:  data.StartTime.UTC().Format(time.RFC3339),
		EndTime:    data.EndTime.UTC().Format(time.RFC3339),
		Duration:   data.EndTime.Sub(data.StartTime).String(),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// --- Machine-readable report types ---

// machineReport is the JSON root schema written by GenerateMachine.
type machineReport struct {
	// SchemaVersion is the machine-report schema version string.
	SchemaVersion string `json:"schemaVersion"`
	// Input is the input artifact fingerprint used for this run.
	Input InputSummary `json:"input"`
	// Generator is extract-sbom build metadata.
	Generator machineGenerator `json:"generator"`
	// Config is the effective runtime configuration snapshot.
	Config machineConfig `json:"config"`
	// RootMetadata is user-supplied/derived SBOM root metadata.
	RootMetadata machineRootMetadata `json:"rootMetadata"`
	// Sandbox describes sandbox runtime state for the run.
	Sandbox machineSandbox `json:"sandbox"`
	// Extraction is the extraction tree root; nil if not available.
	Extraction *machineNode `json:"extraction"`
	// Scans contains one flattened entry per scan task.
	Scans []machineScan `json:"scans"`
	// Decisions contains policy decisions in processing order.
	Decisions []machineDecision `json:"decisions"`
	// Issues contains additional processing issues. It is omitted when empty.
	Issues []ProcessingIssue `json:"issues,omitempty"`
	// StartTime is UTC RFC3339 text.
	StartTime string `json:"startTime"`
	// EndTime is UTC RFC3339 text.
	EndTime string `json:"endTime"`
	// Duration is Go duration text, for example "1.25s".
	Duration string `json:"duration"`
}

// machineConfig captures the runtime configuration snapshot for machine output.
type machineConfig struct {
	// PolicyMode is policy mode text from config.PolicyMode.String().
	PolicyMode string `json:"policyMode"`
	// InterpretMode is interpretation mode text from config.InterpretMode.String().
	InterpretMode string `json:"interpretMode"`
	// Language is the configured report language code ("en" or "de").
	Language string `json:"language"`
	// Limits is the serialized limits snapshot.
	Limits machineLimits `json:"limits"`
}

// machineGenerator represents extract-sbom build metadata shown in JSON output.
type machineGenerator struct {
	// Version is the build version string.
	Version string `json:"version"`
	// Revision is the VCS revision string; omitted when unknown.
	Revision string `json:"revision,omitempty"`
	// Time is the build timestamp text; omitted when unknown.
	Time string `json:"time,omitempty"`
	// Modified reports whether the build tree was dirty.
	Modified bool `json:"modified"`
	// Display is a human-friendly combined build string.
	Display string `json:"display"`
}

// machineLimits is the serialized representation of configured safety limits.
type machineLimits struct {
	// MaxDepth is the recursion depth limit. Valid range: >= 0.
	MaxDepth int `json:"maxDepth"`
	// MaxFiles is the max-files limit. Valid range: >= 0.
	MaxFiles int `json:"maxFiles"`
	// MaxTotalSize is the aggregate extraction size limit in bytes. >= 0.
	MaxTotalSize int64 `json:"maxTotalSize"`
	// MaxEntrySize is the per-entry extraction size limit in bytes. >= 0.
	MaxEntrySize int64 `json:"maxEntrySize"`
	// MaxRatio is the compression/expansion ratio limit. Valid range: >= 0.
	MaxRatio int `json:"maxRatio"`
	// Timeout is Go duration text from config limits, for example "30s".
	Timeout string `json:"timeout"`
}

// machineRootMetadata stores root component metadata supplied or derived.
type machineRootMetadata struct {
	// Manufacturer is optional root component manufacturer text.
	Manufacturer string `json:"manufacturer,omitempty"`
	// Name is optional root component name text.
	Name string `json:"name,omitempty"`
	// Version is optional root component version text.
	Version string `json:"version,omitempty"`
	// DeliveryDate is optional delivery date text as configured.
	DeliveryDate string `json:"deliveryDate,omitempty"`
	// Properties is optional user-defined key/value metadata.
	Properties map[string]string `json:"properties,omitempty"`
}

// machineSandbox captures sandbox availability and unsafe override state.
type machineSandbox struct {
	// Name is the sandbox strategy identifier.
	Name string `json:"name"`
	// Available reports whether the selected sandbox backend was available.
	Available bool `json:"available"`
	// Unsafe is true when --unsafe disabled isolation.
	Unsafe bool `json:"unsafe"`
}

// machineNode is one extraction-tree node in machine report format.
type machineNode struct {
	// Path is the logical extraction path in supplier-delivery notation.
	Path string `json:"path"`
	// Format is identify.FormatInfo.Format.String().
	Format string `json:"format"`
	// Status is extract status text, for example "extracted" or "failed".
	Status string `json:"status"`
	// StatusDetail is optional plain-text detail for status interpretation.
	StatusDetail string `json:"statusDetail,omitempty"`
	// Tool is the helper/tool name used for this node, when known.
	Tool string `json:"tool,omitempty"`
	// SandboxUsed is the sandbox mode actually used for this node.
	SandboxUsed string `json:"sandboxUsed,omitempty"`
	// Duration is Go duration text for this node.
	Duration string `json:"duration,omitempty"`
	// EntriesCount is the extracted child-entry count. Valid range: >= 0.
	EntriesCount int `json:"entriesCount,omitempty"`
	// TotalSize is the node payload size in bytes. Valid range: >= 0.
	TotalSize int64 `json:"totalSize,omitempty"`
	// Children contains nested extracted nodes. Omitted when empty.
	Children []*machineNode `json:"children,omitempty"`
}

// machineScan is one flattened scan result entry for machine output.
type machineScan struct {
	// NodePath is the logical extraction node path that was scanned.
	NodePath string `json:"nodePath"`
	// ComponentCount is the number of BOM components emitted by this scan task.
	// Valid range: >= 0.
	ComponentCount int `json:"componentCount"`
	// EvidencePaths contains task-level logical evidence paths ("/"-separated).
	// It is omitted when no task-level evidence paths were recorded.
	EvidencePaths []string `json:"evidencePaths,omitempty"`
	// Error contains plain-text task error content. Empty means success.
	Error string `json:"error,omitempty"`
}

// machineDecision is one policy-engine decision in machine-readable form.
type machineDecision struct {
	// Trigger is the policy trigger identifier.
	Trigger string `json:"trigger"`
	// NodePath is the logical extraction node path where trigger fired.
	NodePath string `json:"nodePath"`
	// Action is the policy action string, for example "continue", "skip", "abort".
	Action string `json:"action"`
	// Detail is plain-text diagnostic context for the decision.
	Detail string `json:"detail"`
}

// buildMachineTree converts the extraction tree to the JSON report node model.
func buildMachineTree(node *extract.ExtractionNode) *machineNode {
	if node == nil {
		return nil
	}

	mn := &machineNode{
		Path:         node.Path,
		Format:       node.Format.Format.String(),
		Status:       node.Status.String(),
		StatusDetail: node.StatusDetail,
		Tool:         node.Tool,
		SandboxUsed:  node.SandboxUsed,
		Duration:     node.Duration.String(),
		EntriesCount: node.EntriesCount,
		TotalSize:    node.TotalSize,
	}

	for _, child := range node.Children {
		mn.Children = append(mn.Children, buildMachineTree(child))
	}

	return mn
}

// buildMachineScans projects scan results into a stable machine-report schema.
func buildMachineScans(scans []scan.ScanResult) []machineScan {
	result := make([]machineScan, len(scans))
	for i, s := range scans {
		ms := machineScan{NodePath: s.NodePath}
		if s.Error != nil {
			ms.Error = s.Error.Error()
		}
		if s.BOM != nil && s.BOM.Components != nil {
			ms.ComponentCount = len(*s.BOM.Components)
		}
		ms.EvidencePaths = scan.FlattenEvidencePaths(s)
		result[i] = ms
	}
	return result
}

// buildMachineDecisions converts policy decisions to machine-report entries.
func buildMachineDecisions(decisions []policy.Decision) []machineDecision {
	result := make([]machineDecision, len(decisions))
	for i, d := range decisions {
		result[i] = machineDecision{
			Trigger:  d.Trigger,
			NodePath: d.NodePath,
			Action:   d.Action.String(),
			Detail:   d.Detail,
		}
	}
	return result
}
