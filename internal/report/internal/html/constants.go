package html

// Section anchors. These mirror the Markdown renderer's anchors so that in-page
// links embedded in shared prose (for example "[Component Occurrence
// Index](#component-occurrence-index)") resolve to the matching HTML elements.
const (
	anchorSummary               = "summary"
	anchorSummaryAnalysis       = "analysis-overview"
	anchorSummaryVuln           = "vulnerability-summary"
	anchorRunScope              = "run-and-scope"
	anchorInputFile             = "input-file"
	anchorConfig                = "configuration"
	anchorSandbox               = "sandbox-configuration"
	anchorMethodOverview        = "method-at-a-glance"
	anchorProcessingErrors      = "processing-errors"
	anchorResidualRisk          = "residual-risk-and-limitations"
	anchorAppendix              = "appendix"
	anchorComponentIndex        = "component-occurrence-index"
	anchorComponentsWithPURL    = "components-with-purl"
	anchorComponentsWithoutPURL = "components-without-purl"
	anchorSuppression           = "component-normalization"
	anchorSuppressionFS         = "suppression-fs-artifacts"
	anchorSuppressionLowValue   = "suppression-low-value-file-artifacts"
	anchorSuppressionWeakDups   = "suppression-weak-duplicates"
	anchorSuppressionPURLDups   = "suppression-purl-duplicates"
	anchorExtensionFilter       = "extension-filter"
	anchorRootMetadata          = "root-sbom-metadata"
	anchorPolicy                = "policy-decisions"
	anchorScan                  = "scan-results"
	anchorScanNoPackageIDs      = "content-items-without-package-identities"
	anchorExtraction            = "extraction-log"
)

// scanApproachGitHubURL is the canonical documentation link used by the Method
// At A Glance and Residual Risk sections. It mirrors the Markdown renderer.
const scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

// Default configuration values, mirrored from the Markdown renderer (which in
// turn mirrors the CLI flag defaults, not config.DefaultConfig()). They drive
// the "(default)" markers in the Configuration table.
const (
	configDefaultPolicyMode      = "partial"
	configDefaultInterpretMode   = "installer-semantic"
	configDefaultLanguage        = "en"
	configDefaultSBOMFormat      = "cyclonedx-json"
	configDefaultReportSelection = "markdown"
	configDefaultMaxDepth        = 6
	configDefaultMaxFiles        = 200000
	configDefaultMaxTotalSize    = int64(20 * 1024 * 1024 * 1024)
	configDefaultMaxEntrySize    = int64(2 * 1024 * 1024 * 1024)
	configDefaultMaxRatio        = 150
	configDefaultTimeout         = "1m0s"
)

// configDefaultSkipExtensions mirrors config.defaultSkipExtensions(); order must
// match for slices.Equal to detect the default list.
var configDefaultSkipExtensions = []string{
	".doc", ".dot",
	".xls", ".xlt", ".xla",
	".ppt", ".pot", ".pps", ".ppa",
	".vsd", ".vss", ".vst",
	".msg", ".pub", ".mdb",
	".docx", ".docm", ".dotx", ".dotm",
	".xlsx", ".xlsm", ".xltx", ".xltm",
	".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
	".vsdx", ".vsdm",
	".odt", ".ods", ".odp", ".odg", ".odf",
	".pdf",
}

// suppressionTableMaxRows bounds suppression tables, mirroring the Markdown
// renderer so both outputs document the same (bounded) row set.
const suppressionTableMaxRows = 30
