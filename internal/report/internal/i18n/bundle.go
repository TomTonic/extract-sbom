// Package i18n holds the localized label and prose catalog shared by the report
// renderers, together with a small inline-Markdown-to-HTML converter so the HTML
// renderer can reuse the Markdown-flavored catalog strings.
package i18n

// Bundle contains all localized report labels and prose snippets shared by the
// Markdown and HTML report renderers.
//
// Contract for string fields in this struct:
//   - Values are authored as plain text or inline Markdown fragments (for
//     example links "[text](url)", inline code spans, or "**bold**"). The
//     Markdown renderer emits them verbatim; the HTML renderer converts the
//     inline Markdown to HTML via RenderInlineHTML.
//   - Values must not depend on runtime locale APIs.
//   - Fields ending with "Template" are consumed via fmt.Sprintf and must keep
//     placeholder count/order compatible with their call sites.
//   - Fields ending with "Section", "Label", "Header", "Reason" or "Value"
//     are short UI strings (single-line headings/cell labels).
//   - The NoneValue fallback should be a short, language-localized token used
//     when no sample/path value exists.
//
// For must return a fully populated bundle (no zero-value gaps) for every
// supported language. Unknown language codes intentionally fall back to English.
type Bundle struct {
	Title                                  string
	InputSection                           string
	ConfigSection                          string
	RootMetadataSection                    string
	SandboxSection                         string
	ExtractionSection                      string
	ScanSection                            string
	ScanSectionLead                        string
	ScanTaskEvidenceLabel                  string
	ScanNoPackageIDsSection                string
	ScanNoPackageIDsLead                   string
	NoScanNoPackageIDs                     string
	PolicySection                          string
	RunScopeSection                        string
	RunScopeLead                           string
	SummarySection                         string
	ResidualRiskSection                    string
	ProcessingIssuesSection                string
	Field                                  string
	Value                                  string
	Source                                 string
	Setting                                string
	Filename                               string
	Filesize                               string
	RunIDLabel                             string
	RunStartedLabel                        string
	RunEndedLabel                          string
	UnitBytes                              string
	SkipExtensions                         string
	NameLabel                              string
	ManufacturerLabel                      string
	DeliveryDateLabel                      string
	PolicyMode                             string
	InterpretMode                          string
	Language                               string
	MaxDepth                               string
	MaxFiles                               string
	MaxTotalSize                           string
	MaxEntrySize                           string
	MaxRatio                               string
	Timeout                                string
	ProgressLevel                          string
	Generator                              string
	SandboxName                            string
	SandboxAvail                           string
	SandboxIsolationLabel                  string
	SandboxActiveValue                     string
	SandboxUnsafeIgnoredNote               string
	SandboxNoBwrapUnsafe                   string
	SandboxNoBwrapDenied                   string
	TableOfContentsSection                 string
	MethodOverviewSection                  string
	AppendixSection                        string
	ComponentIndexSection                  string
	ComponentIndexLead                     string
	NoIndexedComponents                    string
	ObjectID                               string
	PackageName                            string
	Version                                string
	Purl                                   string
	EvidencePath                           string
	FoundBy                                string
	NoEvidenceRecorded                     string
	ScanError                              string
	ComponentsFound                        string
	NoComponents                           string
	DeliveryPath                           string
	Status                                 string
	Tool                                   string
	Duration                               string
	SuppliedBy                             string
	Derived                                string
	ResidualRiskText                       string
	ResidualRiskProfileLead                string
	ResidualRiskAbsenceHint                string
	ResidualRiskPURLCoverage               string
	ResidualRiskEvidenceCoverage           string
	ResidualRiskNoComponentTasks           string
	ResidualRiskFileArtifactCoverage       string
	ResidualRiskExtensionFilter            string
	ResidualRiskExtractionGap              string
	ResidualRiskToolGap                    string
	ResidualRiskScanGap                    string
	ResidualRiskMoreDetails                string
	NoPolicyDecisions                      string
	NoProcessingIssues                     string
	SummaryLead                            string
	SummaryLeadNoVuln                      string
	VulnEnrichmentNotRequested             string
	VulnEnrichmentStateTemplate            string
	VulnGrypeVersionTemplate               string
	VulnGrypeDBTemplate                    string
	VulnEnrichmentIssuesTemplate           string
	VulnFindingsTemplate                   string
	VulnNoMatchedFindings                  string
	VulnSummaryHeading                     string
	FindingVulnNotRequested                string
	OverviewCompositionTemplate            string
	OverviewInventoryTemplate              string
	OverviewPURLTemplate                   string
	OverviewVulnMatchesTemplate            string
	OverviewVulnNone                       string
	FindingExtractionStatusSuccessTemplate string
	FindingExtractionStatusFailureTemplate string
	ReportHeaderGeneratorVersionTemplate   string
	ReportHeaderToolsLabel                 string
	VulnTableName                          string
	VulnTableInstalled                     string
	VulnTableFixedIn                       string
	VulnTableVulnerability                 string
	VulnTableSeverity                      string
	VulnTableEPSS                          string
	VulnTableRisk                          string
	VulnTableKEV                           string
	VulnTableDescription                   string
	VulnStatusFoundTemplate                string
	VulnStatusNotAssessableUnavailable     string
	VulnStatusNotAssessableNoID            string
	VulnStatusNone                         string
	VulnDetailSourceTemplate               string
	VulnDetailFixTemplate                  string
	VulnDetailCVSSTemplate                 string
	VulnDetailCVSSNone                     string
	VulnDetailDescriptionTemplate          string
	VulnDetailDescriptionNone              string
	VulnDetailEPSSTemplate                 string
	VulnDetailReferenceTemplate            string
	VulnKEVYes                             string
	VulnKEVNo                              string
	MethodLead                             string
	MethodBulletTwoPhases                  string
	MethodBulletEvidence                   string
	MethodBulletDedup                      string
	MethodBulletTrust                      string
	AppendixLead                           string
	SummaryAnalysisSection                 string
	SummaryVulnSection                     string
	EndOfReport                            string
	PolicyDecisionAt                       string
	LinkTwoPhases                          string
	LinkScanDetail                         string
	LinkFinalSBOMBuild                     string
	LinkDeduplication                      string
	LinkPackageDetectionReliability        string
	SummaryAnalysisMethodRef               string
	FindingToolMissingTemplate             string
	FindingExtractionGapTemplate           string
	FindingScanFailedTemplate              string
	FindingNoPackageIdentityTemplate       string
	FindingNoCriticalLimitations           string
	FindingPolicyDecisionsTemplate         string
	FindingProcessingIssuesTemplate        string
	ProcessingPipelineLabel                string
	ProcessingExtractionFailedLabel        string
	ProcessingSecurityBlockedLabel         string
	ProcessingToolMissingLabel             string
	ProcessingTimeoutLabel                 string
	ProcessingPasswordRequiredLabel        string
	ProcessingFormatMismatchLabel          string
	ProcessingCorruptLabel                 string
	ProcessingScanErrorsLabel              string
	ProcessingSourceHeader                 string
	ProcessingLocationHeader               string
	ProcessingClassHeader                  string
	ProcessingStatusHeader                 string
	ProcessingDetectedHeader               string
	ProcessingToolHeader                   string
	ProcessingArchiveTypeHeader            string
	ProcessingArchiveMethodHeader          string
	ProcessingEncryptedHeader              string
	ProcessingPhysicalSizeHeader           string
	ProcessingDetailHeader                 string
	AdditionalEntriesOmittedTemplate       string
	NoneValue                              string
	ReasonLabel                            string
	CountLabel                             string
	DescriptionLabel                       string
	SuppressionOperationalFS               string
	SuppressionOperationalFSFollowUp       string
	SuppressionOperationalLowValue         string
	SuppressionOperationalWeakDup          string
	SuppressionOperationalPURLDup          string
	SuppressionTableDeliveryPath           string
	SuppressionTableComponentName          string
	SuppressionTableSuppressedBy           string
	ExtractionSandboxLabel                 string

	ComponentNormalizationSection       string
	ComponentNormalizationLead          string
	NoSuppressions                      string
	SuppressionReasonFSArtifact         string
	SuppressionReasonLowValueFile       string
	SuppressionReasonWeakDuplicate      string
	SuppressionReasonPURLDuplicate      string
	SuppressionReplacedBy               string
	SuppressionDescriptionFSArtifact    string
	SuppressionDescriptionLowValueFile  string
	SuppressionDescriptionWeakDuplicate string
	SuppressionDescriptionPURLDuplicate string

	ExtensionFilterSection              string
	ExtensionFilterLead                 string
	ExtensionFilterExtensionsLabel      string
	ExtensionFilterSkippedLabel         string
	NoExtensionFilteredFiles            string
	ComponentIndexWithPURLSubsection    string
	ComponentIndexWithoutPURLSubsection string
	OccurrencesLabel                    string
	PurlsLabel                          string
	ComponentIDLabel                    string
	SuppressedByNoIndexedMatch          string
	SuppressedByAmbiguousIndexedMatch   string
	SuppressedByReplacementNotIndexed   string
}

// For returns the translation bundle for the requested language, defaulting to
// English when an unknown code is provided. It must return a fully populated
// bundle (no zero-value gaps) for every supported language.
func For(lang string) Bundle {
	switch lang {
	case "de":
		return german()
	default:
		return english()
	}
}
