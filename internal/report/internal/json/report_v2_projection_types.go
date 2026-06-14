package json

// This file holds the renderer-facing projection view-model types. The
// builders that populate them live in report_v2_projections*.go.

// ProjectionsV2 holds renderer-oriented view models pre-computed from the entity layer.
// Renderers should consume these projections instead of processing raw or entity data directly.
type ProjectionsV2 struct {
	Summary           ProjectionSummaryV2        `json:"summary"`
	ExtractionLog     []ExtractionLogRowV2       `json:"extractionLog"`
	Scans             []ScanRowV2                `json:"scans"`
	Vulnerabilities   []VulnerabilityRowV2       `json:"vulnerabilities"`
	Issues            []IssueRowV2               `json:"issues"`
	ComponentIndex    []PackageOccurrenceGroupV2 `json:"componentIndex"`
	PolicyDecisions   []PolicyDecisionRowV2      `json:"policyDecisions"`
	SuppressionGroups SuppressionGroupsV2        `json:"suppressionGroups"`
}

// ProjectionSummaryV2 holds strongly-typed aggregated counters.
type ProjectionSummaryV2 struct {
	Nodes                  int                   `json:"nodes"`
	ScanTasks              int                   `json:"scanTasks"`
	Components             int                   `json:"components"`
	PackageGroups          int                   `json:"packageGroups"`
	Vulnerabilities        int                   `json:"vulnerabilities"`
	Suppressions           int                   `json:"suppressions"`
	PolicyDecisions        int                   `json:"policyDecisions"`
	Issues                 int                   `json:"issues"`
	ComponentIndexStats    ComponentIndexStatsV2 `json:"componentIndexStats"`
	ExtensionFilteredPaths []string              `json:"extensionFilteredPaths"`
	ScanNoPackagePaths     []string              `json:"scanNoPackagePaths"`

	VulnerabilityEnrichmentState string              `json:"vulnerabilityEnrichmentState"`
	VulnerabilityRequested       bool                `json:"vulnerabilityRequested"`
	RootComponent                *BOMRootComponentV2 `json:"rootComponent,omitempty"`

	// ArchiveCount is the number of extraction-tree nodes that were expanded as
	// containers (have children). FileCount is the number of leaf nodes (files).
	ArchiveCount int `json:"archiveCount"`
	FileCount    int `json:"fileCount"`

	// AffectedPackageCount is the number of distinct components (by bom-ref) with
	// at least one vulnerability match. UniqueVulnerabilityCount is the number of
	// distinct vulnerability IDs across all matches.
	AffectedPackageCount     int `json:"affectedPackageCount"`
	UniqueVulnerabilityCount int `json:"uniqueVulnerabilityCount"`

	// GrypeProvenance records the Grype scanner and database versions used for
	// vulnerability enrichment, for supply-chain reproducibility. Empty when
	// enrichment did not run.
	GrypeProvenance GrypeProvenanceV2 `json:"grypeProvenance"`
}

// GrypeProvenanceV2 captures the Grype scanner and vulnerability-database
// provenance so a scan can be reproduced and audited.
type GrypeProvenanceV2 struct {
	Version   string `json:"version,omitempty"`
	DBSchema  string `json:"dbSchema,omitempty"`
	DBBuilt   string `json:"dbBuilt,omitempty"`
	DBUpdated string `json:"dbUpdated,omitempty"`
}

// ScanRowV2 is one scan-task projection row with component count and flattened evidence paths.
type ScanRowV2 struct {
	SourceRefs     []string `json:"sourceRefs,omitempty"`
	NodePath       string   `json:"nodePath"`
	ComponentCount int      `json:"componentCount"`
	EvidencePaths  []string `json:"evidencePaths,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// PolicyDecisionRowV2 is one policy-decision projection row.
type PolicyDecisionRowV2 struct {
	SourceRef string `json:"sourceRef,omitempty"`
	Trigger   string `json:"trigger"`
	NodePath  string `json:"nodePath,omitempty"`
	Action    string `json:"action"`
	Detail    string `json:"detail,omitempty"`
}

// SuppressionRowV2 is one suppressed-component projection row with resolved kept-component info.
// KeptAnchorID links to the kept component's entry in the component index when resolution succeeded.
type SuppressionRowV2 struct {
	SourceRef         string `json:"sourceRef,omitempty"`
	DeliveryPath      string `json:"deliveryPath"`
	ComponentName     string `json:"componentName"`
	KeptComponentName string `json:"keptComponentName,omitempty"`
	KeptComponentID   string `json:"keptComponentId,omitempty"`
	KeptAnchorID      string `json:"keptAnchorId,omitempty"`
	ResolutionStatus  string `json:"resolutionStatus"`
	ResolutionReason  string `json:"resolutionReason,omitempty"`
}

// SuppressionGroupsV2 holds suppression rows pre-grouped by suppression reason.
// Rows within each group are sorted deterministically by delivery path then component name.
type SuppressionGroupsV2 struct {
	FSArtifacts []SuppressionRowV2 `json:"fsArtifacts"`
	LowValue    []SuppressionRowV2 `json:"lowValue"`
	WeakDups    []SuppressionRowV2 `json:"weakDups"`
	PURLDups    []SuppressionRowV2 `json:"purlDups"`
}

// BOMRootComponentV2 holds derived root-component metadata from the assembled BOM
// and operator-supplied config properties. BOM fields come from the CycloneDX metadata
// component; ConfigProperties carries the operator key/value pairs from the config.
type BOMRootComponentV2 struct {
	BOMRef           string            `json:"bomRef,omitempty"`
	Name             string            `json:"name,omitempty"`
	Version          string            `json:"version,omitempty"`
	ConfigProperties map[string]string `json:"configProperties,omitempty"`
}

// ComponentIndexStatsV2 holds strongly-typed component index statistics.
type ComponentIndexStatsV2 struct {
	TotalComponents               int `json:"totalComponents"`
	MissingDeliveryPath           int `json:"missingDeliveryPath"`
	FilteredContainerNodes        int `json:"filteredContainerNodes"`
	FilteredAbsolutePathNames     int `json:"filteredAbsolutePathNames"`
	FilteredLowValueFileArtifacts int `json:"filteredLowValueFileArtifacts"`
	DuplicateMerged               int `json:"duplicateMerged"`
	IndexedComponents             int `json:"indexedComponents"`
	IndexedWithPURL               int `json:"indexedWithPurl"`
	IndexedWithoutPURL            int `json:"indexedWithoutPurl"`
	IndexedWithEvidencePath       int `json:"indexedWithEvidencePath"`
	IndexedWithEvidenceSourceOnly int `json:"indexedWithEvidenceSourceOnly"`
	IndexedWithoutEvidence        int `json:"indexedWithoutEvidence"`
}

// ExtractionArchiveMetaV2 holds best-effort archive inspection metadata from 7-Zip.
// All fields are optional; absent fields indicate the metadata was not available.
type ExtractionArchiveMetaV2 struct {
	Type             string   `json:"type,omitempty"`
	Methods          []string `json:"methods,omitempty"`
	HasEncryptedItem bool     `json:"hasEncryptedItem,omitempty"`
	PhysicalSize     string   `json:"physicalSize,omitempty"`
	HeadersSize      string   `json:"headersSize,omitempty"`
	Solid            string   `json:"solid,omitempty"`
	Blocks           string   `json:"blocks,omitempty"`
}

// ExtractionLogRowV2 represents a single extraction event in the log.
type ExtractionLogRowV2 struct {
	SourceRefs       []string `json:"sourceRefs,omitempty"`
	ResolutionStatus string   `json:"resolutionStatus,omitempty"`
	ResolutionReason string   `json:"resolutionReason,omitempty"`

	Path        string                   `json:"path"`
	Status      string                   `json:"status"`
	Format      string                   `json:"format"`
	Tool        string                   `json:"tool"`
	Detail      string                   `json:"detail"`
	Depth       int                      `json:"depth"`
	SandboxUsed string                   `json:"sandboxUsed,omitempty"`
	Duration    string                   `json:"duration,omitempty"`
	ArchiveMeta *ExtractionArchiveMetaV2 `json:"archiveMeta,omitempty"`
}

// VulnerabilityRowV2 represents an aggregated vulnerability display row.
type VulnerabilityRowV2 struct {
	SourceRefs       []string `json:"sourceRefs,omitempty"`
	ResolutionStatus string   `json:"resolutionStatus,omitempty"`
	ResolutionReason string   `json:"resolutionReason,omitempty"`

	PackageAnchorID string   `json:"packageAnchorId,omitempty"`
	PackageKey      string   `json:"packageKey,omitempty"`
	Name            string   `json:"name"`
	Installed       string   `json:"installed"`
	FixedIn         string   `json:"fixedIn,omitempty"`
	VulnerabilityID string   `json:"vulnerabilityId"`
	Severity        string   `json:"severity"`
	CVSSScore       *float64 `json:"cvssScore,omitempty"`
	CVSSVersion     string   `json:"cvssVersion,omitempty"`
	CVSSVector      string   `json:"cvssVector,omitempty"`
	Description     string   `json:"description,omitempty"`
	EPSS            *float64 `json:"epss,omitempty"`
	EPSSPercentile  *float64 `json:"epssPercentile,omitempty"`
	Risk            *float64 `json:"risk,omitempty"`
	KEV             bool     `json:"kev,omitempty"`
}

// IssueRowV2 represents a generic processing or scanning issue.
type IssueRowV2 struct {
	SourceRefs       []string `json:"sourceRefs,omitempty"`
	ResolutionStatus string   `json:"resolutionStatus,omitempty"`
	ResolutionReason string   `json:"resolutionReason,omitempty"`

	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// PackageOccurrenceGroupV2 groups a high-level software package to its constituent occurrences.
type PackageOccurrenceGroupV2 struct {
	SourceRefs       []string `json:"sourceRefs,omitempty"`
	ResolutionStatus string   `json:"resolutionStatus,omitempty"`
	ResolutionReason string   `json:"resolutionReason,omitempty"`

	AnchorID        string            `json:"anchorId"`
	PackageName     string            `json:"packageName"`
	Version         string            `json:"version"`
	PURLs           []string          `json:"purls"`
	OccurrenceCount int               `json:"occurrenceCount"`
	VulnUniqueCount int               `json:"vulnUniqueCount"`
	Occurrences     []OccurrenceRowV2 `json:"occurrences"`
}

// OccurrenceRowV2 lists where a component was exactly found in the extracted files.
type OccurrenceRowV2 struct {
	SourceRefs       []string `json:"sourceRefs,omitempty"`
	ResolutionStatus string   `json:"resolutionStatus,omitempty"`
	ResolutionReason string   `json:"resolutionReason,omitempty"`

	ObjectID       string   `json:"objectId"`
	DeliveryPaths  []string `json:"deliveryPaths"`
	EvidencePaths  []string `json:"evidencePaths"`
	EvidenceSource string   `json:"evidenceSource"`
	FoundBy        string   `json:"foundBy"`
	VulnCount      int      `json:"vulnCount"`
}
