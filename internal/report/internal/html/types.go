// Package html implements the self-contained HTML report renderer. It mirrors
// the content of the Markdown report (sharing the i18n catalog) while presenting
// it with HTML-native affordances: tables and collapsible <details> sections.
package html

import (
	htmltmpl "html/template"

	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
)

// ToolVersions aliases the shared report tool-version contract from model.
type ToolVersions = model.ToolVersions

// ReportData aliases the shared report snapshot contract from model.
type ReportData = model.ReportData

// page is the top-level template model for the HTML report.
type page struct {
	Lang       string
	Title      string
	Meta       htmltmpl.HTML
	Tools      htmltmpl.HTML
	TOC        []tocItem
	TOCHeading string
	EndNote    string

	// Summary
	SummaryHeading  string
	SummaryAnchor   string
	SummaryLead     htmltmpl.HTML
	AnalysisHeading string
	AnalysisAnchor  string
	AnalysisParas   []htmltmpl.HTML
	Vuln            vulnSection

	// Run & Scope
	RunScopeHeading string
	RunScopeAnchor  string
	RunScopeLead    string
	InputHeading    string
	InputAnchor     string
	InputRows       []kv
	ConfigHeading   string
	ConfigAnchor    string
	ConfigRows      []kv
	SandboxHeading  string
	SandboxAnchor   string
	Sandbox         sandboxSection

	// Method At A Glance
	Method methodSection

	// Processing Errors
	Processing processingSection

	// Residual Risk
	ResidualHeading string
	ResidualAnchor  string
	ResidualText    string
	ResidualBullets []htmltmpl.HTML

	// Appendix
	AppendixHeading string
	AppendixAnchor  string
	AppendixLead    string
	ComponentIndex  componentIndexSection
	Normalization   normalizationSection
	ExtensionFilter extensionFilterSection
	RootMetadata    rootMetadataSection
	Policy          policySection
	ScanLog         scanLogSection
	Extraction      extractionSection
}

// kv is a generic key/value table row with plain-text cells.
type kv struct{ K, V string }

// tocItem is one Table-of-Contents entry. Level controls indentation (0..2).
type tocItem struct {
	Title  string
	Anchor string
	Level  int
}

// vulnSection holds the Vulnerability Summary. StateLine/FindingLine are
// pre-rendered HTML because the shared catalog templates carry inline code spans.
type vulnSection struct {
	Heading     string
	Anchor      string
	Requested   bool
	SummaryLine string
	StateLine   htmltmpl.HTML
	FindingLine htmltmpl.HTML
	Headers     []string
	Rows        []vulnRow
}

// vulnRow is one row in the vulnerability table. Name and NameAnchor are plain
// strings; the template renders the (optional) anchor link with context-aware
// auto-escaping so an untrusted package name cannot inject markup.
type vulnRow struct {
	ID          string
	Severity    string
	SeverityCSS string
	Name        string
	NameAnchor  string
	Installed   string
	FixedIn     string
	EPSS        string
	Risk        string
	KEV         string
	Description string
}

// sandboxSection renders either a status table (bwrap present) or explanatory
// prose (bwrap absent). Exactly one of Rows / Prose is populated.
type sandboxSection struct {
	Rows  []kv
	Note  htmltmpl.HTML
	Prose htmltmpl.HTML
}

// methodSection holds the Method At A Glance content.
type methodSection struct {
	Heading string
	Anchor  string
	Lead    htmltmpl.HTML
	Bullets []htmltmpl.HTML
}

// processingSection holds the Processing Errors table, or an empty marker.
type processingSection struct {
	Heading   string
	Anchor    string
	Empty     bool
	EmptyText string
	Headers   []string
	Rows      [][]string
}

// componentIndexSection holds the appendix Component Occurrence Index.
type componentIndexSection struct {
	Heading           string
	Anchor            string
	Lead              htmltmpl.HTML
	Empty             bool
	EmptyText         string
	WithPURLTitle     string
	WithPURLAnchor    string
	WithPURL          []packageGroup
	WithoutPURLTitle  string
	WithoutPURLAnchor string
	WithoutPURL       []packageGroup
}

// packageGroup is one collapsible package entry with its occurrences.
type packageGroup struct {
	AnchorID    string
	Title       string
	Name        string
	Version     string
	PURLs       []string
	VulnLine    string
	Occurrences []occurrence
	Labels      occurrenceLabels
}

// occurrence is one concrete component occurrence under a package group.
type occurrence struct {
	AnchorID      string
	ObjectID      string
	DeliveryPaths []string
	Evidence      []string
	FoundBy       string
	VulnLine      string
}

// occurrenceLabels carries the localized field labels for an occurrence so the
// template can render them without re-resolving the bundle.
type occurrenceLabels struct {
	ComponentID  string
	DeliveryPath string
	EvidencePath string
	FoundBy      string
}

// normalizationSection holds the Component Normalization appendix block.
type normalizationSection struct {
	Heading      string
	Anchor       string
	Lead         htmltmpl.HTML
	EmptyText    string
	Empty        bool
	SummaryTable headerKV
	Groups       []suppressionGroup
}

// headerKV is a key/value table with a header row.
type headerKV struct {
	Headers []string
	Rows    []kv
}

// suppressionGroup is one collapsible suppression-reason block.
type suppressionGroup struct {
	AnchorID    string
	Title       string
	Operational []htmltmpl.HTML
	Headers     []string
	Rows        []suppRow
	Truncated   string
}

// suppRow is one suppression-table row. The "suppressed by" cell is modeled as
// data (kept component link/code or an italic reason) so the template can
// auto-escape the untrusted component name.
type suppRow struct {
	DeliveryPath string
	Name         string
	KeptName     string
	KeptAnchor   string
	Reason       string
}

// extensionFilterSection documents skipped extensions and affected paths.
type extensionFilterSection struct {
	Heading         string
	Anchor          string
	Lead            string
	ExtensionsLabel string
	Extensions      string
	SkippedLabel    string
	SkippedPaths    []string
	EmptyText       string
	Empty           bool
}

// rootMetadataSection holds the Root SBOM Metadata table.
type rootMetadataSection struct {
	Heading string
	Anchor  string
	Headers []string
	Rows    [][]string
}

// policySection holds the Policy Decisions table.
type policySection struct {
	Heading   string
	Anchor    string
	Empty     bool
	EmptyText string
	Headers   []string
	Rows      [][]string
}

// scanLogSection holds the Package Scan Log and the no-package-identity list.
type scanLogSection struct {
	Heading        string
	Anchor         string
	Lead           string
	Headers        []string
	Rows           []scanRow
	NoPkgHeading   string
	NoPkgAnchor    string
	NoPkgLead      string
	NoPkgPaths     []string
	NoPkgEmpty     bool
	NoPkgEmptyText string
}

// scanRow is one package-scan-log row.
type scanRow struct {
	NodePath string
	Count    string
	Evidence []string
	Error    string
}

// extractionSection holds the Extraction Log table.
type extractionSection struct {
	Heading string
	Anchor  string
	Headers []string
	Rows    []extractionRow
}

// extractionRow is one extraction-log row; Depth drives indentation of Path.
type extractionRow struct {
	Depth   int
	Path    string
	Format  string
	Status  string
	Tool    string
	Sandbox string
	Detail  string
}

// severityCSSClass maps a normalized severity to a CSS badge class.
func severityCSSClass(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown-sev"
	}
}
