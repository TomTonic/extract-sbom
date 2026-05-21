// Package report implements extract-sbom audit report generation.
//
// This file holds the localized label set for the self-contained HTML audit
// report. The Markdown report has its own much larger translation table
// (report_i18n.go); the HTML report only needs a small, cohesive set of
// presentation labels, so it carries a dedicated message struct here rather
// than overloading the Markdown translation type.
package report

// htmlMessages holds every human-readable label rendered by the HTML report
// template. Keeping all strings in one struct lets the template stay free of
// hard-coded English text and makes the report honor the configured output
// language ("en" or "de").
type htmlMessages struct {
	ReportTitle    string
	GeneratedLabel string
	GeneratorLabel string
	ToolsLabel     string

	SummaryHeading  string
	FieldHeading    string
	ValueHeading    string
	InputFileLabel  string
	InputSizeLabel  string
	BytesUnit       string
	SHA256Label     string
	DurationLabel   string
	SBOMOutputLabel string
	SandboxLabel    string
	ComponentsLabel string
	VulnsLabel      string
	IssuesLabel     string

	ExtractionHeading string
	StatusHeading     string
	CountHeading      string
	ExtractedLabel    string
	FailedLabel       string
	SkippedLabel      string
	TotalNodesLabel   string

	VulnTableHeading   string
	VulnMatchesWord    string
	IDHeading          string
	SeverityHeading    string
	PackageHeading     string
	VersionHeading     string
	DescriptionHeading string

	IssuesHeading  string
	StageHeading   string
	MessageHeading string

	ExtractionLogHeading string
	PathHeading          string
	FormatHeading        string
	ToolHeading          string
	DetailHeading        string

	// VulnNotRequested / VulnUnavailable are shown in the summary table in
	// place of a misleading "0" so a reader can tell a clean result apart from
	// one where enrichment never ran. See htmlVulnState.
	VulnNotRequested string
	VulnUnavailable  string
}

// htmlMessagesEN is the English label set used for language "en" and as the
// fallback for any unrecognized language code.
var htmlMessagesEN = htmlMessages{
	ReportTitle:    "extract-sbom Audit Report",
	GeneratedLabel: "Generated",
	GeneratorLabel: "Generator",
	ToolsLabel:     "External tools",

	SummaryHeading:  "Summary",
	FieldHeading:    "Field",
	ValueHeading:    "Value",
	InputFileLabel:  "Input file",
	InputSizeLabel:  "Input size",
	BytesUnit:       "bytes",
	SHA256Label:     "SHA-256",
	DurationLabel:   "Duration",
	SBOMOutputLabel: "SBOM output",
	SandboxLabel:    "Sandbox",
	ComponentsLabel: "Components found",
	VulnsLabel:      "Vulnerabilities",
	IssuesLabel:     "Processing issues",

	ExtractionHeading: "Extraction Overview",
	StatusHeading:     "Status",
	CountHeading:      "Count",
	ExtractedLabel:    "Extracted",
	FailedLabel:       "Failed",
	SkippedLabel:      "Skipped / tool missing",
	TotalNodesLabel:   "Total nodes",

	VulnTableHeading:   "Vulnerability Table",
	VulnMatchesWord:    "matches",
	IDHeading:          "ID",
	SeverityHeading:    "Severity",
	PackageHeading:     "Package",
	VersionHeading:     "Version",
	DescriptionHeading: "Description",

	IssuesHeading:  "Processing Issues",
	StageHeading:   "Stage",
	MessageHeading: "Message",

	ExtractionLogHeading: "Extraction Log",
	PathHeading:          "Path",
	FormatHeading:        "Format",
	ToolHeading:          "Tool",
	DetailHeading:        "Detail",

	VulnNotRequested: "not requested",
	VulnUnavailable:  "unavailable",
}

// htmlMessagesDE is the German label set used for language "de".
var htmlMessagesDE = htmlMessages{
	ReportTitle:    "extract-sbom Audit-Bericht",
	GeneratedLabel: "Erstellt",
	GeneratorLabel: "Generator",
	ToolsLabel:     "Externe Werkzeuge",

	SummaryHeading:  "Zusammenfassung",
	FieldHeading:    "Feld",
	ValueHeading:    "Wert",
	InputFileLabel:  "Eingabedatei",
	InputSizeLabel:  "Eingabegröße",
	BytesUnit:       "Bytes",
	SHA256Label:     "SHA-256",
	DurationLabel:   "Dauer",
	SBOMOutputLabel: "SBOM-Ausgabe",
	SandboxLabel:    "Sandbox",
	ComponentsLabel: "Gefundene Komponenten",
	VulnsLabel:      "Schwachstellen",
	IssuesLabel:     "Verarbeitungsprobleme",

	ExtractionHeading: "Extraktionsübersicht",
	StatusHeading:     "Status",
	CountHeading:      "Anzahl",
	ExtractedLabel:    "Extrahiert",
	FailedLabel:       "Fehlgeschlagen",
	SkippedLabel:      "Übersprungen / Werkzeug fehlt",
	TotalNodesLabel:   "Knoten gesamt",

	VulnTableHeading:   "Schwachstellentabelle",
	VulnMatchesWord:    "Treffer",
	IDHeading:          "ID",
	SeverityHeading:    "Schweregrad",
	PackageHeading:     "Paket",
	VersionHeading:     "Version",
	DescriptionHeading: "Beschreibung",

	IssuesHeading:  "Verarbeitungsprobleme",
	StageHeading:   "Phase",
	MessageHeading: "Meldung",

	ExtractionLogHeading: "Extraktionsprotokoll",
	PathHeading:          "Pfad",
	FormatHeading:        "Format",
	ToolHeading:          "Werkzeug",
	DetailHeading:        "Detail",

	VulnNotRequested: "nicht angefordert",
	VulnUnavailable:  "nicht verfügbar",
}

// htmlMessagesFor returns the HTML label set for the given language code.
// Any value other than "de" (case-insensitively, prefix match) yields the
// English set, mirroring the Markdown report's English-default behavior.
func htmlMessagesFor(language string) htmlMessages {
	if len(language) >= 2 {
		switch language[:2] {
		case "de", "De", "dE", "DE":
			return htmlMessagesDE
		}
	}
	return htmlMessagesEN
}
