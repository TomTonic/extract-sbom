package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// SARIF 2.1.0 types — only the fields extract-sbom populates are modeled.

// sarifLog is the root SARIF 2.1.0 document.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun is a single analysis run. Invocations and Properties carry the
// vulnerability-enrichment audit metadata; see buildSARIFEnrichment.
type sarifRun struct {
	Tool        sarifTool           `json:"tool"`
	Invocations []sarifInvocation   `json:"invocations,omitempty"`
	Artifacts   []sarifArtifact     `json:"artifacts,omitempty"`
	Results     []sarifResult       `json:"results,omitempty"`
	Properties  *sarifRunProperties `json:"properties,omitempty"`
}

// sarifTool wraps the analysis driver descriptor.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver describes the tool that produced the run and the rules it knows.
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

// sarifRule is one rule descriptor; here, one per unique vulnerability ID.
type sarifRule struct {
	ID               string               `json:"id"`
	ShortDescription sarifMessage         `json:"shortDescription"`
	Properties       *sarifRuleProperties `json:"properties,omitempty"`
}

// sarifRuleProperties carries non-standard rule attributes (the severity).
type sarifRuleProperties struct {
	Severity string `json:"severity,omitempty"`
}

// sarifMessage is a SARIF message string container.
type sarifMessage struct {
	Text string `json:"text"`
}

// sarifInvocation records one tool invocation. ExecutionSuccessful reports
// whether the analysis (including vulnerability enrichment) ran to completion;
// a false value tells consumers that an empty result set is not authoritative.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

// sarifNotification is a tool-execution notification (a run-level message that
// is not a code finding), used here to explain the enrichment outcome.
type sarifNotification struct {
	Level   string       `json:"level,omitempty"`
	Message sarifMessage `json:"message"`
}

// sarifRunProperties is the run-level property bag. It makes the
// vulnerability-enrichment outcome machine-readable without relying on the
// human-readable notification text.
type sarifRunProperties struct {
	VulnerabilityEnrichmentState     string `json:"vulnerabilityEnrichmentState"`
	VulnerabilityEnrichmentRequested bool   `json:"vulnerabilityEnrichmentRequested"`
}

// sarifArtifact describes an input artifact and its content hashes.
type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
	Hashes   map[string]string     `json:"hashes,omitempty"`
}

// sarifArtifactLocation is a URI reference to an artifact.
type sarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}

// sarifResult is a single finding (one vulnerability match).
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

// sarifLocation binds a result to a physical location.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation is the artifact-relative physical location of a result.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

// GenerateSARIF writes a SARIF 2.1.0 JSON report to w.
//
// The run records vulnerability findings as SARIF results. It additionally
// emits an invocation and a run-level property bag describing the
// vulnerability-enrichment outcome (see buildSARIFEnrichment) so that an empty
// result set produced by a clean scan can be told apart from one produced
// because enrichment was not requested or because Grype was unavailable.
//
// Parameters:
//   - data: the complete processing state snapshot
//   - w: the writer to write the SARIF JSON to
//
// Returns an error if writing fails.
func GenerateSARIF(data ReportData, w io.Writer) error {
	rules := buildSARIFRules(data.Vulnerabilities)
	artifacts := buildSARIFArtifacts(data.Input)
	results := buildSARIFResults(data)
	invocation, runProps := buildSARIFEnrichment(data.Vulnerabilities)

	version := ""
	if data.Generator.Version != "" {
		version = data.Generator.Version
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "extract-sbom",
						Version: version,
						Rules:   rules,
					},
				},
				Invocations: []sarifInvocation{invocation},
				Artifacts:   artifacts,
				Results:     results,
				Properties:  &runProps,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// buildSARIFRules derives one rule descriptor per unique vulnerability ID,
// sorted by ID for deterministic output.
func buildSARIFRules(v *vulnscan.Result) []sarifRule {
	ruleSet := make(map[string]string) // vulnID → severity
	if v != nil && v.MatchesByBOMRef != nil {
		for _, matches := range v.MatchesByBOMRef {
			for i := range matches {
				if _, exists := ruleSet[matches[i].VulnerabilityID]; !exists {
					ruleSet[matches[i].VulnerabilityID] = matches[i].Severity
				}
			}
		}
	}

	ruleIDs := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, sarifRule{
			ID:               id,
			ShortDescription: sarifMessage{Text: id},
			Properties:       &sarifRuleProperties{Severity: ruleSet[id]},
		})
	}
	return rules
}

// buildSARIFArtifacts returns the single input-file artifact entry, including
// its SHA-256 hash when available.
func buildSARIFArtifacts(input InputSummary) []sarifArtifact {
	if input.Filename == "" {
		return nil
	}
	art := sarifArtifact{
		Location: sarifArtifactLocation{URI: input.Filename},
	}
	if input.SHA256 != "" {
		art.Hashes = map[string]string{"sha-256": input.SHA256}
	}
	return []sarifArtifact{art}
}

// buildSARIFResults converts the Grype matches into SARIF results, sorted by
// bom-ref and then by vulnerability ID for deterministic output.
func buildSARIFResults(data ReportData) []sarifResult {
	if data.Vulnerabilities == nil || data.Vulnerabilities.MatchesByBOMRef == nil {
		return nil
	}

	// Build a bom-ref → delivery path lookup.
	bomRefDeliveryPath := make(map[string]string)
	if data.BOM != nil && data.BOM.Components != nil {
		comps := *data.BOM.Components
		for i := range comps {
			if comps[i].Properties == nil {
				continue
			}
			for _, p := range *comps[i].Properties {
				if p.Name == "extract-sbom:delivery-path" && p.Value != "" {
					bomRefDeliveryPath[comps[i].BOMRef] = p.Value
					break
				}
			}
		}
	}

	bomRefs := make([]string, 0, len(data.Vulnerabilities.MatchesByBOMRef))
	for ref := range data.Vulnerabilities.MatchesByBOMRef {
		bomRefs = append(bomRefs, ref)
	}
	sort.Strings(bomRefs)

	var results []sarifResult
	for _, bomRef := range bomRefs {
		matches := data.Vulnerabilities.MatchesByBOMRef[bomRef]
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].VulnerabilityID < matches[j].VulnerabilityID
		})
		deliveryPath := bomRefDeliveryPath[bomRef]
		if deliveryPath == "" {
			deliveryPath = data.Input.Filename
		}

		for i := range matches {
			text := matches[i].Description
			if text == "" {
				text = matches[i].VulnerabilityID + " (" + matches[i].Severity + ")"
			}
			results = append(results, sarifResult{
				RuleID:  matches[i].VulnerabilityID,
				Level:   sarifLevel(matches[i].Severity),
				Message: sarifMessage{Text: text},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{URI: deliveryPath},
						},
					},
				},
			})
		}
	}
	return results
}

// buildSARIFEnrichment derives the SARIF invocation and run-level properties
// that record the vulnerability-enrichment outcome.
//
// Without this metadata, a SARIF consumer cannot tell an empty result set
// produced by a clean scan apart from one produced because enrichment was never
// requested or because Grype was unavailable. The invocation's
// executionSuccessful flag, a tool-execution notification, and the typed
// property bag make that distinction explicit and machine-readable, matching
// the audit semantics the Markdown report already preserves.
func buildSARIFEnrichment(v *vulnscan.Result) (sarifInvocation, sarifRunProperties) {
	state, requested := normalizedVulnEnrichmentState(v)

	var level, message string
	executionSuccessful := true
	switch state {
	case vulnscan.StateCompleted:
		level = "note"
		message = "Vulnerability enrichment completed; the results are the complete set of matches found."
	case vulnscan.StateCompletedWithErrors:
		level = "warning"
		message = "Vulnerability enrichment completed with errors; the result set may be incomplete."
	case vulnscan.StateUnavailable:
		level = "error"
		message = "Vulnerability enrichment was requested but Grype was unavailable; " +
			"an empty result set does NOT indicate the absence of vulnerabilities."
		executionSuccessful = false
	default: // StateNotRequested
		level = "note"
		message = "Vulnerability enrichment was not requested; " +
			"this report intentionally contains no vulnerability findings."
	}

	invocation := sarifInvocation{
		ExecutionSuccessful: executionSuccessful,
		ToolExecutionNotifications: []sarifNotification{
			{Level: level, Message: sarifMessage{Text: message}},
		},
	}
	props := sarifRunProperties{
		VulnerabilityEnrichmentState:     string(state),
		VulnerabilityEnrichmentRequested: requested,
	}
	return invocation, props
}

// sarifLevel converts a vulnerability severity to a SARIF result level.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
