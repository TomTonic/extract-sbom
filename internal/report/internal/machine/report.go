// Package machine implements the structured JSON audit report renderer.
package machine

import (
	"encoding/json"
	"io"
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
)

// InputSummary aliases the shared report input summary contract.
type InputSummary = model.InputSummary

// ProcessingIssue aliases the shared structured processing issue contract.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract.
type ReportData = model.ReportData

// Generate writes a structured JSON audit report to the writer.
func Generate(data ReportData, w io.Writer) error {
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
		Extraction:      buildTree(data.Tree),
		Scans:           buildScans(data.Scans),
		Vulnerabilities: buildVulnerabilities(data.Vulnerabilities),
		Decisions:       buildDecisions(data.PolicyDecisions),
		Issues:          data.ProcessingIssues,
		StartTime:       data.StartTime.UTC().Format(time.RFC3339),
		EndTime:         data.EndTime.UTC().Format(time.RFC3339),
		Duration:        data.EndTime.Sub(data.StartTime).String(),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

type machineReport struct {
	SchemaVersion   string                  `json:"schemaVersion"`
	Input           InputSummary            `json:"input"`
	Generator       machineGenerator        `json:"generator"`
	Config          machineConfig           `json:"config"`
	RootMetadata    machineRootMetadata     `json:"rootMetadata"`
	Sandbox         machineSandbox          `json:"sandbox"`
	Extraction      *machineNode            `json:"extraction"`
	Scans           []machineScan           `json:"scans"`
	Vulnerabilities *machineVulnerabilities `json:"vulnerabilities,omitempty"`
	Decisions       []machineDecision       `json:"decisions"`
	Issues          []ProcessingIssue       `json:"issues,omitempty"`
	StartTime       string                  `json:"startTime"`
	EndTime         string                  `json:"endTime"`
	Duration        string                  `json:"duration"`
}

type machineConfig struct {
	PolicyMode    string        `json:"policyMode"`
	InterpretMode string        `json:"interpretMode"`
	Language      string        `json:"language"`
	Limits        machineLimits `json:"limits"`
}

type machineGenerator struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified"`
	Display  string `json:"display"`
}

type machineLimits struct {
	MaxDepth     int    `json:"maxDepth"`
	MaxFiles     int    `json:"maxFiles"`
	MaxTotalSize int64  `json:"maxTotalSize"`
	MaxEntrySize int64  `json:"maxEntrySize"`
	MaxRatio     int    `json:"maxRatio"`
	Timeout      string `json:"timeout"`
}

type machineRootMetadata struct {
	Manufacturer string            `json:"manufacturer,omitempty"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	DeliveryDate string            `json:"deliveryDate,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

type machineSandbox struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Unsafe    bool   `json:"unsafe"`
}

type machineNode struct {
	Path         string         `json:"path"`
	Format       string         `json:"format"`
	Status       string         `json:"status"`
	StatusDetail string         `json:"statusDetail,omitempty"`
	Tool         string         `json:"tool,omitempty"`
	SandboxUsed  string         `json:"sandboxUsed,omitempty"`
	Duration     string         `json:"duration,omitempty"`
	EntriesCount int            `json:"entriesCount,omitempty"`
	TotalSize    int64          `json:"totalSize,omitempty"`
	Children     []*machineNode `json:"children,omitempty"`
}

type machineScan struct {
	NodePath       string   `json:"nodePath"`
	ComponentCount int      `json:"componentCount"`
	EvidencePaths  []string `json:"evidencePaths,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type machineDecision struct {
	Trigger  string `json:"trigger"`
	NodePath string `json:"nodePath"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

type machineVulnerabilities struct {
	State            string                            `json:"state"`
	Requested        bool                              `json:"requested"`
	GrypeVersion     string                            `json:"grypeVersion,omitempty"`
	DBSchemaVersion  string                            `json:"dbSchemaVersion,omitempty"`
	DBBuilt          string                            `json:"dbBuilt,omitempty"`
	DBUpdated        string                            `json:"dbUpdated,omitempty"`
	MatchesByBOMRef  map[string][]vulnscan.VMatch      `json:"matchesByBomRef,omitempty"`
	CoverageByBOMRef map[string]vulnscan.CoverageState `json:"coverageByBomRef,omitempty"`
	Errors           []vulnscan.Issue                  `json:"errors,omitempty"`
}

func buildTree(node *extract.ExtractionNode) *machineNode {
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
		mn.Children = append(mn.Children, buildTree(child))
	}

	return mn
}

func buildScans(scans []scan.ScanResult) []machineScan {
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

func buildDecisions(decisions []policy.Decision) []machineDecision {
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

func buildVulnerabilities(v *vulnscan.Result) *machineVulnerabilities {
	if v == nil {
		return nil
	}
	state, requested := normalizedVulnEnrichmentState(v)
	return &machineVulnerabilities{
		State:            string(state),
		Requested:        requested,
		GrypeVersion:     v.GrypeVersion,
		DBSchemaVersion:  v.DBSchemaVersion,
		DBBuilt:          v.DBBuilt,
		DBUpdated:        v.DBUpdated,
		MatchesByBOMRef:  v.MatchesByBOMRef,
		CoverageByBOMRef: v.CoverageByBOMRef,
		Errors:           v.Errors,
	}
}

func normalizedVulnEnrichmentState(v *vulnscan.Result) (vulnscan.State, bool) {
	state := vulnscan.StateNotRequested
	requested := false
	if v != nil {
		requested = v.Requested
		if v.State != "" {
			state = v.State
		}
	}
	return state, requested
}
