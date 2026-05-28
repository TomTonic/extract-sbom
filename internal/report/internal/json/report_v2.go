package json

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

const (
	reportV2SchemaName    = "extract-sbom-report"
	reportV2SchemaVersion = "2.0.0"
)

// GenerateV2 writes the slice-1 canonical JSON report envelope for schema 2.0.0.
//
// This serializer intentionally focuses on skeleton completeness and raw data
// capture. Entities/projections are populated in later slices.
func GenerateV2(data ReportData, w io.Writer) error {
	report := buildJSONReportV2Skeleton(data, time.Now().UTC())
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func buildJSONReportV2Skeleton(data ReportData, generatedAt time.Time) ReportV2 {
	rawScans := make([]rawScanV2, len(data.Scans))
	for i := range data.Scans {
		rawScans[i] = toRawScanV2(data.Scans[i])
	}

	return ReportV2{
		Schema: reportSchemaV2{
			Name:        reportV2SchemaName,
			Version:     reportV2SchemaVersion,
			GeneratedAt: generatedAt.Format(time.RFC3339),
		},
		Run: runV2{
			RunID:     runIDFromInput(data),
			StartTime: data.StartTime.UTC().Format(time.RFC3339),
			EndTime:   data.EndTime.UTC().Format(time.RFC3339),
			Duration:  data.EndTime.Sub(data.StartTime).String(),
			ExitCode:  0,
		},
		Input: inputSummaryV2{
			Filename: data.Input.Filename,
			Size:     data.Input.Size,
			SHA256:   data.Input.SHA256,
			SHA512:   data.Input.SHA512,
		},
		Generator: generatorV2{
			Version:  data.Generator.Version,
			Revision: data.Generator.Revision,
			Time:     data.Generator.Time,
			Modified: data.Generator.Modified,
			Display:  data.Generator.String(),
		},
		Config: configSnapshotV2{
			SBOMFormat:           data.Config.SBOMFormat,
			PolicyMode:           data.Config.PolicyMode.String(),
			InterpretMode:        data.Config.InterpretMode.String(),
			ReportSelection:      data.Config.ReportSelection.String(),
			ProgressLevel:        data.Config.ProgressLevel.String(),
			Language:             data.Config.Language,
			MarkdownRenderEngine: data.Config.MarkdownRenderEngine,
			MarkdownTemplateFile: data.Config.MarkdownTemplateFile,
			GrypeEnabled:         data.Config.GrypeEnabled,
			Unsafe:               data.Config.Unsafe,
			ParallelScanners:     data.Config.ParallelScanners,
			SkipExtensions:       append([]string(nil), data.Config.SkipExtensions...),
			RootMetadata: rootMetadataV2{
				Manufacturer: data.Config.RootMetadata.Manufacturer,
				Name:         data.Config.RootMetadata.Name,
				Version:      data.Config.RootMetadata.Version,
				DeliveryDate: data.Config.RootMetadata.DeliveryDate,
				Properties:   data.Config.RootMetadata.Properties,
			},
			Limits: limitsV2{
				MaxDepth:     data.Config.Limits.MaxDepth,
				MaxFiles:     data.Config.Limits.MaxFiles,
				MaxTotalSize: data.Config.Limits.MaxTotalSize,
				MaxEntrySize: data.Config.Limits.MaxEntrySize,
				MaxRatio:     data.Config.Limits.MaxRatio,
				Timeout:      data.Config.Limits.Timeout.String(),
			},
			Passwords: passwordInfoV2{
				Count:             len(data.Config.Passwords),
				SensitiveRedacted: true,
			},
		},
		Runtime: runtimeV2{
			Sandbox: sandboxV2{
				Name:           data.SandboxInfo.Name,
				Available:      data.SandboxInfo.Available,
				UnsafeOverride: data.SandboxInfo.UnsafeOvr,
			},
			ToolVersions: toolVersionsV2{
				SevenZip:   data.ToolVersions.SevenZip,
				Unshield:   data.ToolVersions.Unshield,
				Unsquashfs: data.ToolVersions.Unsquashfs,
				Grype:      data.ToolVersions.Grype,
				GrypeDB:    data.ToolVersions.GrypeDB,
			},
			Warnings: []warningV2{},
		},
		Raw: rawV2{
			ExtractionTreeRaw:   data.Tree,
			ScansRaw:            rawScans,
			BOMRaw:              data.BOM,
			VulnerabilitiesRaw:  data.Vulnerabilities,
			PolicyDecisionsRaw:  copyPolicyDecisions(data.PolicyDecisions),
			ProcessingIssuesRaw: copyProcessingIssues(data.ProcessingIssues),
			SuppressionsRaw:     copySuppressions(data.Suppressions),
			ArtifactPaths: artifactPathsV2{
				SBOMPath: data.SBOMPath,
			},
		},
		Entities: entitiesV2{
			Nodes:           []entityV2{},
			ScanTasks:       []entityV2{},
			Components:      []entityV2{},
			PackageGroups:   []entityV2{},
			Vulnerabilities: []entityV2{},
			Suppressions:    []entityV2{},
			PolicyDecisions: []entityV2{},
			Issues:          []entityV2{},
		},
		Projections: projectionsV2{
			Generic: genericProjectionV2{
				Summary: map[string]any{
					"note": "slice-1 skeleton; entities/projections will be populated in later slices",
				},
				ExtractionRows:    []projectionRowV2{},
				VulnerabilityRows: []projectionRowV2{},
				IssueRows:         []projectionRowV2{},
				ComponentIndex:    []projectionRowV2{},
			},
			Markdown: markdownProjectionV2{
				Sections: []projectionRowV2{},
				TOC:      []projectionRowV2{},
				Anchors:  []projectionRowV2{},
			},
			HTML: htmlProjectionV2{
				SummaryCards: []projectionRowV2{},
				TableModels:  []projectionRowV2{},
			},
		},
		Integrity: integrityV2{
			Counts: integrityCountsV2{
				Nodes:           0,
				ScanTasks:       0,
				Components:      0,
				PackageGroups:   0,
				Vulnerabilities: 0,
				Suppressions:    0,
				PolicyDecisions: 0,
				Issues:          0,
			},
			DanglingReferenceCount: 0,
			ValidationState:        "ok",
			ValidationErrors:       []string{},
		},
		Compatibility: compatibilityV2{
			LegacyAliasesUsed: legacyAliasesV2{},
			MigrationHints: []string{
				"slice-1 skeleton: entities and projections are intentionally empty",
			},
		},
	}
}

func toRawScanV2(scanResult scan.ScanResult) rawScanV2 {
	out := rawScanV2{
		NodePath:      scanResult.NodePath,
		BOM:           scanResult.BOM,
		EvidencePaths: scanResult.EvidencePaths,
	}
	if scanResult.Error != nil {
		out.Error = scanResult.Error.Error()
	}
	return out
}

func runIDFromInput(data ReportData) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%s",
		data.Input.Filename,
		data.Input.Size,
		data.Input.SHA256,
		data.Input.SHA512,
		data.StartTime.UTC().Format(time.RFC3339Nano),
		data.EndTime.UTC().Format(time.RFC3339Nano),
	)))
	return "run:" + hex.EncodeToString(sum[:12])
}

func copyPolicyDecisions(in []policy.Decision) []policy.Decision {
	out := make([]policy.Decision, len(in))
	copy(out, in)
	return out
}

func copyProcessingIssues(in []ProcessingIssue) []ProcessingIssue {
	out := make([]ProcessingIssue, len(in))
	copy(out, in)
	return out
}

func copySuppressions(in []assembly.SuppressionRecord) []assembly.SuppressionRecord {
	out := make([]assembly.SuppressionRecord, len(in))
	copy(out, in)
	return out
}
