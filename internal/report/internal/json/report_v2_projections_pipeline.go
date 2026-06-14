package json

import (
	"time"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// buildExtractionProjectionRows flattens extraction tree data into ordered rows.
func buildExtractionProjectionRows(tree *extract.ExtractionNode, index entityIndexV2) []ExtractionLogRowV2 {
	rows := make([]ExtractionLogRowV2, 0)
	var walk func(node *extract.ExtractionNode, depth int)
	walk = func(node *extract.ExtractionNode, depth int) {
		if node == nil {
			return
		}
		row := ExtractionLogRowV2{
			SourceRefs:  sourceRefsOrNil(index.nodeByPath[node.Path]),
			Path:        node.Path,
			Status:      node.Status.String(),
			Format:      node.Format.Format.String(),
			Tool:        node.Tool,
			Detail:      node.StatusDetail,
			Depth:       depth,
			SandboxUsed: node.SandboxUsed,
		}
		if node.Duration > 0 {
			row.Duration = node.Duration.Round(time.Millisecond).String()
		}
		if node.ArchiveMeta != nil {
			row.ArchiveMeta = &ExtractionArchiveMetaV2{
				Type:             node.ArchiveMeta.Type,
				Methods:          append([]string(nil), node.ArchiveMeta.Methods...),
				HasEncryptedItem: node.ArchiveMeta.HasEncryptedItem,
				PhysicalSize:     node.ArchiveMeta.PhysicalSize,
				HeadersSize:      node.ArchiveMeta.HeadersSize,
				Solid:            node.ArchiveMeta.Solid,
				Blocks:           node.ArchiveMeta.Blocks,
			}
		}
		rows = append(rows, row)
		for _, child := range node.Children {
			walk(child, depth+1)
		}
	}
	walk(tree, 0)
	return rows
}

// buildScanProjectionRows maps scan results into display rows.
func buildScanProjectionRows(scans []scan.ScanResult, entities entitiesV2) []ScanRowV2 {
	scanEntityByPath := make(map[string]string, len(entities.ScanTasks))
	for i := range entities.ScanTasks {
		scanEntityByPath[entities.ScanTasks[i].NodePath] = entities.ScanTasks[i].ID
	}

	rows := make([]ScanRowV2, 0, len(scans))
	for i := range scans {
		compCount := 0
		if scans[i].BOM != nil && scans[i].BOM.Components != nil {
			compCount = len(*scans[i].BOM.Components)
		}
		evidencePaths := scan.FlattenEvidencePaths(scans[i])
		if evidencePaths == nil {
			evidencePaths = []string{}
		}
		row := ScanRowV2{
			SourceRefs:     sourceRefsOrNil(scanEntityByPath[scans[i].NodePath]),
			NodePath:       scans[i].NodePath,
			ComponentCount: compCount,
			EvidencePaths:  evidencePaths,
		}
		if scans[i].Error != nil {
			row.Error = scans[i].Error.Error()
		}
		rows = append(rows, row)
	}
	return rows
}

// buildPolicyDecisionProjectionRows converts policy decision entities into projection rows.
func buildPolicyDecisionProjectionRows(entities entitiesV2) []PolicyDecisionRowV2 {
	rows := make([]PolicyDecisionRowV2, 0, len(entities.PolicyDecisions))
	for i := range entities.PolicyDecisions {
		rows = append(rows, PolicyDecisionRowV2{
			SourceRef: entities.PolicyDecisions[i].ID,
			Trigger:   entities.PolicyDecisions[i].Trigger,
			NodePath:  entities.PolicyDecisions[i].NodePath,
			Action:    entities.PolicyDecisions[i].Action,
			Detail:    entities.PolicyDecisions[i].Detail,
		})
	}
	return rows
}

// buildIssueProjectionRows emits issue rows.
func buildIssueProjectionRows(entities entitiesV2) []IssueRowV2 {
	rows := make([]IssueRowV2, 0, len(entities.Issues))
	for i := range entities.Issues {
		rows = append(rows, IssueRowV2{
			SourceRefs: []string{entities.Issues[i].ID},
			Stage:      entities.Issues[i].Stage,
			Message:    entities.Issues[i].Message,
		})
	}
	return rows
}
