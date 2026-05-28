package json

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/policy"
	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	"github.com/TomTonic/extract-sbom/internal/scan"
	"github.com/TomTonic/extract-sbom/internal/vulnscan"
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

	entities, index := buildEntitiesV2(data)
	projections := buildProjectionsV2(data, entities, index)
	integrity := buildIntegrityV2(entities, projections)

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
		Entities:    entities,
		Projections: projections,
		Integrity:   integrity,
		Compatibility: compatibilityV2{
			LegacyAliasesUsed: legacyAliasesV2{},
			MigrationHints: []string{
				"slice-2: entities and integrity are populated from ReportData",
				"slice-3: projections will expand to renderer-ready domain models",
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

type entityIndexV2 struct {
	nodeByPath      map[string]string
	componentByRef  map[string]string
	componentByName map[string]string
}

func buildEntitiesV2(data ReportData) (entitiesV2, entityIndexV2) {
	entities := entitiesV2{
		Nodes:           make([]nodeEntityV2, 0),
		ScanTasks:       make([]scanTaskEntityV2, 0),
		Components:      make([]componentEntityV2, 0),
		PackageGroups:   make([]packageGroupEntityV2, 0),
		Vulnerabilities: make([]vulnerabilityEntityV2, 0),
		Suppressions:    make([]suppressionEntityV2, 0),
		PolicyDecisions: make([]policyDecisionEntityV2, 0),
		Issues:          make([]issueEntityV2, 0),
	}

	index := entityIndexV2{
		nodeByPath:      map[string]string{},
		componentByRef:  map[string]string{},
		componentByName: map[string]string{},
	}

	buildNodeEntities(data.Tree, "", &entities.Nodes, index.nodeByPath)
	buildComponentEntities(data.BOM, &entities.Components, index)
	buildPackageGroupEntities(entities.Components, &entities.PackageGroups)
	buildScanTaskEntities(data.Scans, index, &entities.ScanTasks)
	buildVulnerabilityEntities(data.Vulnerabilities, index, &entities.Vulnerabilities)
	buildSuppressionEntities(data.Suppressions, index, &entities.Suppressions)
	buildPolicyDecisionEntities(data.PolicyDecisions, index, &entities.PolicyDecisions)
	buildIssueEntities(data.ProcessingIssues, &entities.Issues)

	return entities, index
}

func buildNodeEntities(node *extract.ExtractionNode, parentID string, out *[]nodeEntityV2, nodeByPath map[string]string) string {
	if node == nil {
		return ""
	}

	id := stableID("node", node.Path, parentID)
	idx := len(*out)
	*out = append(*out, nodeEntityV2{
		ID:       id,
		Path:     node.Path,
		Status:   node.Status.String(),
		ParentID: parentID,
		ChildIDs: []string{},
	})
	if node.Path != "" {
		if _, exists := nodeByPath[node.Path]; !exists {
			nodeByPath[node.Path] = id
		}
	}

	childIDs := make([]string, 0, len(node.Children))
	for i := range node.Children {
		childID := buildNodeEntities(node.Children[i], id, out, nodeByPath)
		if childID != "" {
			childIDs = append(childIDs, childID)
		}
	}
	(*out)[idx].ChildIDs = childIDs
	return id
}

func buildComponentEntities(bom *cdx.BOM, out *[]componentEntityV2, index entityIndexV2) {
	if bom == nil || bom.Components == nil {
		return
	}

	for i := range *bom.Components {
		appendComponentEntity((*bom.Components)[i], out, index, i)
	}
}

func appendComponentEntity(component cdx.Component, out *[]componentEntityV2, index entityIndexV2, order int) {
	id := stableID("comp", component.BOMRef, component.PackageURL, component.Name, component.Version, string(component.Type), fmt.Sprintf("%d", order))
	entity := componentEntityV2{
		ID:      id,
		BOMRef:  component.BOMRef,
		Name:    component.Name,
		Version: component.Version,
		PURL:    component.PackageURL,
		Type:    string(component.Type),
	}
	*out = append(*out, entity)

	if component.BOMRef != "" {
		index.componentByRef[component.BOMRef] = id
	}
	nameKey := componentNameKey(component.Name, component.Version)
	if nameKey != "" {
		if _, exists := index.componentByName[nameKey]; !exists {
			index.componentByName[nameKey] = id
		}
	}
}

func buildPackageGroupEntities(components []componentEntityV2, out *[]packageGroupEntityV2) {
	byPURL := map[string][]string{}
	for i := range components {
		if components[i].PURL == "" {
			continue
		}
		byPURL[components[i].PURL] = append(byPURL[components[i].PURL], components[i].ID)
	}

	purls := make([]string, 0, len(byPURL))
	for purl := range byPURL {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	for i := range purls {
		componentIDs := byPURL[purls[i]]
		sort.Strings(componentIDs)
		*out = append(*out, packageGroupEntityV2{
			ID:           stableID("pkg", purls[i]),
			PURL:         purls[i],
			ComponentIDs: componentIDs,
		})
	}
}

func buildScanTaskEntities(scans []scan.ScanResult, index entityIndexV2, out *[]scanTaskEntityV2) {
	for i := range scans {
		componentIDs := make([]string, 0)
		if scans[i].BOM != nil && scans[i].BOM.Components != nil {
			for j := range *scans[i].BOM.Components {
				ref := strings.TrimSpace((*scans[i].BOM.Components)[j].BOMRef)
				if ref == "" {
					continue
				}
				if componentID, exists := index.componentByRef[ref]; exists {
					componentIDs = append(componentIDs, componentID)
				}
			}
		}
		sort.Strings(componentIDs)

		item := scanTaskEntityV2{
			ID:           stableID("scan", scans[i].NodePath, fmt.Sprintf("%d", i)),
			NodePath:     scans[i].NodePath,
			NodeID:       index.nodeByPath[scans[i].NodePath],
			ComponentIDs: dedupeSortedStrings(componentIDs),
		}
		if scans[i].Error != nil {
			item.Error = scans[i].Error.Error()
		}
		*out = append(*out, item)
	}
}

func buildVulnerabilityEntities(vulns *vulnscan.Result, index entityIndexV2, out *[]vulnerabilityEntityV2) {
	if vulns == nil {
		return
	}

	bomRefs := make([]string, 0, len(vulns.MatchesByBOMRef))
	for ref := range vulns.MatchesByBOMRef {
		bomRefs = append(bomRefs, ref)
	}
	sort.Strings(bomRefs)

	for _, ref := range bomRefs {
		componentID := index.componentByRef[ref]
		matches := vulns.MatchesByBOMRef[ref]
		for i := range matches {
			vulnID := strings.TrimSpace(matches[i].VulnerabilityID)
			if vulnID == "" {
				vulnID = "unknown"
			}
			*out = append(*out, vulnerabilityEntityV2{
				ID:              stableID("vuln", vulnID, componentID, ref, fmt.Sprintf("%d", i)),
				VulnerabilityID: vulnID,
				ComponentID:     componentID,
				Severity:        matches[i].Severity,
				BOMRef:          ref,
			})
		}
	}
}

func buildSuppressionEntities(records []assembly.SuppressionRecord, index entityIndexV2, out *[]suppressionEntityV2) {
	for i := range records {
		suppressedRef := strings.TrimSpace(records[i].Component.BOMRef)
		suppressedID := ""
		if suppressedRef != "" {
			suppressedID = index.componentByRef[suppressedRef]
		}
		if suppressedID == "" {
			suppressedID = index.componentByName[componentNameKey(records[i].Component.Name, records[i].Component.Version)]
		}

		keptID := index.componentByName[componentNameKey(records[i].KeptName, "")]

		item := suppressionEntityV2{
			ID:                     stableID("sup", records[i].Reason, records[i].Component.BOMRef, records[i].Component.Name, records[i].KeptName, fmt.Sprintf("%d", i)),
			Reason:                 records[i].Reason,
			SuppressedComponentRef: suppressedRef,
			SuppressedComponentID:  suppressedID,
			KeptComponentName:      records[i].KeptName,
			KeptComponentFoundBy:   records[i].KeptFoundBy,
			KeptComponentID:        keptID,
			ResolutionStatus:       "resolved",
		}
		if item.SuppressedComponentID == "" {
			item.ResolutionStatus = "missing"
			item.ResolutionReason = "suppressed component not present in canonical component set"
		}
		*out = append(*out, item)
	}
}

func buildPolicyDecisionEntities(decisions []policy.Decision, index entityIndexV2, out *[]policyDecisionEntityV2) {
	for i := range decisions {
		*out = append(*out, policyDecisionEntityV2{
			ID:       fmt.Sprintf("pol:%06d", i+1),
			Trigger:  decisions[i].Trigger,
			NodePath: decisions[i].NodePath,
			NodeID:   index.nodeByPath[decisions[i].NodePath],
			Action:   decisions[i].Action.String(),
			Detail:   decisions[i].Detail,
		})
	}
}

func buildIssueEntities(issues []ProcessingIssue, out *[]issueEntityV2) {
	for i := range issues {
		*out = append(*out, issueEntityV2{
			ID:      fmt.Sprintf("issue:%06d", i+1),
			Stage:   issues[i].Stage,
			Message: issues[i].Message,
		})
	}
}

func buildProjectionsV2(data ReportData, entities entitiesV2, index entityIndexV2) projectionsV2 {
	occurrences, occurrenceStats := domain.CollectComponentOccurrences(data.BOM)
	packageGroups := domain.BuildPackageOccurrenceGroups(occurrences)

	extractionRows := buildExtractionProjectionRows(data.Tree, index)
	vulnerabilityRows := buildVulnerabilityProjectionRows(entities)
	issueRows := buildIssueProjectionRows(entities)
	componentIndexRows := buildComponentIndexProjectionRows(packageGroups, index)
	if len(componentIndexRows) == 0 {
		componentIndexRows = buildComponentFallbackProjectionRows(entities.Components)
	}
	markdownSections, markdownTOC, markdownAnchors := buildMarkdownProjectionRows(entities, extractionRows, vulnerabilityRows, componentIndexRows)
	htmlSummaryCards, htmlTableModels := buildHTMLProjectionRows(data, entities, extractionRows, vulnerabilityRows, issueRows)

	return projectionsV2{
		Generic: genericProjectionV2{
			Summary: map[string]any{
				"nodes":                        len(entities.Nodes),
				"scanTasks":                    len(entities.ScanTasks),
				"components":                   len(entities.Components),
				"packageGroups":                len(entities.PackageGroups),
				"vulnerabilities":              len(entities.Vulnerabilities),
				"suppressions":                 len(entities.Suppressions),
				"policyDecisions":              len(entities.PolicyDecisions),
				"issues":                       len(entities.Issues),
				"componentIndexStats":          occurrenceStats,
				"vulnerabilityEnrichmentState": vulnerabilityStateValue(data.Vulnerabilities),
				"vulnerabilityRequested":       vulnerabilityRequestedValue(data.Vulnerabilities),
			},
			ExtractionRows:    extractionRows,
			VulnerabilityRows: vulnerabilityRows,
			IssueRows:         issueRows,
			ComponentIndex:    componentIndexRows,
		},
		Markdown: markdownProjectionV2{
			Sections: markdownSections,
			TOC:      markdownTOC,
			Anchors:  markdownAnchors,
		},
		HTML: htmlProjectionV2{
			SummaryCards: htmlSummaryCards,
			TableModels:  htmlTableModels,
		},
	}
}

func buildExtractionProjectionRows(tree *extract.ExtractionNode, index entityIndexV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0)
	var walk func(node *extract.ExtractionNode, depth int)
	walk = func(node *extract.ExtractionNode, depth int) {
		if node == nil {
			return
		}
		row := projectionRowV2{
			SourceRefs: sourceRefsOrNil(index.nodeByPath[node.Path]),
			Data: map[string]any{
				"kind":   "extraction-node",
				"path":   node.Path,
				"status": node.Status.String(),
				"format": node.Format.Format.String(),
				"tool":   node.Tool,
				"detail": node.StatusDetail,
				"depth":  depth,
			},
		}
		rows = append(rows, row)
		for _, child := range node.Children {
			walk(child, depth+1)
		}
	}
	walk(tree, 0)
	return rows
}

func buildVulnerabilityProjectionRows(entities entitiesV2) []projectionRowV2 {
	componentByID := make(map[string]componentEntityV2, len(entities.Components))
	for i := range entities.Components {
		componentByID[entities.Components[i].ID] = entities.Components[i]
	}

	rows := make([]projectionRowV2, 0, len(entities.Vulnerabilities))
	for i := range entities.Vulnerabilities {
		refs := []string{entities.Vulnerabilities[i].ID}
		component := componentEntityV2{}
		if entities.Vulnerabilities[i].ComponentID != "" {
			refs = append(refs, entities.Vulnerabilities[i].ComponentID)
			component = componentByID[entities.Vulnerabilities[i].ComponentID]
		}
		row := projectionRowV2{
			SourceRefs: refs,
			Data: map[string]any{
				"kind":            "vulnerability",
				"vulnerabilityId": entities.Vulnerabilities[i].VulnerabilityID,
				"severity":        entities.Vulnerabilities[i].Severity,
				"packageName":     component.Name,
				"installed":       component.Version,
				"bomRef":          entities.Vulnerabilities[i].BOMRef,
			},
		}
		if entities.Vulnerabilities[i].ComponentID == "" {
			row.ResolutionStatus = "missing"
			row.ResolutionReason = "component reference missing in vulnerability entity"
		}
		rows = append(rows, row)
	}
	return rows
}

func buildIssueProjectionRows(entities entitiesV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0, len(entities.Issues))
	for i := range entities.Issues {
		rows = append(rows, projectionRowV2{
			SourceRefs: []string{entities.Issues[i].ID},
			Data: map[string]any{
				"kind":    "issue",
				"stage":   entities.Issues[i].Stage,
				"message": entities.Issues[i].Message,
			},
		})
	}
	return rows
}

func buildComponentIndexProjectionRows(groups []domain.PackageOccurrenceGroup, index entityIndexV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0)
	for i := range groups {
		groupRefs := make([]string, 0, len(groups[i].Occurrences))
		for j := range groups[i].Occurrences {
			if componentID := index.componentByRef[groups[i].Occurrences[j].ObjectID]; componentID != "" {
				groupRefs = append(groupRefs, componentID)
			}
		}
		groupRefs = dedupeSortedStrings(sortedStrings(groupRefs))
		rows = append(rows, projectionRowV2{
			SourceRefs: fallbackSourceRefs(groupRefs),
			Data: map[string]any{
				"kind":            "package-group",
				"anchorId":        groups[i].AnchorID,
				"packageName":     groups[i].PackageName,
				"version":         groups[i].Version,
				"purls":           groups[i].PURLs,
				"occurrenceCount": len(groups[i].Occurrences),
			},
		})
		for j := range groups[i].Occurrences {
			componentID := index.componentByRef[groups[i].Occurrences[j].ObjectID]
			if componentID == "" {
				continue
			}
			rows = append(rows, projectionRowV2{
				SourceRefs: []string{componentID},
				Data: map[string]any{
					"kind":            "occurrence",
					"packageAnchorId": groups[i].AnchorID,
					"anchorId":        occurrenceAnchorID(groups[i].Occurrences[j].ObjectID),
					"objectId":        groups[i].Occurrences[j].ObjectID,
					"deliveryPaths":   groups[i].Occurrences[j].DeliveryPaths,
					"evidencePaths":   groups[i].Occurrences[j].EvidencePaths,
					"evidenceSource":  groups[i].Occurrences[j].EvidenceSource,
					"foundBy":         groups[i].Occurrences[j].FoundBy,
				},
			})
		}
	}
	return rows
}

func buildComponentFallbackProjectionRows(components []componentEntityV2) []projectionRowV2 {
	rows := make([]projectionRowV2, 0, len(components))
	for i := range components {
		rows = append(rows, projectionRowV2{
			SourceRefs: []string{components[i].ID},
			Data: map[string]any{
				"kind":        "component-fallback",
				"packageName": components[i].Name,
				"version":     components[i].Version,
				"purl":        components[i].PURL,
				"bomRef":      components[i].BOMRef,
			},
		})
	}
	return rows
}

func buildMarkdownProjectionRows(entities entitiesV2, extractionRows, vulnerabilityRows, componentIndexRows []projectionRowV2) ([]projectionRowV2, []projectionRowV2, []projectionRowV2) {
	fallback := firstProjectionSourceRef(entities)
	sections := []struct {
		key    string
		anchor string
		level  int
		refs   []string
	}{
		{key: "summary", anchor: "summary", level: 0, refs: collectComponentIDs(entities.Components)},
		{key: "processing-issues", anchor: "processing-errors", level: 0, refs: collectIssueIDs(entities.Issues)},
		{key: "component-index", anchor: "component-occurrence-index", level: 1, refs: collectComponentIDs(entities.Components)},
		{key: "policy", anchor: "policy-decisions", level: 1, refs: collectPolicyDecisionIDs(entities.PolicyDecisions)},
		{key: "scan", anchor: "scan-results", level: 1, refs: collectScanTaskIDs(entities.ScanTasks)},
		{key: "extraction", anchor: "extraction-log", level: 1, refs: collectNodeIDs(entities.Nodes)},
		{key: "vulnerabilities", anchor: "vulnerability-summary", level: 1, refs: collectVulnerabilityIDs(entities.Vulnerabilities)},
	}

	sectionRows := make([]projectionRowV2, 0, len(sections))
	tocRows := make([]projectionRowV2, 0, len(sections))
	anchorRows := make([]projectionRowV2, 0)

	for _, section := range sections {
		refs := preferredOrFallback(section.refs, fallback)
		if len(refs) == 0 {
			continue
		}
		data := map[string]any{"kind": "section", "key": section.key, "anchor": section.anchor, "level": section.level}
		sectionRows = append(sectionRows, projectionRowV2{SourceRefs: refs, Data: data})
		tocRows = append(tocRows, projectionRowV2{SourceRefs: refs, Data: map[string]any{"kind": "toc-entry", "key": section.key, "anchor": section.anchor, "level": section.level}})
	}

	for i := range componentIndexRows {
		if componentIndexRows[i].Data == nil {
			continue
		}
		anchor, _ := componentIndexRows[i].Data["anchorId"].(string)
		if anchor == "" {
			continue
		}
		anchorRows = append(anchorRows, projectionRowV2{SourceRefs: componentIndexRows[i].SourceRefs, Data: map[string]any{"kind": "anchor", "anchor": anchor}})
	}
	for i := range extractionRows {
		if extractionRows[i].Data == nil {
			continue
		}
		path, _ := extractionRows[i].Data["path"].(string)
		if path == "" {
			continue
		}
		anchorRows = append(anchorRows, projectionRowV2{SourceRefs: extractionRows[i].SourceRefs, Data: map[string]any{"kind": "extraction-anchor", "path": path}})
	}
	for i := range vulnerabilityRows {
		if vulnerabilityRows[i].Data == nil {
			continue
		}
		vulnID, _ := vulnerabilityRows[i].Data["vulnerabilityId"].(string)
		if vulnID == "" {
			continue
		}
		anchorRows = append(anchorRows, projectionRowV2{SourceRefs: vulnerabilityRows[i].SourceRefs, Data: map[string]any{"kind": "vulnerability-anchor", "vulnerabilityId": vulnID}})
	}

	return sectionRows, tocRows, anchorRows
}

func buildHTMLProjectionRows(data ReportData, entities entitiesV2, extractionRows, vulnerabilityRows, issueRows []projectionRowV2) ([]projectionRowV2, []projectionRowV2) {
	summaryCards := make([]projectionRowV2, 0, 4)
	tableModels := make([]projectionRowV2, 0, 3)

	summaryCards = append(summaryCards,
		projectionRowV2{SourceRefs: preferredOrFallback(collectComponentIDs(entities.Components), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "components", "count": len(entities.Components)}},
		projectionRowV2{SourceRefs: preferredOrFallback(collectVulnerabilityIDs(entities.Vulnerabilities), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "vulnerabilities", "count": len(entities.Vulnerabilities), "state": vulnerabilityStateValue(data.Vulnerabilities)}},
		projectionRowV2{SourceRefs: preferredOrFallback(collectIssueIDs(entities.Issues), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "issues", "count": len(entities.Issues)}},
		projectionRowV2{SourceRefs: preferredOrFallback(collectNodeIDs(entities.Nodes), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "summary-card", "name": "extraction", "count": len(extractionRows)}},
	)

	tableModels = append(tableModels,
		projectionRowV2{SourceRefs: preferredOrFallback(collectVulnerabilityIDs(entities.Vulnerabilities), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "table-model", "name": "vulnerabilities", "rowCount": len(vulnerabilityRows), "columns": []string{"vulnerabilityId", "severity", "packageName", "installed"}}},
		projectionRowV2{SourceRefs: preferredOrFallback(collectIssueIDs(entities.Issues), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "table-model", "name": "issues", "rowCount": len(issueRows), "columns": []string{"stage", "message"}}},
		projectionRowV2{SourceRefs: preferredOrFallback(collectNodeIDs(entities.Nodes), firstProjectionSourceRef(entities)), Data: map[string]any{"kind": "table-model", "name": "extraction-log", "rowCount": len(extractionRows), "columns": []string{"path", "format", "status", "tool", "detail"}}},
	)

	return summaryCards, tableModels
}

func vulnerabilityStateValue(v *vulnscan.Result) string {
	if v == nil {
		return string(vulnscan.StateNotRequested)
	}
	if v.State == "" {
		return string(vulnscan.StateNotRequested)
	}
	return string(v.State)
}

func vulnerabilityRequestedValue(v *vulnscan.Result) bool {
	return v != nil && v.Requested
}

func sourceRefsOrNil(ref string) []string {
	if ref == "" {
		return nil
	}
	return []string{ref}
}

func preferredOrFallback(refs []string, fallback []string) []string {
	if len(refs) > 0 {
		return refs
	}
	return fallback
}

func fallbackSourceRefs(refs []string) []string {
	if len(refs) > 0 {
		return refs
	}
	return []string{}
}

func firstProjectionSourceRef(entities entitiesV2) []string {
	if ids := collectNodeIDs(entities.Nodes); len(ids) > 0 {
		return ids[:1]
	}
	if ids := collectComponentIDs(entities.Components); len(ids) > 0 {
		return ids[:1]
	}
	if ids := collectIssueIDs(entities.Issues); len(ids) > 0 {
		return ids[:1]
	}
	if ids := collectScanTaskIDs(entities.ScanTasks); len(ids) > 0 {
		return ids[:1]
	}
	return nil
}

func collectNodeIDs(in []nodeEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

func collectScanTaskIDs(in []scanTaskEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

func collectComponentIDs(in []componentEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

func collectVulnerabilityIDs(in []vulnerabilityEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

func collectPolicyDecisionIDs(in []policyDecisionEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

func collectIssueIDs(in []issueEntityV2) []string {
	out := make([]string, 0, len(in))
	for i := range in {
		out = append(out, in[i].ID)
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func occurrenceAnchorID(objectID string) string {
	if objectID == "" {
		return "component-occurrence"
	}

	var b strings.Builder
	b.WriteString("component-")
	for _, r := range strings.ToLower(objectID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.TrimRight(b.String(), "-")
}

func buildIntegrityV2(entities entitiesV2, projections projectionsV2) integrityV2 {
	allEntityIDs := map[string]struct{}{}
	nodeIDs := map[string]struct{}{}
	componentIDs := map[string]struct{}{}

	for i := range entities.Nodes {
		allEntityIDs[entities.Nodes[i].ID] = struct{}{}
		nodeIDs[entities.Nodes[i].ID] = struct{}{}
	}
	for i := range entities.ScanTasks {
		allEntityIDs[entities.ScanTasks[i].ID] = struct{}{}
	}
	for i := range entities.Components {
		allEntityIDs[entities.Components[i].ID] = struct{}{}
		componentIDs[entities.Components[i].ID] = struct{}{}
	}
	for i := range entities.PackageGroups {
		allEntityIDs[entities.PackageGroups[i].ID] = struct{}{}
	}
	for i := range entities.Vulnerabilities {
		allEntityIDs[entities.Vulnerabilities[i].ID] = struct{}{}
	}
	for i := range entities.Suppressions {
		allEntityIDs[entities.Suppressions[i].ID] = struct{}{}
	}
	for i := range entities.PolicyDecisions {
		allEntityIDs[entities.PolicyDecisions[i].ID] = struct{}{}
	}
	for i := range entities.Issues {
		allEntityIDs[entities.Issues[i].ID] = struct{}{}
	}

	validationErrors := make([]string, 0)
	dangling := 0

	addMissing := func(msg string) {
		dangling++
		validationErrors = append(validationErrors, msg)
	}

	for i := range entities.ScanTasks {
		if entities.ScanTasks[i].NodeID == "" {
			addMissing(fmt.Sprintf("scanTasks[%d] missing nodeId", i))
		} else if _, ok := nodeIDs[entities.ScanTasks[i].NodeID]; !ok {
			addMissing(fmt.Sprintf("scanTasks[%d] references unknown nodeId %q", i, entities.ScanTasks[i].NodeID))
		}
		for j := range entities.ScanTasks[i].ComponentIDs {
			if _, ok := componentIDs[entities.ScanTasks[i].ComponentIDs[j]]; !ok {
				addMissing(fmt.Sprintf("scanTasks[%d] references unknown componentId %q", i, entities.ScanTasks[i].ComponentIDs[j]))
			}
		}
	}

	for i := range entities.PackageGroups {
		for j := range entities.PackageGroups[i].ComponentIDs {
			if _, ok := componentIDs[entities.PackageGroups[i].ComponentIDs[j]]; !ok {
				addMissing(fmt.Sprintf("packageGroups[%d] references unknown componentId %q", i, entities.PackageGroups[i].ComponentIDs[j]))
			}
		}
	}

	for i := range entities.Vulnerabilities {
		if entities.Vulnerabilities[i].ComponentID == "" {
			addMissing(fmt.Sprintf("vulnerabilities[%d] missing componentId", i))
			continue
		}
		if _, ok := componentIDs[entities.Vulnerabilities[i].ComponentID]; !ok {
			addMissing(fmt.Sprintf("vulnerabilities[%d] references unknown componentId %q", i, entities.Vulnerabilities[i].ComponentID))
		}
	}

	for i := range entities.Suppressions {
		if entities.Suppressions[i].SuppressedComponentID != "" {
			if _, ok := componentIDs[entities.Suppressions[i].SuppressedComponentID]; !ok {
				addMissing(fmt.Sprintf("suppressions[%d] references unknown suppressedComponentId %q", i, entities.Suppressions[i].SuppressedComponentID))
			}
		}
		if entities.Suppressions[i].KeptComponentID != "" {
			if _, ok := componentIDs[entities.Suppressions[i].KeptComponentID]; !ok {
				addMissing(fmt.Sprintf("suppressions[%d] references unknown keptComponentId %q", i, entities.Suppressions[i].KeptComponentID))
			}
		}
	}

	for i := range entities.PolicyDecisions {
		if entities.PolicyDecisions[i].NodeID == "" {
			continue
		}
		if _, ok := nodeIDs[entities.PolicyDecisions[i].NodeID]; !ok {
			addMissing(fmt.Sprintf("policyDecisions[%d] references unknown nodeId %q", i, entities.PolicyDecisions[i].NodeID))
		}
	}

	projectionRows := append([]projectionRowV2{}, projections.Generic.ExtractionRows...)
	projectionRows = append(projectionRows, projections.Generic.VulnerabilityRows...)
	projectionRows = append(projectionRows, projections.Generic.IssueRows...)
	projectionRows = append(projectionRows, projections.Generic.ComponentIndex...)
	projectionRows = append(projectionRows, projections.Markdown.Sections...)
	projectionRows = append(projectionRows, projections.Markdown.TOC...)
	projectionRows = append(projectionRows, projections.Markdown.Anchors...)
	projectionRows = append(projectionRows, projections.HTML.SummaryCards...)
	projectionRows = append(projectionRows, projections.HTML.TableModels...)
	for i := range projectionRows {
		for j := range projectionRows[i].SourceRefs {
			if _, ok := allEntityIDs[projectionRows[i].SourceRefs[j]]; !ok {
				addMissing(fmt.Sprintf("projection row %d references unknown sourceRef %q", i, projectionRows[i].SourceRefs[j]))
			}
		}
	}

	state := "ok"
	if dangling > 0 {
		state = "warning"
	}

	return integrityV2{
		Counts: integrityCountsV2{
			Nodes:           len(entities.Nodes),
			ScanTasks:       len(entities.ScanTasks),
			Components:      len(entities.Components),
			PackageGroups:   len(entities.PackageGroups),
			Vulnerabilities: len(entities.Vulnerabilities),
			Suppressions:    len(entities.Suppressions),
			PolicyDecisions: len(entities.PolicyDecisions),
			Issues:          len(entities.Issues),
		},
		DanglingReferenceCount: dangling,
		ValidationState:        state,
		ValidationErrors:       validationErrors,
	}
}

func componentNameKey(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" && version == "" {
		return ""
	}
	return name + "\x00" + version
}

func dedupeSortedStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for i := 1; i < len(in); i++ {
		if in[i] == in[i-1] {
			continue
		}
		out = append(out, in[i])
	}
	return out
}

func stableID(prefix string, parts ...string) string {
	input := strings.Join(parts, "\x1f")
	sum := sha256.Sum256([]byte(input))
	return prefix + ":" + hex.EncodeToString(sum[:12])
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
