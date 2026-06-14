package html

import (
	"fmt"
	"sort"
	"strings"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

func buildExtensionFilter(skipExtensions []string, proj reportjson.ProjectionsV2, t i18npkg.Bundle) extensionFilterSection {
	s := extensionFilterSection{
		Heading:         t.ExtensionFilterSection,
		Anchor:          anchorExtensionFilter,
		Lead:            t.ExtensionFilterLead,
		ExtensionsLabel: t.ExtensionFilterExtensionsLabel,
		SkippedLabel:    t.ExtensionFilterSkippedLabel,
		EmptyText:       t.NoExtensionFilteredFiles,
	}
	if len(skipExtensions) == 0 {
		s.Empty = true
		return s
	}
	exts := append([]string(nil), skipExtensions...)
	sort.Strings(exts)
	quoted := make([]string, len(exts))
	for i, e := range exts {
		quoted[i] = "`" + e + "`"
	}
	s.Extensions = strings.Join(quoted, ", ")
	paths := append([]string(nil), proj.Summary.ExtensionFilteredPaths...)
	sort.Strings(paths)
	s.SkippedPaths = paths
	return s
}

func buildRootMetadata(root *reportjson.BOMRootComponentV2, t i18npkg.Bundle) rootMetadataSection {
	s := rootMetadataSection{
		Heading: t.RootMetadataSection,
		Anchor:  anchorRootMetadata,
		Headers: []string{t.Field, t.Value, t.Source},
	}
	if root == nil {
		return s
	}
	if root.BOMRef != "" {
		s.Rows = append(s.Rows, []string{t.ObjectID, root.BOMRef, t.Derived})
	}
	if root.Name != "" {
		s.Rows = append(s.Rows, []string{t.PackageName, root.Name, t.Derived})
	}
	if root.Version != "" {
		s.Rows = append(s.Rows, []string{t.Version, root.Version, t.Derived})
	}
	if len(root.ConfigProperties) > 0 {
		keys := make([]string, 0, len(root.ConfigProperties))
		for k := range root.ConfigProperties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s.Rows = append(s.Rows, []string{k, root.ConfigProperties[k], t.SuppliedBy})
		}
	}
	return s
}

func buildPolicy(decisions []reportjson.PolicyDecisionRowV2, t i18npkg.Bundle) policySection {
	s := policySection{Heading: t.PolicySection, Anchor: anchorPolicy, EmptyText: t.NoPolicyDecisions}
	if len(decisions) == 0 {
		s.Empty = true
		return s
	}
	s.Headers = []string{"Trigger", t.DeliveryPath, t.ProcessingDetailHeader, "Action"}
	for _, d := range decisions {
		s.Rows = append(s.Rows, []string{d.Trigger, d.NodePath, d.Detail, d.Action})
	}
	return s
}

func buildScanLog(proj reportjson.ProjectionsV2, t i18npkg.Bundle) scanLogSection {
	s := scanLogSection{
		Heading:        t.ScanSection,
		Anchor:         anchorScan,
		Lead:           t.ScanSectionLead,
		Headers:        []string{t.DeliveryPath, t.ComponentsFound, t.ScanTaskEvidenceLabel},
		NoPkgHeading:   t.ScanNoPackageIDsSection,
		NoPkgAnchor:    anchorScanNoPackageIDs,
		NoPkgEmptyText: t.NoScanNoPackageIDs,
	}
	for i := range proj.Scans {
		row := &proj.Scans[i]
		sr := scanRow{NodePath: row.NodePath}
		switch {
		case row.Error != "":
			sr.Error = row.Error
		case row.ComponentCount > 0:
			sr.Count = fmt.Sprintf("%d", row.ComponentCount)
			sr.Evidence = row.EvidencePaths
		default:
			sr.Count = t.NoComponents
		}
		s.Rows = append(s.Rows, sr)
	}
	if len(proj.Summary.ScanNoPackagePaths) == 0 {
		s.NoPkgEmpty = true
	} else {
		s.NoPkgLead = fmt.Sprintf(t.ScanNoPackageIDsLead, len(proj.Summary.ScanNoPackagePaths))
		s.NoPkgPaths = proj.Summary.ScanNoPackagePaths
	}
	return s
}

func buildExtraction(rows []reportjson.ExtractionLogRowV2, t i18npkg.Bundle) extractionSection {
	s := extractionSection{
		Heading: t.ExtractionSection,
		Anchor:  anchorExtraction,
		Headers: []string{"Path", "Format", t.Status, t.Tool, t.ExtractionSandboxLabel, t.ProcessingDetailHeader},
	}
	for i := range rows {
		row := &rows[i]
		depth := row.Depth
		if depth > 5 {
			depth = 5
		}
		detail := row.Detail
		if meta := formatExtractionArchiveMeta(row.ArchiveMeta); meta != "" {
			if detail != "" {
				detail = meta + " " + detail
			} else {
				detail = meta
			}
		}
		shortPath := row.Path
		if idx := strings.LastIndex(row.Path, "/"); idx >= 0 {
			shortPath = row.Path[idx+1:]
		}
		s.Rows = append(s.Rows, extractionRow{
			Depth:     depth,
			Path:      row.Path,
			ShortPath: shortPath,
			Format:    row.Format,
			Status:    row.Status,
			Tool:      row.Tool,
			Sandbox:   row.SandboxUsed,
			Detail:    detail,
		})
	}
	return s
}
