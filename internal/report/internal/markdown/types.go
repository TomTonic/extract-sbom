// Package markdown implements the active Markdown-based markdown report renderer.
package markdown

import (
	model "github.com/TomTonic/extract-sbom/internal/report/internal/model"
)

// ToolVersions aliases the shared report tool-version contract from model.
type ToolVersions = model.ToolVersions

// InputSummary aliases the shared input summary contract from model.
type InputSummary = model.InputSummary

// SandboxSummary aliases the shared sandbox summary contract from model.
type SandboxSummary = model.SandboxSummary

// ProcessingIssue aliases the shared processing-issue contract from model.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract from model.
type ReportData = model.ReportData

// reportSection defines one TOC entry and heading anchor in the markdown report.
type reportSection struct {
	title  string
	anchor string
	level  int
}

const (
	scanApproachGitHubURL = "https://github.com/TomTonic/extract-sbom/blob/main/SCAN_APPROACH.md"

	anchorMethodOverview         = "method-at-a-glance"
	anchorAppendix               = "appendix"
	anchorInputFile              = "input-file"
	anchorConfig                 = "configuration"
	anchorExtensionFilter        = "extension-filter"
	anchorRootMetadata           = "root-sbom-metadata"
	anchorSandbox                = "sandbox-configuration"
	anchorSummary                = "summary"
	anchorProcessingErrors       = "processing-errors"
	anchorResidualRisk           = "residual-risk-and-limitations"
	anchorPolicy                 = "policy-decisions"
	anchorComponentIndex         = "component-occurrence-index"
	anchorComponentsWithPURL     = "components-with-purl"
	anchorComponentsWithoutPURL  = "components-without-purl"
	anchorSuppression            = "component-normalization"
	anchorSuppressionFSArtifacts = "suppression-fs-artifacts"
	anchorSuppressionLowValue    = "suppression-low-value-file-artifacts"
	anchorScan                   = "scan-results"
	anchorScanNoPackageIDs       = "content-items-without-package-identities"
	anchorExtraction             = "extraction-log"
	anchorSummaryAnalysis        = "analysis-overview"
	anchorSummaryKeyFindings     = "key-findings"
	anchorSummaryVuln            = "vulnerability-summary"
)
