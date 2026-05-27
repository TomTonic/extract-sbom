// Package report implements extract-sbom audit report generation.
//
// This file defines report-internal helper types and canonical anchor
// constants. Root report contract types are aliased from the internal model
// package so the root package can act as a thin facade.
package report

import model "github.com/TomTonic/extract-sbom/internal/report/internal/model"

// ToolVersions aliases the shared report tool-version contract from model.
type ToolVersions = model.ToolVersions

// InputSummary aliases the shared input summary contract from model.
type InputSummary = model.InputSummary

// SandboxSummary aliases the shared sandbox summary contract from model.
type SandboxSummary = model.SandboxSummary

// ProcessingIssue aliases the shared processing-issue contract from model.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract from model.
//
//nolint:revive // Stutter is kept intentionally for the root facade API during package extraction.
type ReportData = model.ReportData
