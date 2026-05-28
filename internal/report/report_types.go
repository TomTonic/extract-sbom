// Package report implements extract-sbom audit report generation.
//
// This file defines report-internal helper types and canonical anchor
// constants. Root report contract types are aliased from the internal model
// package so the root package can act as a thin facade.
package report

import model "github.com/TomTonic/extract-sbom/internal/report/internal/model"

// InputSummary aliases the shared input summary contract from model.
type InputSummary = model.InputSummary

// ProcessingIssue aliases the shared processing-issue contract from model.
type ProcessingIssue = model.ProcessingIssue

// ReportData aliases the shared report snapshot contract from model.
//
//nolint:revive // Stutter is kept intentionally for the root facade API during package extraction.
type ReportData = model.ReportData
