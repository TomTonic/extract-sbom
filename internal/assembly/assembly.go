// Package assembly merges per-node CycloneDX BOMs into one consolidated SBOM.
//
// The implementation is split by responsibility to keep the behavior
// traceable and maintainable:
// - assemble_flow.go: orchestration, dependency/composition assembly
// - normalize_scan.go: per-node scan normalization and local dedup
// - global_dedup.go: cross-node PURL deduplication
// - bomref.go: deterministic BOMRef planning and assignment
// - output.go: SBOM writing and file/CPE helpers
package assembly
