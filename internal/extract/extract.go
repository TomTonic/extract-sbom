// Package extract implements recursive, auditable extraction of archive formats.
//
// It applies the Syft-first principle: every file is first checked for
// Syft-native handling; extract-sbom only extracts when Syft cannot see through
// a container format.
//
// Implementation files are responsibility-focused:
// - types.go: extraction domain model and statuses
// - extract_flow.go: recursive traversal and status assignment flow
// - extract_inprocess.go: ZIP/TAR extraction paths with safeguard checks
// - extract_external.go: sandboxed 7zz/unshield extraction and tool lookup
// - msi.go: direct MSI metadata parsing from OLE streams
package extract
