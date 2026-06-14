package orchestrator

import (
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

// treeHasHardSecurity reports whether any node in the extraction tree ended in
// a hard security block state.
func treeHasHardSecurity(node *extract.ExtractionNode) bool {
	if node == nil {
		return false
	}
	if node.Status == extract.StatusSecurityBlocked {
		return true
	}
	for _, child := range node.Children {
		if treeHasHardSecurity(child) {
			return true
		}
	}
	return false
}

// treeHasIncomplete reports whether extraction contains failed, skipped, or
// tool-missing nodes that indicate incomplete analysis.
func treeHasIncomplete(node *extract.ExtractionNode) bool {
	if node == nil {
		return false
	}
	switch node.Status {
	case extract.StatusFailed, extract.StatusSkipped, extract.StatusToolMissing:
		return true
	}
	for _, child := range node.Children {
		if treeHasIncomplete(child) {
			return true
		}
	}
	return false
}

// hasScanFailures reports whether any scan task returned an execution error.
func hasScanFailures(scans []scan.ScanResult) bool {
	for _, scanResult := range scans {
		if scanResult.Error != nil {
			return true
		}
	}
	return false
}
