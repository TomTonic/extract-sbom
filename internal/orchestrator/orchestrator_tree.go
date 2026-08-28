package orchestrator

import (
	"slices"

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
	return slices.ContainsFunc(node.Children, treeHasHardSecurity)
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
	return slices.ContainsFunc(node.Children, treeHasIncomplete)
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
