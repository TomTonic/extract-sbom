package orchestrator

import (
	"fmt"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func TestTreeHasHardSecurityNil(t *testing.T) {
	t.Parallel()
	if treeHasHardSecurity(nil) {
		t.Error("treeHasHardSecurity(nil) = true, want false")
	}
}

func TestTreeHasHardSecurityRoot(t *testing.T) {
	t.Parallel()
	node := &extract.ExtractionNode{Status: extract.StatusSecurityBlocked}
	if !treeHasHardSecurity(node) {
		t.Error("treeHasHardSecurity(blocked root) = false, want true")
	}
}

func TestTreeHasHardSecurityChild(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Status: extract.StatusExtracted},
			{Status: extract.StatusSecurityBlocked},
		},
	}
	if !treeHasHardSecurity(root) {
		t.Error("treeHasHardSecurity(child blocked) = false, want true")
	}
}

func TestTreeHasHardSecurityNoBlocked(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Status: extract.StatusExtracted},
			{Status: extract.StatusSkipped},
		},
	}
	if treeHasHardSecurity(root) {
		t.Error("treeHasHardSecurity(no blocked) = true, want false")
	}
}

func TestTreeHasIncompleteNil(t *testing.T) {
	t.Parallel()
	if treeHasIncomplete(nil) {
		t.Error("treeHasIncomplete(nil) = true, want false")
	}
}

func TestTreeHasIncompleteWithFailed(t *testing.T) {
	t.Parallel()
	node := &extract.ExtractionNode{Status: extract.StatusFailed}
	if !treeHasIncomplete(node) {
		t.Error("treeHasIncomplete(failed) = false, want true")
	}
}

func TestTreeHasIncompleteWithToolMissing(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Status: extract.StatusToolMissing},
		},
	}
	if !treeHasIncomplete(root) {
		t.Error("treeHasIncomplete(child tool-missing) = false, want true")
	}
}

func TestTreeHasIncompleteAllSuccess(t *testing.T) {
	t.Parallel()
	root := &extract.ExtractionNode{
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Status: extract.StatusExtracted},
			{Status: extract.StatusSyftNative},
		},
	}
	if treeHasIncomplete(root) {
		t.Error("treeHasIncomplete(all success) = true, want false")
	}
}

func TestHasScanFailuresEmpty(t *testing.T) {
	t.Parallel()
	if hasScanFailures(nil) {
		t.Error("hasScanFailures(nil) = true, want false")
	}
	if hasScanFailures([]scan.ScanResult{}) {
		t.Error("hasScanFailures(empty) = true, want false")
	}
}

func TestHasScanFailuresNoErrors(t *testing.T) {
	t.Parallel()
	scans := []scan.ScanResult{
		{NodePath: "a.zip"},
		{NodePath: "b.zip"},
	}
	if hasScanFailures(scans) {
		t.Error("hasScanFailures(no errors) = true, want false")
	}
}

func TestHasScanFailuresWithError(t *testing.T) {
	t.Parallel()
	scans := []scan.ScanResult{
		{NodePath: "a.zip"},
		{NodePath: "b.zip", Error: fmt.Errorf("scan failed")},
	}
	if !hasScanFailures(scans) {
		t.Error("hasScanFailures(with error) = false, want true")
	}
}
