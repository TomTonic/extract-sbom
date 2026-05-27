package machine

import (
	"testing"

	"github.com/TomTonic/extract-sbom/internal/policy"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func TestOrderingContractSlicesPreserveProcessingOrder(t *testing.T) {
	t.Parallel()

	scans := []scan.ScanResult{{NodePath: "z/path"}, {NodePath: "a/path"}}
	decisions := []policy.Decision{
		{Trigger: "max-files", NodePath: "z/path", Action: policy.ActionSkip, Detail: "skip z"},
		{Trigger: "max-depth", NodePath: "a/path", Action: policy.ActionContinue, Detail: "continue a"},
	}

	machineScans := buildScans(scans)
	if len(machineScans) != 2 || machineScans[0].NodePath != "z/path" || machineScans[1].NodePath != "a/path" {
		t.Fatalf("machine scan order changed: %+v", machineScans)
	}

	machineDecisions := buildDecisions(decisions)
	if len(machineDecisions) != 2 || machineDecisions[0].NodePath != "z/path" || machineDecisions[1].NodePath != "a/path" {
		t.Fatalf("machine decision order changed: %+v", machineDecisions)
	}
}
