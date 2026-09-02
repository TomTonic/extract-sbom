package html

import (
	"strings"
	"testing"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
	reportjson "github.com/TomTonic/extract-sbom/internal/report/internal/json"
)

// TestBuildSuppRowResolved verifies that a resolved suppression (a surviving
// duplicate exists) is rendered as a link to the kept component instead of
// the generic "no indexed match" reason.
func TestBuildSuppRowResolved(t *testing.T) {
	t.Parallel()

	tr := i18npkg.For("en")
	row := &reportjson.SuppressionRowV2{
		DeliveryPath:      "lib/dup.jar",
		ResolutionStatus:  "resolved",
		KeptComponentName: "lib-1.0.jar",
		KeptAnchorID:      "comp-abc123",
	}

	got := buildSuppRow(row, "dup.jar", tr)

	if got.DeliveryPath != "lib/dup.jar" {
		t.Errorf("DeliveryPath = %q, want %q", got.DeliveryPath, "lib/dup.jar")
	}
	if got.Name != "dup.jar" {
		t.Errorf("Name = %q, want %q", got.Name, "dup.jar")
	}
	if got.KeptName != "lib-1.0.jar" {
		t.Errorf("KeptName = %q, want %q", got.KeptName, "lib-1.0.jar")
	}
	if got.KeptAnchor != "comp-abc123" {
		t.Errorf("KeptAnchor = %q, want %q", got.KeptAnchor, "comp-abc123")
	}
	if got.Reason != "" {
		t.Errorf("Reason = %q, want empty when resolved", got.Reason)
	}
}

// TestBuildSuppRowUnresolved verifies that a suppression with no surviving
// duplicate falls back to the generic "no indexed match" reason and leaves
// the kept-component fields empty.
func TestBuildSuppRowUnresolved(t *testing.T) {
	t.Parallel()

	tr := i18npkg.For("en")
	row := &reportjson.SuppressionRowV2{
		DeliveryPath:     "lib/orphan.jar",
		ResolutionStatus: "unresolved",
	}

	got := buildSuppRow(row, "orphan.jar", tr)

	if got.KeptName != "" || got.KeptAnchor != "" {
		t.Errorf("KeptName/KeptAnchor = %q/%q, want both empty", got.KeptName, got.KeptAnchor)
	}
	if !strings.Contains(string(got.Reason), "no surviving package component") {
		t.Errorf("Reason = %q, want it to mention no surviving package component", got.Reason)
	}
}

// TestBuildSuppRowResolvedWithoutKeptName verifies that a "resolved" status
// with an empty KeptComponentName still falls back to the generic reason,
// matching the && condition in buildSuppRow.
func TestBuildSuppRowResolvedWithoutKeptName(t *testing.T) {
	t.Parallel()

	tr := i18npkg.For("en")
	row := &reportjson.SuppressionRowV2{
		DeliveryPath:     "lib/orphan.jar",
		ResolutionStatus: "resolved",
	}

	got := buildSuppRow(row, "orphan.jar", tr)

	if got.KeptName != "" {
		t.Errorf("KeptName = %q, want empty", got.KeptName)
	}
	if got.Reason == "" {
		t.Error("Reason = empty, want fallback reason text")
	}
}
