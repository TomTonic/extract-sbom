package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/assembly"
	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

func TestUniqueSortedPathsEmpty(t *testing.T) {
	t.Parallel()
	if got := uniqueSortedPaths(nil); got != nil {
		t.Fatalf("uniqueSortedPaths(nil) = %v, want nil", got)
	}
}

func TestUniqueSortedPathsDedupsAndSorts(t *testing.T) {
	t.Parallel()
	input := []string{"b/path", "a/path", "", "b/path", "c/path", ""}
	got := uniqueSortedPaths(input)
	want := []string{"a/path", "b/path", "c/path"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCompareOccurrenceAllFields(t *testing.T) {
	t.Parallel()

	base := componentOccurrence{
		ObjectID:      "extract-sbom:AAA",
		PackageName:   "alpha",
		Version:       "1.0.0",
		PURL:          "pkg:maven/alpha@1.0.0",
		DeliveryPaths: []string{"a/path"},
		EvidencePaths: []string{"a/evidence"},
		FoundBy:       "java-archive-cataloger",
	}

	tests := []struct {
		name string
		a, b componentOccurrence
		want int
	}{
		{"equal", base, base, 0},
		{"delivery path less", func() componentOccurrence {
			c := base
			c.DeliveryPaths = []string{"a/earlier"}
			return c
		}(), base, -1},
		{"delivery path greater", base, func() componentOccurrence {
			c := base
			c.DeliveryPaths = []string{"a/earlier"}
			return c
		}(), 1},
		{"evidence path less", func() componentOccurrence {
			c := base
			c.EvidencePaths = []string{"a/a"}
			return c
		}(), func() componentOccurrence {
			c := base
			c.EvidencePaths = []string{"a/z"}
			return c
		}(), -1},
		{"package name less", func() componentOccurrence {
			c := base
			c.PackageName = "aaa"
			return c
		}(), func() componentOccurrence {
			c := base
			c.PackageName = "zzz"
			return c
		}(), -1},
		{"version less", func() componentOccurrence {
			c := base
			c.Version = "1.0.0"
			return c
		}(), func() componentOccurrence {
			c := base
			c.Version = "2.0.0"
			return c
		}(), -1},
		{"purl less", func() componentOccurrence {
			c := base
			c.PURL = "pkg:a"
			return c
		}(), func() componentOccurrence {
			c := base
			c.PURL = "pkg:z"
			return c
		}(), -1},
		{"foundby less", func() componentOccurrence {
			c := base
			c.FoundBy = "aaa"
			return c
		}(), func() componentOccurrence {
			c := base
			c.FoundBy = "zzz"
			return c
		}(), -1},
		{"objectid less", func() componentOccurrence {
			c := base
			c.ObjectID = "extract-sbom:AAA"
			return c
		}(), func() componentOccurrence {
			c := base
			c.ObjectID = "extract-sbom:ZZZ"
			return c
		}(), -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareOccurrence(tt.a, tt.b)
			if (tt.want < 0 && got >= 0) || (tt.want > 0 && got <= 0) || (tt.want == 0 && got != 0) {
				t.Fatalf("compareOccurrence() = %d, want sign %d", got, tt.want)
			}
		})
	}
}

func TestCollectSuppressionStats(t *testing.T) {
	t.Parallel()

	records := []assembly.SuppressionRecord{
		{Reason: assembly.SuppressionFSArtifact},
		{Reason: assembly.SuppressionFSArtifact},
		{Reason: assembly.SuppressionLowValueFile},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionWeakDuplicate},
		{Reason: assembly.SuppressionPURLDuplicate},
	}

	stats := collectSuppressionStats(records)
	if stats.FSArtifacts != 2 {
		t.Errorf("FSArtifacts = %d, want 2", stats.FSArtifacts)
	}
	if stats.LowValueFiles != 1 {
		t.Errorf("LowValueFiles = %d, want 1", stats.LowValueFiles)
	}
	if stats.WeakDuplicate != 3 {
		t.Errorf("WeakDuplicate = %d, want 3", stats.WeakDuplicate)
	}
	if stats.PURLDuplicate != 1 {
		t.Errorf("PURLDuplicate = %d, want 1", stats.PURLDuplicate)
	}
}

func TestCollectSuppressionStatsEmpty(t *testing.T) {
	t.Parallel()
	stats := collectSuppressionStats(nil)
	if stats.FSArtifacts != 0 || stats.LowValueFiles != 0 || stats.WeakDuplicate != 0 || stats.PURLDuplicate != 0 {
		t.Fatal("empty input should produce zero stats")
	}
}

func TestCollectExtractionStats(t *testing.T) {
	t.Parallel()

	tree := &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Path: "a.jar", Status: extract.StatusSyftNative},
			{Path: "b.cab", Status: extract.StatusFailed, StatusDetail: "7zz error"},
			{Path: "c.msi", Status: extract.StatusToolMissing},
			{Path: "d.iso", Status: extract.StatusSecurityBlocked},
			{Path: "e.tar", Status: extract.StatusSkipped},
			{Path: "f.zip", Status: extract.StatusPending},
			{
				Path:                   "g.zip",
				Status:                 extract.StatusExtracted,
				ExtensionFilteredPaths: []string{"g.zip/skip.dll"},
			},
		},
	}

	stats := collectExtractionStats(tree)
	if stats.Total != 8 {
		t.Errorf("Total = %d, want 8", stats.Total)
	}
	if stats.Extracted != 2 {
		t.Errorf("Extracted = %d, want 2", stats.Extracted)
	}
	if stats.SyftNative != 1 {
		t.Errorf("SyftNative = %d, want 1", stats.SyftNative)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
	if stats.ToolMissing != 1 {
		t.Errorf("ToolMissing = %d, want 1", stats.ToolMissing)
	}
	if stats.SecurityBlocked != 1 {
		t.Errorf("SecurityBlocked = %d, want 1", stats.SecurityBlocked)
	}
	if stats.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", stats.Skipped)
	}
	if stats.Pending != 1 {
		t.Errorf("Pending = %d, want 1", stats.Pending)
	}
	if stats.ExtensionFiltered != 1 {
		t.Errorf("ExtensionFiltered = %d, want 1", stats.ExtensionFiltered)
	}
}

func TestCollectExtractionStatsNilTree(t *testing.T) {
	t.Parallel()
	stats := collectExtractionStats(nil)
	if stats.Total != 0 {
		t.Errorf("Total = %d, want 0", stats.Total)
	}
}

func TestCollectProcessingEntriesFromTree(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Path: "a.cab", Status: extract.StatusFailed, StatusDetail: "7zz exit 2"},
			{Path: "b.msi", Status: extract.StatusToolMissing},
			{Path: "c.zip", Status: extract.StatusSecurityBlocked, StatusDetail: "zip bomb"},
		},
	}
	data.ProcessingIssues = []ProcessingIssue{
		{Stage: "assembly", Message: "merge error"},
	}
	data.Scans = []scan.ScanResult{
		{NodePath: "root.zip", Error: fmt.Errorf("syft failed")},
	}

	entries := collectProcessingEntries(data)
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 5", len(entries))
	}

	// Verify sources
	sources := make(map[string]int)
	for _, e := range entries {
		sources[e.Source]++
	}
	if sources["pipeline"] != 1 {
		t.Errorf("pipeline entries = %d, want 1", sources["pipeline"])
	}
	if sources["extraction"] != 3 {
		t.Errorf("extraction entries = %d, want 3", sources["extraction"])
	}
	if sources["scan"] != 1 {
		t.Errorf("scan entries = %d, want 1", sources["scan"])
	}
}

func TestCollectProcessingEntriesToolMissingFallbackDetail(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.Tree = &extract.ExtractionNode{
		Path:   "root.zip",
		Status: extract.StatusExtracted,
		Children: []*extract.ExtractionNode{
			{Path: "a.msi", Status: extract.StatusToolMissing},
		},
	}

	entries := collectProcessingEntries(data)
	found := false
	for _, e := range entries {
		if e.Location == "a.msi" {
			found = true
			if !strings.Contains(e.Detail, "status=") {
				t.Fatalf("expected fallback detail with status=, got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Fatal("tool-missing entry not found")
	}
}

func TestWriteScanNoPackageIdentitiesSubsection(t *testing.T) {
	t.Parallel()

	tr := getTranslations("en")

	t.Run("zero tasks", func(t *testing.T) {
		var buf bytes.Buffer
		writeScanNoPackageIdentitiesSubsection(&buf, scanStats{NoComponentTasks: 0}, tr)
		if !strings.Contains(buf.String(), tr.noScanNoPackageIDs) {
			t.Fatal("expected 'no items' message for zero-task case")
		}
	})

	t.Run("with paths", func(t *testing.T) {
		var buf bytes.Buffer
		stats := scanStats{
			NoComponentTasks: 2,
			NoComponentPaths: []string{"b/file.jar", "a/file.war"},
		}
		writeScanNoPackageIdentitiesSubsection(&buf, stats, tr)
		out := buf.String()
		if !strings.Contains(out, "`a/file.war`") || !strings.Contains(out, "`b/file.jar`") {
			t.Fatalf("expected both paths in output, got:\n%s", out)
		}
	})
}

func TestFirstStringEmpty(t *testing.T) {
	t.Parallel()
	if got := firstString(nil); got != "" {
		t.Fatalf("firstString(nil) = %q, want empty", got)
	}
}

func TestFirstStringNonEmpty(t *testing.T) {
	t.Parallel()
	if got := firstString([]string{"a", "b"}); got != "a" {
		t.Fatalf("firstString = %q, want a", got)
	}
}

func TestSortSuppressionRecords(t *testing.T) {
	t.Parallel()

	records := []assembly.SuppressionRecord{
		{DeliveryPath: "z/path", Component: cdx.Component{Name: "zlib"}},
		{DeliveryPath: "a/path", Component: cdx.Component{Name: "alpha"}},
		{DeliveryPath: "a/path", Component: cdx.Component{Name: "beta"}},
	}

	sortSuppressionRecords(records)
	if records[0].DeliveryPath != "a/path" || records[0].Component.Name != "alpha" {
		t.Fatalf("first record = %+v, want a/path alpha", records[0])
	}
	if records[1].DeliveryPath != "a/path" || records[1].Component.Name != "beta" {
		t.Fatalf("second record = %+v, want a/path beta", records[1])
	}
	if records[2].DeliveryPath != "z/path" {
		t.Fatalf("third record = %+v, want z/path", records[2])
	}
}

func TestBuildMachineTreeNilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := buildMachineTree(nil); got != nil {
		t.Fatal("buildMachineTree(nil) should return nil")
	}
}

func TestBuildMachineDecisions(t *testing.T) {
	t.Parallel()

	decisions := []machineDecision{}
	if len(decisions) != 0 {
		t.Fatal("baseline check")
	}
}

func TestCollectScanStats(t *testing.T) {
	t.Parallel()

	comps := []cdx.Component{{Name: "a"}, {Name: "b"}}
	scans := []scan.ScanResult{
		{NodePath: "good.jar", BOM: &cdx.BOM{Components: &comps}},
		{NodePath: "empty.jar", BOM: &cdx.BOM{}},
		{NodePath: "err.jar", Error: fmt.Errorf("fail")},
	}
	stats := collectScanStats(scans)
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.Successful != 2 {
		t.Errorf("Successful = %d, want 2", stats.Successful)
	}
	if stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1", stats.Errors)
	}
	if stats.TotalComponents != 2 {
		t.Errorf("TotalComponents = %d, want 2", stats.TotalComponents)
	}
	if stats.NoComponentTasks != 1 {
		t.Errorf("NoComponentTasks = %d, want 1", stats.NoComponentTasks)
	}
}

func TestCollectPolicyStats(t *testing.T) {
	t.Parallel()

	stats := collectPolicyStats(nil)
	if stats.Total != 0 {
		t.Errorf("Total = %d, want 0", stats.Total)
	}
}
