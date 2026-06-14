package json

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/TomTonic/extract-sbom/internal/assembly"
)

func TestCleanSuppressionComponentNameLogical(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"log4j-2.14.1.jar", "log4j-2.14.1.jar"},
		{"com.example/lib", "com.example/lib"},
		{"", ""},
	}
	for _, c := range cases {
		if got := cleanSuppressionComponentName(c.in); got != c.want {
			t.Errorf("cleanSuppressionComponentName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanSuppressionComponentNameAbsolutePath(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"/tmp/extract-sbom-7z-383614817/deep/path/SomeFile.jar", "SomeFile.jar"},
		{"/private/var/folders/abc/T/extract-sbom-7z-999/inner.dll", "inner.dll"},
		{"/usr/local/lib/libfoo.so", "libfoo.so"},
	}
	for _, c := range cases {
		if got := cleanSuppressionComponentName(c.in); got != c.want {
			t.Errorf("cleanSuppressionComponentName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildSuppressionGroupsStripsAbsolutePaths(t *testing.T) {
	t.Parallel()

	absName := "/tmp/extract-sbom-7z-999/nested/lib/SomeFile.jar"
	records := []assembly.SuppressionRecord{{
		Reason: assembly.SuppressionFSArtifact,
		Component: cdx.Component{
			BOMRef: "ref:abs",
			Name:   absName,
		},
		DeliveryPath: "delivery/lib/SomeFile.jar",
	}}

	groups := buildSuppressionGroupsProjection(records, nil, nil)
	if len(groups.FSArtifacts) != 1 {
		t.Fatalf("expected 1 FSArtifact suppression, got %d", len(groups.FSArtifacts))
	}
	got := groups.FSArtifacts[0].ComponentName
	if got != "SomeFile.jar" {
		t.Errorf("ComponentName = %q, want %q (absolute path must be stripped)", got, "SomeFile.jar")
	}
}
