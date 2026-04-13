package buildinfo

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestReadUsesReleaseVersionOverride(t *testing.T) {
	old := ReleaseVersion
	ReleaseVersion = "v9.9.9"
	t.Cleanup(func() { ReleaseVersion = old })

	info := Read()
	if info.Version != "v9.9.9" {
		t.Fatalf("version = %q, want %q", info.Version, "v9.9.9")
	}
}

func TestReadDefaultPathWithoutReleaseVersion(t *testing.T) {
	old := ReleaseVersion
	ReleaseVersion = ""
	t.Cleanup(func() { ReleaseVersion = old })

	info := Read()
	// When run under `go test`, debug.ReadBuildInfo() succeeds and the default
	// Version should not be "(unknown)". It will be either the module version
	// or "(devel)" depending on how the test binary was built.
	if info.Version == "(unknown)" {
		t.Fatal("Version should not be (unknown) when ReadBuildInfo succeeds")
	}
}

func TestReadWhitespaceOnlyReleaseVersionIsIgnored(t *testing.T) {
	old := ReleaseVersion
	ReleaseVersion = "   \t\n  "
	t.Cleanup(func() { ReleaseVersion = old })

	info := Read()
	if info.Version == "   \t\n  " {
		t.Fatal("whitespace-only ReleaseVersion should not be used verbatim")
	}
}

func TestInfoStringFormatsFields(t *testing.T) {
	t.Parallel()

	info := Info{
		Version:  "v1.2.3",
		Revision: "0123456789abcdef",
		Time:     "2026-04-11T12:34:56Z",
		Modified: true,
	}

	got := info.String()
	want := "v1.2.3 rev 0123456789ab 2026-04-11T12:34:56Z dirty"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestInfoStringEmptyVersionFallback(t *testing.T) {
	t.Parallel()

	info := Info{}
	got := info.String()
	if !strings.HasPrefix(got, "(devel)") {
		t.Fatalf("String() = %q, want prefix (devel)", got)
	}
}

func TestInfoStringShortRevision(t *testing.T) {
	t.Parallel()

	info := Info{Version: "v1.0.0", Revision: "abc123"}
	got := info.String()
	if !strings.Contains(got, "rev abc123") {
		t.Fatalf("String() = %q, want short revision preserved", got)
	}
}

func TestInfoStringVersionOnly(t *testing.T) {
	t.Parallel()

	info := Info{Version: "v2.0.0"}
	got := info.String()
	if got != "v2.0.0" {
		t.Fatalf("String() = %q, want %q", got, "v2.0.0")
	}
}

func TestReadReleaseVersionSuppressesDirtyMarker(t *testing.T) {
	old := ReleaseVersion
	ReleaseVersion = "v1.2.3"
	t.Cleanup(func() { ReleaseVersion = old })

	info := Read()
	if info.Modified {
		t.Fatal("expected Modified=false when ReleaseVersion is injected")
	}
	if strings.Contains(info.String(), "dirty") {
		t.Fatalf("String() = %q, must not contain dirty for release builds", info.String())
	}
}

func TestReadFallsBackToUnknownWhenBuildInfoUnavailable(t *testing.T) {
	oldRV := ReleaseVersion
	oldFn := readBuildInfo
	ReleaseVersion = ""
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }
	t.Cleanup(func() {
		ReleaseVersion = oldRV
		readBuildInfo = oldFn
	})

	info := Read()
	if info.Version != "(unknown)" {
		t.Fatalf("Version = %q, want %q", info.Version, "(unknown)")
	}
}

func TestReadBuildInfoUnavailableWithReleaseVersion(t *testing.T) {
	oldRV := ReleaseVersion
	oldFn := readBuildInfo
	ReleaseVersion = "v3.0.0"
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }
	t.Cleanup(func() {
		ReleaseVersion = oldRV
		readBuildInfo = oldFn
	})

	info := Read()
	if info.Version != "v3.0.0" {
		t.Fatalf("Version = %q, want %q", info.Version, "v3.0.0")
	}
}

func TestReadUsesMainVersionWhenNoDevelOverride(t *testing.T) {
	oldRV := ReleaseVersion
	oldFn := readBuildInfo
	ReleaseVersion = ""
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "v5.1.0"},
		}, true
	}
	t.Cleanup(func() {
		ReleaseVersion = oldRV
		readBuildInfo = oldFn
	})

	info := Read()
	if info.Version != "v5.1.0" {
		t.Fatalf("Version = %q, want %q", info.Version, "v5.1.0")
	}
}

func TestReadExtractsVCSSettings(t *testing.T) {
	oldRV := ReleaseVersion
	oldFn := readBuildInfo
	ReleaseVersion = ""
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "v1.0.0"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef1234567890"},
				{Key: "vcs.time", Value: "2025-06-01T10:00:00Z"},
				{Key: "vcs.modified", Value: "true"},
			},
		}, true
	}
	t.Cleanup(func() {
		ReleaseVersion = oldRV
		readBuildInfo = oldFn
	})

	info := Read()
	if info.Revision != "abcdef1234567890" {
		t.Fatalf("Revision = %q, want %q", info.Revision, "abcdef1234567890")
	}
	if info.Time != "2025-06-01T10:00:00Z" {
		t.Fatalf("Time = %q, want %q", info.Time, "2025-06-01T10:00:00Z")
	}
	if !info.Modified {
		t.Fatal("Modified should be true")
	}
}
