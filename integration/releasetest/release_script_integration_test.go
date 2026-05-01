package releasetest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseScriptIntegration(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("release script integration test requires linux or darwin")
	}

	requireExternalToolsOrSkip(t)

	repoRoot := findRepoRoot(t)
	candidate := strings.TrimSpace(os.Getenv("RELEASE_TEST_CANDIDATE"))
	if candidate == "" {
		candidate = filepath.Join(t.TempDir(), "extract-sbom")

		build := exec.Command("go", "build", "-trimpath", "-o", candidate, "./cmd/extract-sbom")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build release candidate failed: %v\n%s", err, string(out))
		}
	} else {
		if info, err := os.Stat(candidate); err != nil {
			t.Fatalf("RELEASE_TEST_CANDIDATE does not exist: %s (%v)", candidate, err)
		} else if info.IsDir() {
			t.Fatalf("RELEASE_TEST_CANDIDATE must point to a file, got directory: %s", candidate)
		}
	}

	scriptPath := filepath.Join(repoRoot, ".github", "release-test", "run-release-test.sh")
	inputZip := filepath.Join(repoRoot, "integration", "vendorsuite", "testdata", "vendor-suite-3.2.zip")
	expectedPaths := filepath.Join(repoRoot, ".github", "release-test", "expected-delivery-paths.txt")

	cmd := exec.Command("bash", scriptPath)
	cmd.Env = append(os.Environ(),
		"RELEASE_TEST_CANDIDATE="+candidate,
		"RELEASE_TEST_INPUT_ZIP="+inputZip,
		"RELEASE_TEST_EXPECTED_PATHS="+expectedPaths,
	)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	if err := cmd.Run(); err != nil {
		t.Fatalf("release script failed: %v\n%s", err, combined.String())
	}
}

func requireExternalToolsOrSkip(t *testing.T) {
	t.Helper()

	missing := make([]string, 0, 4)
	for _, tool := range []string{"bash", "jq", "unshield"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}

	if _, err7zz := exec.LookPath("7zz"); err7zz != nil {
		if _, err7z := exec.LookPath("7z"); err7z != nil {
			missing = append(missing, "7zz/7z")
		}
	}

	if len(missing) > 0 {
		t.Skipf(
			"Skipping release script integration test; missing required tools: %s. This is acceptable because the release container test validates this later as well, but fail-early is not possible in this environment. Install these tools on the execution environment to enable this test.",
			strings.Join(missing, ", "),
		)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}

	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("could not find repository root from %s: %v", wd, err)
	}
	return root
}
