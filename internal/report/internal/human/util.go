package human

import (
	"runtime/debug"
	"strings"
)

// generatorGitHubURL returns a GitHub URL for the given generator version string.
func generatorGitHubURL(version string) string {
	const repoBase = "https://github.com/TomTonic/extract-sbom"
	v := strings.TrimSuffix(version, "+dirty")
	if idx := strings.LastIndex(v, "-"); idx != -1 {
		hash := v[idx+1:]
		if len(hash) >= 12 {
			return repoBase + "/commit/" + hash
		}
	}
	if strings.HasPrefix(v, "v") {
		return repoBase + "/releases/tag/" + v
	}
	return repoBase
}

// getSyftVersion reads the Syft dependency version from build info at runtime.
func getSyftVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi == nil {
		return ""
	}
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/anchore/syft" {
			return dep.Path + " " + dep.Version
		}
	}
	return ""
}
