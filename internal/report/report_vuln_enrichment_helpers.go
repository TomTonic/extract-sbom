package report

import "github.com/TomTonic/extract-sbom/internal/vulnscan"

// normalizedVulnEnrichmentState returns a stable enrichment-state view shared
// by machine and SARIF renderers.
func normalizedVulnEnrichmentState(v *vulnscan.Result) (vulnscan.State, bool) {
	state := vulnscan.StateNotRequested
	requested := false
	if v != nil {
		requested = v.Requested
		if v.State != "" {
			state = v.State
		}
	}
	return state, requested
}
