package html

import (
	"fmt"
	"strconv"
	"strings"

	domain "github.com/TomTonic/extract-sbom/internal/report/internal/domain"
	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
)

// vulnDescriptionMaxRunes bounds inline vulnerability descriptions, mirroring the
// Markdown renderer so both outputs truncate identically.
const vulnDescriptionMaxRunes = 100

// emptyDash returns v, or "-" when v is blank.
func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

// valueOrDash returns value, or "-" when value is blank.
func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// truncateText shortens s to at most limit runes, appending an ellipsis when cut.
func truncateText(s string, limit int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}

func formatNumber(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func formatSeverity(severity string, cvss *float64) string {
	if cvss == nil {
		return strings.ToUpper(domain.NormalizeSeverity(severity))
	}
	return fmt.Sprintf("%s (%s)", strings.ToUpper(domain.NormalizeSeverity(severity)), formatNumber(*cvss))
}

func formatEPSS(epss, percentile *float64) string {
	if epss == nil {
		return "-"
	}
	p := fmt.Sprintf("%.1f%%", (*epss)*100)
	if percentile == nil {
		return p
	}
	return fmt.Sprintf("%s (%s)", p, formatPercentileRank((*percentile)*100))
}

func formatRisk(risk *float64) string {
	if risk == nil {
		return "-"
	}
	return formatNumber(*risk)
}

func formatKEV(kev bool, t i18npkg.Bundle) string {
	if kev {
		return t.VulnKEVYes
	}
	return t.VulnKEVNo
}

func formatPercentileRank(pct float64) string {
	whole := int(pct + 0.5)
	if whole <= 0 {
		return "0th"
	}
	if whole%100 >= 11 && whole%100 <= 13 {
		return fmt.Sprintf("%dth", whole)
	}
	switch whole % 10 {
	case 1:
		return fmt.Sprintf("%dst", whole)
	case 2:
		return fmt.Sprintf("%dnd", whole)
	case 3:
		return fmt.Sprintf("%drd", whole)
	default:
		return fmt.Sprintf("%dth", whole)
	}
}
