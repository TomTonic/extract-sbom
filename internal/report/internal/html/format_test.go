package html

import (
	"testing"

	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
)

func TestFormatNumber(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0.0"},
		{1.234, "1.2"},
		{9.9, "9.9"},
		{99.9, "99.9"},
	}
	for _, tc := range cases {
		if got := formatNumber(tc.in); got != tc.want {
			t.Errorf("formatNumber(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatSeverity(t *testing.T) {
	t.Parallel()
	cvss := 7.5
	if got := formatSeverity("HIGH", &cvss); got != "HIGH (7.5)" {
		t.Errorf("got %q", got)
	}
	if got := formatSeverity("medium", nil); got != "MEDIUM" {
		t.Errorf("got %q", got)
	}
}

func TestFormatEPSS(t *testing.T) {
	t.Parallel()
	if got := formatEPSS(nil, nil); got != "-" {
		t.Errorf("nil epss: got %q", got)
	}
	v := 0.123
	if got := formatEPSS(&v, nil); got != "12.3%" {
		t.Errorf("epss no pct: got %q", got)
	}
	p := 0.75
	got := formatEPSS(&v, &p)
	if got != "12.3% (75th)" {
		t.Errorf("epss with pct: got %q", got)
	}
}

func TestFormatRisk(t *testing.T) {
	t.Parallel()
	if got := formatRisk(nil); got != "-" {
		t.Errorf("nil: got %q", got)
	}
	r := 8.3
	if got := formatRisk(&r); got != "8.3" {
		t.Errorf("got %q", got)
	}
}

func TestFormatKEV(t *testing.T) {
	t.Parallel()
	bun := i18npkg.For("en")
	if got := formatKEV(true, bun); got != bun.VulnKEVYes {
		t.Errorf("kev true: got %q", got)
	}
	if got := formatKEV(false, bun); got != bun.VulnKEVNo {
		t.Errorf("kev false: got %q", got)
	}
}

func TestFormatPercentileRank(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0th"},
		{1, "1st"},
		{2, "2nd"},
		{3, "3rd"},
		{4, "4th"},
		{11, "11th"},
		{12, "12th"},
		{13, "13th"},
		{21, "21st"},
		{22, "22nd"},
		{23, "23rd"},
		{99, "99th"},
		{100, "100th"},
		{111, "111th"},
		{121, "121st"},
	}
	for _, tc := range cases {
		if got := formatPercentileRank(tc.in); got != tc.want {
			t.Errorf("formatPercentileRank(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
