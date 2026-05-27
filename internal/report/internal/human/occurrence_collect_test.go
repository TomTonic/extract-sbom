package human

import "testing"

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
