package i18n

import "testing"

func TestRenderInlineHTML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello world", "hello world"},
		{"code", "state is `completed` now", "state is <code>completed</code> now"},
		{"link anchor", "see [Vulnerability Summary](#vulnerability-summary).",
			`see <a href="#vulnerability-summary">Vulnerability Summary</a>.`},
		{"link external", "[SCAN_APPROACH.md](https://example.com/x#y)",
			`<a href="https://example.com/x#y">SCAN_APPROACH.md</a>`},
		{"bold", "**Tools:** 7-Zip", "<strong>Tools:</strong> 7-Zip"},
		{"two links", "[a](#a) and [b](#b)",
			`<a href="#a">a</a> and <a href="#b">b</a>`},
		{"escape ampersand", "AT&T & co", "AT&amp;T &amp; co"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := string(RenderInlineHTML(tc.in))
			if got != tc.want {
				t.Errorf("RenderInlineHTML(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRenderInlineHTMLEscapesMarkupInText verifies that raw HTML metacharacters
// in the literal text are escaped and cannot inject tags.
func TestRenderInlineHTMLEscapesMarkupInText(t *testing.T) {
	t.Parallel()

	got := string(RenderInlineHTML("a <script>alert(1)</script> b"))
	if want := "a &lt;script&gt;alert(1)&lt;/script&gt; b"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPlainText(t *testing.T) {
	t.Parallel()

	got := PlainText("see [the docs](#x) for `code` and **bold**")
	if want := "see the docs for code and bold"; got != want {
		t.Errorf("PlainText = %q, want %q", got, want)
	}
}
