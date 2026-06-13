package i18n

import (
	"html"
	"html/template"
	"regexp"
	"strings"
)

// inlineLinkPattern matches a Markdown inline link: [text](url).
// Both groups are non-greedy so adjacent links in one string stay separate.
var inlineLinkPattern = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

// inlineCodePattern matches an inline code span delimited by single backticks.
var inlineCodePattern = regexp.MustCompile("`([^`]+)`")

// inlineBoldPattern matches a bold span delimited by double asterisks.
var inlineBoldPattern = regexp.MustCompile(`\*\*([^*]+)\*\*`)

// RenderInlineHTML converts the subset of inline Markdown used in the report
// translation catalog into safe HTML. It supports inline code (`code`), links
// ([text](url)), and bold (**text**).
//
// All literal text is HTML-escaped first, so the only markup in the result is
// the small set of tags this function emits; the returned template.HTML is
// therefore safe to embed without further escaping.
//
// The input is trusted, localized catalog content — never raw user data — but
// escaping is applied regardless so that any value interpolated into a template
// string (for example a package name inside a prose sentence) cannot inject
// markup.
func RenderInlineHTML(s string) template.HTML {
	// Escape all HTML metacharacters up front. Markdown delimiters (`[`, `]`,
	// backtick, `*`) are not affected by html.EscapeString, so the pattern
	// matching below still works on the escaped text.
	escaped := html.EscapeString(s)

	// Inline code first so that link/bold markers inside a code span are not
	// reinterpreted (the catalog never nests these, but this keeps it robust).
	escaped = inlineCodePattern.ReplaceAllString(escaped, "<code>$1</code>")

	// Links: [text](url). The URL is emitted into an href; html.EscapeString
	// already neutralized quotes and angle brackets, so attribute injection is
	// not possible.
	escaped = inlineLinkPattern.ReplaceAllStringFunc(escaped, func(m string) string {
		groups := inlineLinkPattern.FindStringSubmatch(m)
		text, url := groups[1], groups[2]
		return `<a href="` + url + `">` + text + `</a>`
	})

	// Bold last.
	escaped = inlineBoldPattern.ReplaceAllString(escaped, "<strong>$1</strong>")

	return template.HTML(escaped) //nolint:gosec // markup is limited to the tags emitted above over escaped text
}

// PlainText strips the inline Markdown markers from a catalog string, leaving
// only the human-readable text. It is used where markup must not appear, for
// example in an HTML title attribute or a plain-text label.
func PlainText(s string) string {
	s = inlineCodePattern.ReplaceAllString(s, "$1")
	s = inlineLinkPattern.ReplaceAllString(s, "$1")
	s = inlineBoldPattern.ReplaceAllString(s, "$1")
	return strings.TrimSpace(s)
}
