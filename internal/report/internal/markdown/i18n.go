package markdown

import (
	i18npkg "github.com/TomTonic/extract-sbom/internal/report/internal/i18n"
)

// translations is the shared localized label/prose bundle. It is aliased from
// the i18n package so the Markdown and HTML renderers share one catalog.
type translations = i18npkg.Bundle

// getTranslations returns the translation bundle for the requested language,
// defaulting to English when an unknown code is provided.
func getTranslations(lang string) translations {
	return i18npkg.For(lang)
}
