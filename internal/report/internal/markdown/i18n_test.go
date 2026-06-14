package markdown

import (
	"reflect"
	"testing"
)

// TestGetTranslationsWiring verifies the markdown package's thin accessor over
// the shared i18n catalog: known languages resolve and unknown codes fall back
// to English. Field-level completeness is covered in the i18n package.
func TestGetTranslationsWiring(t *testing.T) {
	t.Parallel()

	en := getTranslations("en")
	de := getTranslations("de")
	if en.Title == "" || de.Title == "" {
		t.Fatal("expected populated bundles for en and de")
	}
	if en.SummarySection == de.SummarySection {
		t.Error("expected en and de section titles to differ")
	}
	if !reflect.DeepEqual(en, getTranslations("fr")) {
		t.Error("unknown language code did not fall back to English bundle")
	}
}
