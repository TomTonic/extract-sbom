package i18n

import (
	"reflect"
	"testing"
)

// TestBundlesHaveNoEmptyFields verifies that every string field in the Bundle
// is non-empty for all supported languages. This catches forgotten translations
// when new fields are added.
func TestBundlesHaveNoEmptyFields(t *testing.T) {
	t.Parallel()

	for _, lang := range []string{"en", "de"} {
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			b := For(lang)
			v := reflect.ValueOf(b)
			ty := v.Type()

			for i := range v.NumField() {
				field := ty.Field(i)
				if field.Type.Kind() != reflect.String {
					continue
				}
				if v.Field(i).String() == "" {
					t.Errorf("Bundle[%s].%s is empty", lang, field.Name)
				}
			}
		})
	}
}

// TestBundlesHaveSameFields verifies that EN and DE bundles are structurally
// identical (every field populated in both).
func TestBundlesHaveSameFields(t *testing.T) {
	t.Parallel()

	en := For("en")
	de := For("de")
	enV := reflect.ValueOf(en)
	deV := reflect.ValueOf(de)
	ty := enV.Type()

	for i := range enV.NumField() {
		field := ty.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		enEmpty := enV.Field(i).String() == ""
		deEmpty := deV.Field(i).String() == ""
		if enEmpty != deEmpty {
			t.Errorf("field %s: empty mismatch (en empty=%v, de empty=%v)", field.Name, enEmpty, deEmpty)
		}
	}
}

// TestUnknownLanguageFallsBackToEnglish verifies that an unsupported language
// code produces the English bundle rather than an empty struct.
func TestUnknownLanguageFallsBackToEnglish(t *testing.T) {
	t.Parallel()

	if !reflect.DeepEqual(For("en"), For("fr")) {
		t.Error("unknown language code did not fall back to English bundle")
	}
}
