package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func normalizeHumanGeneratedTimestamp(s string) string {
	tsPattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
	return tsPattern.ReplaceAllString(s, "<generated-at>")
}

func TestGenerateHumanWithTemplateIdentityWrapperMatchesDefault(t *testing.T) {
	data := makeTestReportData()

	var base bytes.Buffer
	if err := GenerateHuman(data, "en", &base); err != nil {
		t.Fatalf("GenerateHuman: %v", err)
	}

	var wrapped bytes.Buffer
	if err := GenerateHumanWithTemplate(data, "en", &wrapped, "{{.Body}}"); err != nil {
		t.Fatalf("GenerateHumanWithTemplate: %v", err)
	}

	baseNormalized := normalizeHumanGeneratedTimestamp(base.String())
	wrappedNormalized := normalizeHumanGeneratedTimestamp(wrapped.String())
	if baseNormalized != wrappedNormalized {
		t.Fatalf("identity wrapper changed report body")
	}
}

func TestGenerateHumanWithTemplateCanWrapOutput(t *testing.T) {
	data := makeTestReportData()

	const wrapper = "BEGIN\n{{.Body}}\nEND"
	var out bytes.Buffer
	if err := GenerateHumanWithTemplate(data, "en", &out, wrapper); err != nil {
		t.Fatalf("GenerateHumanWithTemplate: %v", err)
	}

	s := out.String()
	if !strings.HasPrefix(s, "BEGIN\n") {
		t.Fatalf("missing wrapper prefix")
	}
	if !strings.HasSuffix(s, "\nEND") {
		t.Fatalf("missing wrapper suffix")
	}
	if !strings.Contains(s, "# ") {
		t.Fatalf("wrapped output does not contain report body")
	}
}

func TestGenerateHumanWithTemplateInvalidTemplateReturnsError(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateHumanWithTemplate(data, "en", &out, "{{")
	if err == nil {
		t.Fatal("expected template parse error")
	}
}
