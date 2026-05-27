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

func TestGenerateHumanWithTemplateDocumentRendersSelectedSections(t *testing.T) {
	data := makeTestReportData()

	const tpl = "{{.Header}}{{.TableOfContents}}{{.Sections.Summary}}{{.Sections.Extraction}}{{.EndOfReport}}"
	var out bytes.Buffer
	if err := GenerateHumanWithTemplateDocument(data, "en", &out, tpl); err != nil {
		t.Fatalf("GenerateHumanWithTemplateDocument: %v", err)
	}

	s := out.String()
	if !strings.Contains(s, "# ") {
		t.Fatalf("missing report title header")
	}
	if !strings.Contains(s, "## ") {
		t.Fatalf("missing section heading")
	}
	if !strings.Contains(s, "test.zip") {
		t.Fatalf("expected extraction content")
	}
}

func TestGenerateHumanWithTemplateDocumentRejectsEmptyTemplate(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateHumanWithTemplateDocument(data, "en", &out, "")
	if err == nil {
		t.Fatal("expected empty-template error")
	}
}

func TestGenerateHumanWithTemplateDocumentInvalidTemplateReturnsError(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateHumanWithTemplateDocument(data, "en", &out, "{{")
	if err == nil {
		t.Fatal("expected document template parse error")
	}
}

func TestGenerateHumanWithOptionsDefaultMatchesGenerateHuman(t *testing.T) {
	data := makeTestReportData()

	var base bytes.Buffer
	if err := GenerateHuman(data, "en", &base); err != nil {
		t.Fatalf("GenerateHuman: %v", err)
	}

	var viaOpts bytes.Buffer
	if err := GenerateHumanWithOptions(data, "en", &viaOpts, HumanRenderOptions{}); err != nil {
		t.Fatalf("GenerateHumanWithOptions: %v", err)
	}

	baseNormalized := normalizeHumanGeneratedTimestamp(base.String())
	viaOptsNormalized := normalizeHumanGeneratedTimestamp(viaOpts.String())
	if baseNormalized != viaOptsNormalized {
		t.Fatalf("options default changed report body")
	}
}

func TestGenerateHumanWithOptionsRejectsUnknownEngine(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateHumanWithOptions(data, "en", &out, HumanRenderOptions{Engine: HumanRenderEngine("unknown")})
	if err == nil {
		t.Fatal("expected unsupported-engine error")
	}
}

func TestGenerateHumanWithOptionsTemplateWrapper(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateHumanWithOptions(data, "en", &out, HumanRenderOptions{
		Engine:          HumanRenderEngineTemplateWrapper,
		WrapperTemplate: "HEAD\n{{.Body}}\nTAIL",
	})
	if err != nil {
		t.Fatalf("GenerateHumanWithOptions: %v", err)
	}

	s := out.String()
	if !strings.HasPrefix(s, "HEAD\n") {
		t.Fatalf("missing wrapper header")
	}
	if !strings.HasSuffix(s, "\nTAIL") {
		t.Fatalf("missing wrapper footer")
	}
}

func TestGenerateHumanWithOptionsTemplateDocumentRequiresTemplate(t *testing.T) {
	data := makeTestReportData()

	var out bytes.Buffer
	err := GenerateHumanWithOptions(data, "en", &out, HumanRenderOptions{Engine: HumanRenderEngineTemplateDocument})
	if err == nil {
		t.Fatal("expected missing document template error")
	}
}
