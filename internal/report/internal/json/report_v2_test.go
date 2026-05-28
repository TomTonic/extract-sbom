package json

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGenerateV2IncludesCanonicalEnvelope(t *testing.T) {
	t.Parallel()

	data := makeTestReportData()
	data.SBOMPath = "/tmp/out/test.cdx.json"

	var buf bytes.Buffer
	if err := GenerateV2(data, &buf); err != nil {
		t.Fatalf("GenerateV2 error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, key := range []string{"schema", "run", "input", "generator", "config", "runtime", "raw", "entities", "projections", "integrity", "compatibility"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing top-level key %q", key)
		}
	}

	schemaObj, ok := parsed["schema"].(map[string]any)
	if !ok {
		t.Fatalf("schema has unexpected type: %T", parsed["schema"])
	}
	if got := schemaObj["version"]; got != reportV2SchemaVersion {
		t.Fatalf("schema.version = %v, want %s", got, reportV2SchemaVersion)
	}

	rawObj, ok := parsed["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw has unexpected type: %T", parsed["raw"])
	}
	artifactPaths, ok := rawObj["artifactPaths"].(map[string]any)
	if !ok {
		t.Fatalf("raw.artifactPaths has unexpected type: %T", rawObj["artifactPaths"])
	}
	if got := artifactPaths["sbomPath"]; got != data.SBOMPath {
		t.Fatalf("raw.artifactPaths.sbomPath = %v, want %s", got, data.SBOMPath)
	}

	configObj, ok := parsed["config"].(map[string]any)
	if !ok {
		t.Fatalf("config has unexpected type: %T", parsed["config"])
	}
	passwords, ok := configObj["passwords"].(map[string]any)
	if !ok {
		t.Fatalf("config.passwords has unexpected type: %T", configObj["passwords"])
	}
	if got := passwords["sensitiveRedacted"]; got != true {
		t.Fatalf("config.passwords.sensitiveRedacted = %v, want true", got)
	}
}

func TestGenerateV2ConformsSchemaV2(t *testing.T) {
	t.Parallel()

	schemaBytes, readErr := os.ReadFile("report.schema.v2.json")
	if readErr != nil {
		t.Fatalf("read schema: %v", readErr)
	}
	var schemaDoc any
	if unmarshalErr := json.Unmarshal(schemaBytes, &schemaDoc); unmarshalErr != nil {
		t.Fatalf("unmarshal schema: %v", unmarshalErr)
	}

	compiler := jsonschema.NewCompiler()
	if addErr := compiler.AddResource("report.schema.v2.json", schemaDoc); addErr != nil {
		t.Fatalf("add schema resource: %v", addErr)
	}
	schema, err := compiler.Compile("report.schema.v2.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	data := makeTestReportData()
	var out bytes.Buffer
	if err := GenerateV2(data, &out); err != nil {
		t.Fatalf("GenerateV2 error: %v", err)
	}

	var doc any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal generated v2 json: %v", err)
	}

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("generated v2 report does not match schema: %v", err)
	}
}
