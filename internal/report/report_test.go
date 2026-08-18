package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const legacyRustEnrichmentFixture = `{
	"rust_enrichment": {
		"engine_metadata": {
			"engine_name": "rust_engine"
		}
	}
}`

const seededRustEnrichmentNotImplementedFixture = `{
	"rust_enrichment": {
		"seeded_fingerprinting": {
			"status": "not_implemented",
			"schema_version": "0.1.0",
			"message": "Seeded fingerprinting is enabled but not implemented in this milestone."
		}
	}
}`

func loadReportJSONForTest(t *testing.T, payload string) *Report {
	t.Helper()

	path := filepath.Join(t.TempDir(), "report.json")

	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write test report: %v", err)
	}

	rep, err := Load(path)
	if err != nil {
		t.Fatalf("load test report: %v", err)
	}

	return rep
}

func TestLoadLegacyRustEnrichmentWithoutSeededFingerprinting(t *testing.T) {
	rep := loadReportJSONForTest(t, legacyRustEnrichmentFixture)

	if rep.RustEnrichment == nil {
		t.Fatal("expected rust_enrichment to be present")
	}

	if rep.RustEnrichment.SeededFingerprinting != nil {
		t.Fatal("expected seeded_fingerprinting to be nil for legacy report")
	}
}

func TestLoadSeededFingerprintingNotImplemented(t *testing.T) {
	rep := loadReportJSONForTest(t, seededRustEnrichmentNotImplementedFixture)

	if rep.RustEnrichment == nil {
		t.Fatal("expected rust_enrichment to be present")
	}

	if rep.RustEnrichment.SeededFingerprinting == nil {
		t.Fatal("expected seeded_fingerprinting to be present")
	}

	seeded := rep.RustEnrichment.SeededFingerprinting

	if seeded.Status != "not_implemented" {
		t.Fatalf("unexpected status: %q", seeded.Status)
	}

	if seeded.SchemaVersion != "0.1.0" {
		t.Fatalf("unexpected schema version: %q", seeded.SchemaVersion)
	}

	const expectedMessage = "Seeded fingerprinting is enabled but not implemented in this milestone."

	if seeded.Message != expectedMessage {
		t.Fatalf(
			"unexpected message: got %q, want %q",
			seeded.Message,
			expectedMessage,
		)
	}
}

func TestLoadSeededFingerprintingFailedStatus(t *testing.T) {
	rep := loadReportJSONForTest(t, `{
		"rust_enrichment": {
			"seeded_fingerprinting": {
				"status": "failed",
				"schema_version": "0.1.0",
				"message": "example error"
			}
		}
	}`)

	if rep.RustEnrichment == nil {
		t.Fatal("expected rust_enrichment to be present")
	}

	if rep.RustEnrichment.SeededFingerprinting == nil {
		t.Fatal("expected seeded_fingerprinting to be present")
	}

	seeded := rep.RustEnrichment.SeededFingerprinting

	if seeded.Status != "failed" {
		t.Fatalf("unexpected status: %q", seeded.Status)
	}

	if seeded.SchemaVersion != "0.1.0" {
		t.Fatalf("unexpected schema version: %q", seeded.SchemaVersion)
	}

	if seeded.Message != "example error" {
		t.Fatalf("unexpected message: %q", seeded.Message)
	}
}

func TestLoadSeededFingerprintingDisabledStatus(t *testing.T) {
	rep := loadReportJSONForTest(t, `{
		"rust_enrichment": {
			"seeded_fingerprinting": {
				"status": "disabled"
			}
		}
	}`)

	if rep.RustEnrichment == nil {
		t.Fatal("expected rust_enrichment to be present")
	}

	if rep.RustEnrichment.SeededFingerprinting == nil {
		t.Fatal("expected seeded_fingerprinting to be present")
	}

	if rep.RustEnrichment.SeededFingerprinting.Status != "disabled" {
		t.Fatalf(
			"unexpected status: %q",
			rep.RustEnrichment.SeededFingerprinting.Status,
		)
	}
}

func TestLoadSeededFingerprintingWithoutOptionalMetadata(t *testing.T) {
	rep := loadReportJSONForTest(t, `{
		"rust_enrichment": {
			"seeded_fingerprinting": {
				"status": "disabled"
			}
		}
	}`)

	if rep.RustEnrichment == nil {
		t.Fatal("expected rust_enrichment to be present")
	}

	if rep.RustEnrichment.SeededFingerprinting == nil {
		t.Fatal("expected seeded_fingerprinting to be present")
	}

	seeded := rep.RustEnrichment.SeededFingerprinting

	if seeded.SchemaVersion != "" {
		t.Fatalf(
			"expected empty schema version, got %q",
			seeded.SchemaVersion,
		)
	}

	if seeded.Message != "" {
		t.Fatalf(
			"expected empty message, got %q",
			seeded.Message,
		)
	}
}

func TestLegacyRustEnrichmentRoundTripDoesNotAddSeededFingerprinting(t *testing.T) {
	rep := loadReportJSONForTest(t, legacyRustEnrichmentFixture)

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal legacy report: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode round-trip JSON: %v", err)
	}

	rustValue, ok := decoded["rust_enrichment"]
	if !ok {
		t.Fatal("expected rust_enrichment after round trip")
	}

	rustEnrichment, ok := rustValue.(map[string]any)
	if !ok {
		t.Fatalf(
			"expected rust_enrichment to be a JSON object, got %T",
			rustValue,
		)
	}

	if _, exists := rustEnrichment["seeded_fingerprinting"]; exists {
		t.Fatal("legacy round trip must not add seeded_fingerprinting")
	}
}

func TestSeededFingerprintingRoundTripPreservesPlaceholderContract(t *testing.T) {
	rep := loadReportJSONForTest(t, seededRustEnrichmentNotImplementedFixture)

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal seeded report: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode round-trip JSON: %v", err)
	}

	rustValue, ok := decoded["rust_enrichment"]
	if !ok {
		t.Fatal("expected rust_enrichment after round trip")
	}

	rustEnrichment, ok := rustValue.(map[string]any)
	if !ok {
		t.Fatalf(
			"expected rust_enrichment to be a JSON object, got %T",
			rustValue,
		)
	}

	seededValue, ok := rustEnrichment["seeded_fingerprinting"]
	if !ok {
		t.Fatal("expected seeded_fingerprinting after round trip")
	}

	seeded, ok := seededValue.(map[string]any)
	if !ok {
		t.Fatalf(
			"expected seeded_fingerprinting to be a JSON object, got %T",
			seededValue,
		)
	}

	if status, ok := seeded["status"].(string); !ok || status != "not_implemented" {
		t.Fatalf(
			"unexpected seeded status after round trip: %#v",
			seeded["status"],
		)
	}

	if schemaVersion, ok := seeded["schema_version"].(string); !ok || schemaVersion != "0.1.0" {
		t.Fatalf(
			"unexpected seeded schema version after round trip: %#v",
			seeded["schema_version"],
		)
	}

	const expectedMessage = "Seeded fingerprinting is enabled but not implemented in this milestone."

	if message, ok := seeded["message"].(string); !ok || message != expectedMessage {
		t.Fatalf(
			"unexpected seeded message after round trip: %#v",
			seeded["message"],
		)
	}
}
