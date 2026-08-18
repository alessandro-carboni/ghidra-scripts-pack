package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_LegacyStateWithoutSeededField(t *testing.T) {
	dir := t.TempDir()
	legacy := []byte(`{"last_report":"reports/sample.json"}`)

	if err := os.WriteFile(StateFilePath(dir), legacy, 0o644); err != nil {
		t.Fatalf("write legacy state fixture: %v", err)
	}

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil state for existing legacy file")
	}

	if s.SeededFingerprintingEnabled {
		t.Fatal("missing legacy field must default to false")
	}
	if s.LastReport != "reports/sample.json" {
		t.Fatalf("unexpected last_report value: %q", s.LastReport)
	}
}

func TestSave_SeededTrueIsPersisted(t *testing.T) {
	dir := t.TempDir()

	if err := Save(dir, State{SeededFingerprintingEnabled: true}); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	data, err := os.ReadFile(StateFilePath(dir))
	if err != nil {
		t.Fatalf("read saved state: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode saved state: %v", err)
	}

	value, ok := decoded["seeded_fingerprinting_enabled"]
	if !ok {
		t.Fatal("expected seeded_fingerprinting_enabled key in persisted JSON")
	}
	if value != true {
		t.Fatalf("expected persisted value true, got %v", value)
	}
}

func TestSave_SeededFalseIsPersistedExplicitly(t *testing.T) {
	dir := t.TempDir()

	if err := Save(dir, State{SeededFingerprintingEnabled: false}); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	data, err := os.ReadFile(StateFilePath(dir))
	if err != nil {
		t.Fatalf("read saved state: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode saved state: %v", err)
	}

	value, ok := decoded["seeded_fingerprinting_enabled"]
	if !ok {
		t.Fatal("State has no omitempty tags, so seeded_fingerprinting_enabled must always be present")
	}
	if value != false {
		t.Fatalf("expected persisted value false, got %v", value)
	}
}

func TestRoundTrip_SeededFingerprintingEnabled(t *testing.T) {
	cases := []bool{true, false}

	for _, want := range cases {
		dir := t.TempDir()

		if err := Save(dir, State{SeededFingerprintingEnabled: want}); err != nil {
			t.Fatalf("unexpected save error for %v: %v", want, err)
		}

		loaded, err := Load(dir)
		if err != nil {
			t.Fatalf("unexpected load error for %v: %v", want, err)
		}
		if loaded == nil {
			t.Fatalf("expected non-nil state after round trip for %v", want)
		}

		if loaded.SeededFingerprintingEnabled != want {
			t.Fatalf("round trip mismatch: want %v, got %v", want, loaded.SeededFingerprintingEnabled)
		}
	}
}

func TestResolveSeededFingerprintingEnabled(t *testing.T) {
	tests := []struct {
		name      string
		persisted bool
		flagSet   bool
		want      bool
	}{
		{name: "flag true overrides persisted false", persisted: false, flagSet: true, want: true},
		{name: "flag true overrides persisted true", persisted: true, flagSet: true, want: true},
		{name: "flag false keeps persisted true", persisted: true, flagSet: false, want: true},
		{name: "flag false keeps persisted false", persisted: false, flagSet: false, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveSeededFingerprintingEnabled(tt.persisted, tt.flagSet)
			if got != tt.want {
				t.Fatalf("ResolveSeededFingerprintingEnabled(%v, %v) = %v, want %v", tt.persisted, tt.flagSet, got, tt.want)
			}
		})
	}
}

func TestStateFilePath(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, ".runstate.json")

	if got := StateFilePath(dir); got != want {
		t.Fatalf("StateFilePath(%q) = %q, want %q", dir, got, want)
	}
}
