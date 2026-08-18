package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLegacyRunStateFixtureDefaultsSeededToFalse(t *testing.T) {
	fixturePath := filepath.Join("testdata", "legacy_runstate.json")

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read legacy run-state fixture: %v", err)
	}

	projectRoot := t.TempDir()

	if err := os.WriteFile(StateFilePath(projectRoot), data, 0o644); err != nil {
		t.Fatalf("write legacy run-state fixture: %v", err)
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("load legacy run-state: %v", err)
	}

	if loaded == nil {
		t.Fatal("expected legacy run-state to load")
	}

	if loaded.SeededFingerprintingEnabled {
		t.Fatal("legacy run-state without seeded field must default to false")
	}
}

func TestSeededRunStateRoundTripPreservesTrue(t *testing.T) {
	projectRoot := t.TempDir()

	original := State{
		SeededFingerprintingEnabled: true,
	}

	if err := Save(projectRoot, original); err != nil {
		t.Fatalf("save seeded run-state: %v", err)
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("load seeded run-state: %v", err)
	}

	if loaded == nil {
		t.Fatal("expected saved run-state to load")
	}

	if !loaded.SeededFingerprintingEnabled {
		t.Fatal("seeded run-state must preserve true after save and load")
	}
}
