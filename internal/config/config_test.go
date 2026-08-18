package config

import "testing"

func TestDefault_SeededFingerprintingDisabledByDefault(t *testing.T) {
	cfg := Default("/tmp/triage-project-root")

	if cfg.SeededFingerprintingEnabled {
		t.Fatal("seeded fingerprinting must be disabled by default")
	}
}
