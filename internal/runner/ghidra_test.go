package runner

import (
	"reflect"
	"testing"
)

func TestBuildRustEnrichmentArgsSeededDisabledPreservesLegacyInvocation(t *testing.T) {
	got := buildRustEnrichmentArgs("input.json", "output.json", false)
	want := []string{
		"input.json",
		"output.json",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"unexpected Rust arguments with seeded disabled: got %v, want %v",
			got,
			want,
		)
	}
}

func TestBuildRustEnrichmentArgsSeededEnabledAppendsSingleFlag(t *testing.T) {
	got := buildRustEnrichmentArgs("input.json", "output.json", true)
	want := []string{
		"input.json",
		"output.json",
		"--seeded",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"unexpected Rust arguments with seeded enabled: got %v, want %v",
			got,
			want,
		)
	}
}
