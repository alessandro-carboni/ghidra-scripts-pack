package runner

import (
	"reflect"
	"testing"
)

func TestBuildGhidraPostScriptArgsSeededDisabledPreservesLegacyInvocation(t *testing.T) {
	got := buildGhidraPostScriptArgs(
		"export_report.py",
		"reports",
		"rules",
		false,
	)
	want := []string{
		"-postScript",
		"export_report.py",
		"reports",
		"rules",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"unexpected Ghidra post-script arguments with seeded disabled: got %v, want %v",
			got,
			want,
		)
	}
}

func TestBuildGhidraPostScriptArgsSeededEnabledAppendsSingleMarker(t *testing.T) {
	got := buildGhidraPostScriptArgs(
		"export_report.py",
		"reports",
		"rules",
		true,
	)
	want := []string{
		"-postScript",
		"export_report.py",
		"reports",
		"rules",
		"seeded=true",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"unexpected Ghidra post-script arguments with seeded enabled: got %v, want %v",
			got,
			want,
		)
	}
}

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
