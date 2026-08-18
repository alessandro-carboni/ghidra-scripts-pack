package main

import (
	"flag"
	"testing"
)

func TestParseSeededFlag_DefaultsFalse(t *testing.T) {
	fs := flag.NewFlagSet("test-scan", flag.ContinueOnError)
	seeded := parseSeededFlag(fs)

	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if *seeded {
		t.Fatal("-seeded must default to false")
	}
}

func TestParseSeededFlag_SetTrueWhenPassed(t *testing.T) {
	fs := flag.NewFlagSet("test-scan", flag.ContinueOnError)
	seeded := parseSeededFlag(fs)

	if err := fs.Parse([]string{"-seeded"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if !*seeded {
		t.Fatal("-seeded must be true when passed")
	}
}

func TestParseSeededFlag_CoexistsWithExistingScanFlags(t *testing.T) {
	fs := flag.NewFlagSet("test-scan", flag.ContinueOnError)
	input := fs.String("input", "", "input file or directory")
	ghidraDir := fs.String("ghidra-dir", "", "ghidra installation directory")
	seeded := parseSeededFlag(fs)

	if err := fs.Parse([]string{"-input", "sample.exe", "-ghidra-dir", `C:\ghidra`, "-seeded"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if *input != "sample.exe" {
		t.Fatalf("unexpected -input value: %q", *input)
	}
	if *ghidraDir != `C:\ghidra` {
		t.Fatalf("unexpected -ghidra-dir value: %q", *ghidraDir)
	}
	if !*seeded {
		t.Fatal("-seeded must be true when passed alongside existing flags")
	}
}

func TestParseSeededFlag_UnknownFlagStillRejected(t *testing.T) {
	fs := flag.NewFlagSet("test-scan", flag.ContinueOnError)
	_ = parseSeededFlag(fs)

	if err := fs.Parse([]string{"-not-a-real-flag"}); err == nil {
		t.Fatal("expected an error for an unknown flag, got nil")
	}
}
