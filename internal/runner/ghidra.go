package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ghidra-malware-triage/internal/config"
	"ghidra-malware-triage/internal/state"
)

type ScanResult struct {
	InputPath         string
	SampleName        string
	RawReportPath     string
	EnrichedReportPath string
	FinalReportPath   string
	ExitCode          int
	StartedAt         time.Time
	FinishedAt        time.Time
}

func BuildPyGhidraRunPath(ghidraDir string) string {
	return filepath.Join(ghidraDir, "support", "pyghidraRun.bat")
}

func EnsureExecutablePaths(cfg config.Config) error {
	pyghidra := BuildPyGhidraRunPath(cfg.GhidraDir)

	if _, err := os.Stat(pyghidra); err != nil {
		return fmt.Errorf("pyghidraRun.bat not found: %s", pyghidra)
	}
	if _, err := os.Stat(cfg.ScriptPath); err != nil {
		return fmt.Errorf("script path not found: %s", cfg.ScriptPath)
	}
	if _, err := os.Stat(cfg.RuleDir); err != nil {
		return fmt.Errorf("rule dir not found: %s", cfg.RuleDir)
	}
	if _, err := os.Stat(cfg.RustEnginePath); err != nil {
		return fmt.Errorf("rust engine not found: %s", cfg.RustEnginePath)
	}

	return nil
}

func CollectInputs(inputPath string) ([]string, error) {
	resolvedInput, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(resolvedInput)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{resolvedInput}, nil
	}

	entries, err := os.ReadDir(resolvedInput)
	if err != nil {
		return nil, err
	}

	results := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		results = append(results, filepath.Join(resolvedInput, entry.Name()))
	}

	return results, nil
}

func ScanFile(cfg config.Config, inputPath string) (*ScanResult, error) {
	resolvedInput, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve input path: %w", err)
	}

	sampleName := filepath.Base(resolvedInput)
	workingRawReportPath := filepath.Join(cfg.OutputDir, "raw_report.json")

	if err := removeIfExists(workingRawReportPath); err != nil {
		return nil, fmt.Errorf("remove previous raw report: %w", err)
	}

	pyghidra := BuildPyGhidraRunPath(cfg.GhidraDir)
	args := []string{
		"-H",
		cfg.ProjectDir,
		cfg.ProjectName,
		"-import", resolvedInput,
		"-overwrite",
		"-scriptPath", cfg.ScriptPath,
		"-postScript", cfg.PostScript, cfg.OutputDir, cfg.RuleDir,
	}

	startedAt := time.Now()
	exitCode, err := runCommand(pyghidra, args)
	if err != nil {
		return &ScanResult{
			InputPath:     resolvedInput,
			SampleName:    sampleName,
			RawReportPath: workingRawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    time.Now(),
		}, fmt.Errorf("ghidra scan failed: %w", err)
	}

	finalRawReportPath, err := finalizeRawReport(cfg.OutputDir, resolvedInput)
	if err != nil {
		return &ScanResult{
			InputPath:     resolvedInput,
			SampleName:    sampleName,
			RawReportPath: workingRawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    time.Now(),
		}, err
	}

	enrichedReportPath := buildEnrichedReportPathFromRaw(finalRawReportPath)
	if err := runRustEnrichment(cfg.RustEnginePath, finalRawReportPath, enrichedReportPath); err != nil {
		return &ScanResult{
			InputPath:         resolvedInput,
			SampleName:        sampleName,
			RawReportPath:     finalRawReportPath,
			EnrichedReportPath: enrichedReportPath,
			ExitCode:          exitCode,
			StartedAt:         startedAt,
			FinishedAt:        time.Now(),
		}, fmt.Errorf("rust enrichment failed: %w", err)
	}

	return &ScanResult{
		InputPath:          resolvedInput,
		SampleName:         sampleName,
		RawReportPath:      finalRawReportPath,
		EnrichedReportPath: enrichedReportPath,
		FinalReportPath:    enrichedReportPath,
		ExitCode:           exitCode,
		StartedAt:          startedAt,
		FinishedAt:         time.Now(),
	}, nil
}

func FastScan(cfg config.Config, st state.State) (*ScanResult, error) {
	if st.LastProgram == "" {
		return nil, fmt.Errorf("missing last program in saved state")
	}
	if st.LastFilePath == "" {
		return nil, fmt.Errorf("missing last file path in saved state")
	}

	workingRawReportPath := filepath.Join(cfg.OutputDir, "raw_report.json")
	if err := removeIfExists(workingRawReportPath); err != nil {
		return nil, fmt.Errorf("remove previous raw report: %w", err)
	}

	pyghidra := BuildPyGhidraRunPath(cfg.GhidraDir)
	args := []string{
		"-H",
		cfg.ProjectDir,
		cfg.ProjectName,
		"-process", st.LastProgram,
		"-noanalysis",
		"-scriptPath", cfg.ScriptPath,
		"-postScript", cfg.PostScript, cfg.OutputDir, cfg.RuleDir,
	}

	startedAt := time.Now()
	exitCode, err := runCommand(pyghidra, args)
	if err != nil {
		return &ScanResult{
			InputPath:     st.LastFilePath,
			SampleName:    st.LastProgram,
			RawReportPath: workingRawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    time.Now(),
		}, fmt.Errorf("ghidra fast scan failed: %w", err)
	}

	finalRawReportPath, err := finalizeRawReport(cfg.OutputDir, st.LastFilePath)
	if err != nil {
		return &ScanResult{
			InputPath:     st.LastFilePath,
			SampleName:    st.LastProgram,
			RawReportPath: workingRawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    time.Now(),
		}, err
	}

	enrichedReportPath := buildEnrichedReportPathFromRaw(finalRawReportPath)
	if err := runRustEnrichment(cfg.RustEnginePath, finalRawReportPath, enrichedReportPath); err != nil {
		return &ScanResult{
			InputPath:          st.LastFilePath,
			SampleName:         st.LastProgram,
			RawReportPath:      finalRawReportPath,
			EnrichedReportPath: enrichedReportPath,
			ExitCode:           exitCode,
			StartedAt:          startedAt,
			FinishedAt:         time.Now(),
		}, fmt.Errorf("rust enrichment failed: %w", err)
	}

	return &ScanResult{
		InputPath:          st.LastFilePath,
		SampleName:         st.LastProgram,
		RawReportPath:      finalRawReportPath,
		EnrichedReportPath: enrichedReportPath,
		FinalReportPath:    enrichedReportPath,
		ExitCode:           exitCode,
		StartedAt:          startedAt,
		FinishedAt:         time.Now(),
	}, nil
}

func SaveStateFromScan(projectRoot string, cfg config.Config, result *ScanResult) error {
	s := state.State{
		GhidraDir:          cfg.GhidraDir,
		ProjectDir:         cfg.ProjectDir,
		ProjectName:        cfg.ProjectName,
		PostScript:         cfg.PostScript,
		ScriptPath:         cfg.ScriptPath,
		RuleDir:            cfg.RuleDir,
		OutputDir:          cfg.OutputDir,
		RustEnginePath:     cfg.RustEnginePath,
		LastFilePath:       result.InputPath,
		LastProgram:        filepath.Base(result.InputPath),
		LastReport:         result.FinalReportPath,
		LastRawReport:      result.RawReportPath,
		LastEnrichedReport: result.EnrichedReportPath,
	}
	return state.Save(projectRoot, s)
}

func SaveStateAfterFast(projectRoot string, st state.State, cfg config.Config, result *ScanResult) error {
	st.GhidraDir = cfg.GhidraDir
	st.ProjectDir = cfg.ProjectDir
	st.ProjectName = cfg.ProjectName
	st.PostScript = cfg.PostScript
	st.ScriptPath = cfg.ScriptPath
	st.RuleDir = cfg.RuleDir
	st.OutputDir = cfg.OutputDir
	st.RustEnginePath = cfg.RustEnginePath
	st.LastReport = result.FinalReportPath
	st.LastRawReport = result.RawReportPath
	st.LastEnrichedReport = result.EnrichedReportPath

	return state.Save(projectRoot, st)
}

func runCommand(executable string, args []string) (int, error) {
	cmd := exec.Command(executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	return exitCode, err
}

func finalizeRawReport(outputDir, sourceFilePath string) (string, error) {
	workingRawReportPath := filepath.Join(outputDir, "raw_report.json")
	if _, err := os.Stat(workingRawReportPath); err != nil {
		return "", fmt.Errorf("raw report not generated: %s", workingRawReportPath)
	}

	finalRawPath := filepath.Join(outputDir, buildRawReportFileName(sourceFilePath))
	if err := os.Rename(workingRawReportPath, finalRawPath); err != nil {
		return "", fmt.Errorf("finalize raw report: %w", err)
	}

	return finalRawPath, nil
}

func buildRawReportFileName(sourceFilePath string) string {
	baseName := filepath.Base(sourceFilePath)
	sampleBase := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s_raw.json", sampleBase, ts)
}

func buildEnrichedReportPathFromRaw(rawPath string) string {
	return strings.Replace(rawPath, "_raw.json", ".json", 1)
}

func runRustEnrichment(rustEnginePath, inputReportPath, outputReportPath string) error {
	_, err := runCommand(rustEnginePath, []string{inputReportPath, outputReportPath})
	return err
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}