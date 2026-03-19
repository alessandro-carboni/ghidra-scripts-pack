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
	InputPath       string
	SampleName      string
	RawReportPath   string
	FinalReportPath string
	ExitCode        int
	StartedAt       time.Time
	FinishedAt      time.Time
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
	rawReportPath := filepath.Join(cfg.OutputDir, "raw_report.json")

	if err := removeIfExists(rawReportPath); err != nil {
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
	finishedAt := time.Now()

	if err != nil {
		return &ScanResult{
			InputPath:     resolvedInput,
			SampleName:    sampleName,
			RawReportPath: rawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
		}, fmt.Errorf("ghidra scan failed: %w", err)
	}

	finalReportPath, err := finalizeReport(cfg.OutputDir, resolvedInput)
	if err != nil {
		return &ScanResult{
			InputPath:     resolvedInput,
			SampleName:    sampleName,
			RawReportPath: rawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
		}, err
	}

	return &ScanResult{
		InputPath:       resolvedInput,
		SampleName:      sampleName,
		RawReportPath:   rawReportPath,
		FinalReportPath: finalReportPath,
		ExitCode:        exitCode,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
	}, nil
}

func FastScan(cfg config.Config, st state.State) (*ScanResult, error) {
	if st.LastProgram == "" {
		return nil, fmt.Errorf("missing last program in saved state")
	}
	if st.LastFilePath == "" {
		return nil, fmt.Errorf("missing last file path in saved state")
	}

	rawReportPath := filepath.Join(cfg.OutputDir, "raw_report.json")
	if err := removeIfExists(rawReportPath); err != nil {
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
	finishedAt := time.Now()

	if err != nil {
		return &ScanResult{
			InputPath:     st.LastFilePath,
			SampleName:    st.LastProgram,
			RawReportPath: rawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
		}, fmt.Errorf("ghidra fast scan failed: %w", err)
	}

	finalReportPath, err := finalizeReport(cfg.OutputDir, st.LastFilePath)
	if err != nil {
		return &ScanResult{
			InputPath:     st.LastFilePath,
			SampleName:    st.LastProgram,
			RawReportPath: rawReportPath,
			ExitCode:      exitCode,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
		}, err
	}

	return &ScanResult{
		InputPath:       st.LastFilePath,
		SampleName:      st.LastProgram,
		RawReportPath:   rawReportPath,
		FinalReportPath: finalReportPath,
		ExitCode:        exitCode,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
	}, nil
}

func SaveStateFromScan(projectRoot string, cfg config.Config, result *ScanResult) error {
	s := state.State{
		GhidraDir:    cfg.GhidraDir,
		ProjectDir:   cfg.ProjectDir,
		ProjectName:  cfg.ProjectName,
		PostScript:   cfg.PostScript,
		ScriptPath:   cfg.ScriptPath,
		RuleDir:      cfg.RuleDir,
		OutputDir:    cfg.OutputDir,
		LastFilePath: result.InputPath,
		LastProgram:  filepath.Base(result.InputPath),
		LastReport:   result.FinalReportPath,
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
	st.LastReport = result.FinalReportPath

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

func finalizeReport(outputDir, sourceFilePath string) (string, error) {
	rawReportPath := filepath.Join(outputDir, "raw_report.json")
	if _, err := os.Stat(rawReportPath); err != nil {
		return "", fmt.Errorf("raw report not generated: %s", rawReportPath)
	}

	finalReportPath := filepath.Join(outputDir, buildReportFileName(sourceFilePath))
	if err := os.Rename(rawReportPath, finalReportPath); err != nil {
		return "", fmt.Errorf("finalize report: %w", err)
	}

	return finalReportPath, nil
}

func buildReportFileName(sourceFilePath string) string {
	baseName := filepath.Base(sourceFilePath)
	sampleBase := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.json", sampleBase, ts)
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}