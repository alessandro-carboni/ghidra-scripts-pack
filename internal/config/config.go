package config

import (
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	GhidraDir   string
	ProjectDir  string
	ProjectName string
	ScriptPath  string
	PostScript  string
	RuleDir     string
	OutputDir   string
	ReportsDir  string
}

func Default(projectRoot string) Config {
	return Config{
		GhidraDir:   "",
		ProjectDir:  `C:\ghidra-projects`,
		ProjectName: "TriageProject",
		ScriptPath:  filepath.Join(projectRoot, "ghidra_scripts"),
		PostScript:  "export_report.py",
		RuleDir:     filepath.Join(projectRoot, "rules"),
		OutputDir:   filepath.Join(projectRoot, "reports"),
		ReportsDir:  filepath.Join(projectRoot, "reports"),
	}
}

func (c *Config) ApplyOverrides(
	ghidraDir string,
	projectDir string,
	projectName string,
	scriptPath string,
	postScript string,
	ruleDir string,
	outputDir string,
) {
	if ghidraDir != "" {
		c.GhidraDir = ghidraDir
	}
	if projectDir != "" {
		c.ProjectDir = projectDir
	}
	if projectName != "" {
		c.ProjectName = projectName
	}
	if scriptPath != "" {
		c.ScriptPath = scriptPath
	}
	if postScript != "" {
		c.PostScript = postScript
	}
	if ruleDir != "" {
		c.RuleDir = ruleDir
	}
	if outputDir != "" {
		c.OutputDir = outputDir
		c.ReportsDir = outputDir
	}
}

func (c Config) ValidateForScan() error {
	if c.GhidraDir == "" {
		return errors.New("missing ghidra directory")
	}
	if c.ProjectDir == "" {
		return errors.New("missing project directory")
	}
	if c.ProjectName == "" {
		return errors.New("missing project name")
	}
	if c.ScriptPath == "" {
		return errors.New("missing script path")
	}
	if c.PostScript == "" {
		return errors.New("missing post script")
	}
	if c.RuleDir == "" {
		return errors.New("missing rule dir")
	}
	if c.OutputDir == "" {
		return errors.New("missing output dir")
	}
	return nil
}

func EnsureDirs(c Config) error {
	dirs := []string{
		c.ProjectDir,
		c.OutputDir,
		c.ReportsDir,
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	return nil
}

func ProjectRootFromWD() (string, error) {
	return os.Getwd()
}