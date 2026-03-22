package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type Config struct {
	GhidraDir        string
	ProjectDir       string
	ProjectName      string
	ScriptPath       string
	PostScript       string
	RuleDir          string
	OutputDir        string
	ReportsDir       string
	RustEnginePath   string
	AIBaseURL        string
	AIModel          string
	AIAPIKey         string
	AITimeoutSeconds int
}

func Default(projectRoot string) Config {
	return Config{
		GhidraDir:        "",
		ProjectDir:       defaultProjectDir(),
		ProjectName:      "TriageProject",
		ScriptPath:       filepath.Join(projectRoot, "ghidra_scripts"),
		PostScript:       "export_report.py",
		RuleDir:          filepath.Join(projectRoot, "rules"),
		OutputDir:        filepath.Join(projectRoot, "reports"),
		ReportsDir:       filepath.Join(projectRoot, "reports"),
		RustEnginePath:   filepath.Join(projectRoot, "rust_engine", "target", "debug", defaultRustEngineBinaryName()),
		AIBaseURL:        strings.TrimSpace(os.Getenv("TRIAGE_AI_BASE_URL")),
		AIModel:          strings.TrimSpace(os.Getenv("TRIAGE_AI_MODEL")),
		AIAPIKey:         strings.TrimSpace(os.Getenv("TRIAGE_AI_API_KEY")),
		AITimeoutSeconds: readIntEnv("TRIAGE_AI_TIMEOUT_SECONDS", 90),
	}
}

func defaultProjectDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ghidra-projects`
	}

	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(os.TempDir(), "ghidra-projects")
	}

	return filepath.Join(home, "ghidra-projects")
}

func defaultRustEngineBinaryName() string {
	if runtime.GOOS == "windows" {
		return "rust_engine.exe"
	}
	return "rust_engine"
}

func (c *Config) ApplyOverrides(
	ghidraDir string,
	projectDir string,
	projectName string,
	scriptPath string,
	postScript string,
	ruleDir string,
	outputDir string,
	rustEnginePath string,
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
	if rustEnginePath != "" {
		c.RustEnginePath = rustEnginePath
	}
}

func (c *Config) ApplyAIOverrides(
	baseURL string,
	model string,
	apiKey string,
	timeoutSeconds int,
) {
	if strings.TrimSpace(baseURL) != "" {
		c.AIBaseURL = strings.TrimSpace(baseURL)
	}
	if strings.TrimSpace(model) != "" {
		c.AIModel = strings.TrimSpace(model)
	}
	if apiKey != "" {
		c.AIAPIKey = apiKey
	}
	if timeoutSeconds > 0 {
		c.AITimeoutSeconds = timeoutSeconds
	}
}

func (c Config) ValidateForAnalysis() error {
	if strings.TrimSpace(c.GhidraDir) == "" {
		return errors.New("missing ghidra directory")
	}
	if strings.TrimSpace(c.ProjectDir) == "" {
		return errors.New("missing project directory")
	}
	if strings.TrimSpace(c.ProjectName) == "" {
		return errors.New("missing project name")
	}
	if strings.TrimSpace(c.ScriptPath) == "" {
		return errors.New("missing script path")
	}
	if strings.TrimSpace(c.PostScript) == "" {
		return errors.New("missing post script")
	}
	if strings.TrimSpace(c.RuleDir) == "" {
		return errors.New("missing rule dir")
	}
	if strings.TrimSpace(c.OutputDir) == "" {
		return errors.New("missing output dir")
	}
	return nil
}

func (c Config) ValidateForEnrichment() error {
	if strings.TrimSpace(c.OutputDir) == "" {
		return errors.New("missing output dir")
	}
	if strings.TrimSpace(c.RustEnginePath) == "" {
		return errors.New("missing rust engine path")
	}
	return nil
}

func (c Config) ValidateForAI() error {
	if strings.TrimSpace(c.AIBaseURL) == "" {
		return errors.New("missing AI base URL (set TRIAGE_AI_BASE_URL or pass -ai-base-url)")
	}
	if strings.TrimSpace(c.AIModel) == "" {
		return errors.New("missing AI model (set TRIAGE_AI_MODEL or pass -ai-model)")
	}
	if c.AITimeoutSeconds <= 0 {
		return errors.New("invalid AI timeout")
	}
	return nil
}

func (c Config) ValidateForScan() error {
	return c.ValidateForAnalysis()
}

func EnsureDirs(c Config) error {
	dirs := []string{
		c.ProjectDir,
		c.OutputDir,
		c.ReportsDir,
	}

	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
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

func readIntEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}

	return v
}
