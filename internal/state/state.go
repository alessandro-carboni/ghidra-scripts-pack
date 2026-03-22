package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	GhidraDir          string `json:"ghidra_dir"`
	ProjectDir         string `json:"project_dir"`
	ProjectName        string `json:"project_name"`
	PostScript         string `json:"post_script"`
	ScriptPath         string `json:"script_path"`
	RuleDir            string `json:"rule_dir"`
	OutputDir          string `json:"output_dir"`
	RustEnginePath     string `json:"rust_engine_path"`
	LastFilePath       string `json:"last_file_path"`
	LastProgram        string `json:"last_program"`
	LastReport         string `json:"last_report"`
	LastRawReport      string `json:"last_raw_report"`
	LastEnrichedReport string `json:"last_enriched_report"`
	LastAIReport       string `json:"last_ai_report"`
	UpdatedAt          string `json:"updated_at"`
}

func StateFilePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".runstate.json")
}

func Load(projectRoot string) (*State, error) {
	path := StateFilePath(projectRoot)

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	return &s, nil
}

func Save(projectRoot string, s State) error {
	s.UpdatedAt = time.Now().Format(time.RFC3339)

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(StateFilePath(projectRoot), data, 0o644)
}
