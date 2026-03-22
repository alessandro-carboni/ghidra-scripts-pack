package ai

import (
	"encoding/json"

	"ghidra-malware-triage/internal/report"
)

func MergeAIIntoReport(reportPath string, analysis AIAnalysis) (string, error) {
	raw, err := report.LoadRaw(reportPath)
	if err != nil {
		return "", err
	}

	analysisMap, err := toMap(analysis)
	if err != nil {
		return "", err
	}

	raw["ai_analysis"] = analysisMap

	if err := report.SaveRaw(reportPath, raw); err != nil {
		return "", err
	}

	mdPath, err := report.WriteMarkdownFromRaw(reportPath, raw)
	if err != nil {
		return "", err
	}

	return mdPath, nil
}

func toMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}
