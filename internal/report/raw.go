package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func LoadRaw(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return raw, nil
}

func Pretty(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":"%v"}`, err)
	}
	return string(data)
}

func getMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func getSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func getString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}

func getBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	default:
		return false
	}
}

func getInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case float32:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case int32:
		return int(x)
	default:
		return 0
	}
}

func getStringSlice(v any) []string {
	items := getSlice(v)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func pathGet(root map[string]any, path string) (any, bool) {
	current := any(root)
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := m[part]
		if !exists {
			return nil, false
		}
		current = next
	}
	return current, true
}

func SelectOutputField(raw map[string]any, field string) (any, []string, error) {
	fieldMap := map[string]string{
		"analysis_metadata":         "analysis_metadata",
		"rule_contract":             "rule_contract",
		"rust_enrichment":           "rust_enrichment",
		"sample":                    "sample",

		"global_analysis":           "global_analysis",
		"external_symbols":          "global_analysis.external_symbols",
		"suspicious_apis":           "global_analysis.suspicious_apis",
		"capabilities":              "global_analysis.capabilities",
		"interesting_strings":       "global_analysis.interesting_strings",
		"strings":                   "global_analysis.strings",
		"benign_contexts":           "global_analysis.benign_contexts",
		"score_adjustments":         "global_analysis.score_adjustments",

		"function_analysis":         "function_analysis",
		"functions":                 "function_analysis.functions",
		"top_functions":             "function_analysis.top_functions",
		"function_role_summary":     "function_analysis.function_role_summary",

		"behavior_analysis":         "behavior_analysis",
		"callgraph":                 "behavior_analysis.callgraph",
		"behavior_clusters":         "behavior_analysis.behavior_clusters",
		"execution_flow_hypotheses": "behavior_analysis.execution_flow_hypotheses",
		"three_hop_flows":           "behavior_analysis.three_hop_flows",
		"behavior_summary":          "behavior_analysis.behavior_summary",
		"behavior_story":            "behavior_analysis.behavior_story",

		"binary_structure":          "binary_structure",
		"packer_analysis":           "binary_structure.packer_analysis",
		"entrypoint_info":           "binary_structure.entrypoint_info",
		"entrypoint_window":         "binary_structure.entrypoint_window",
		"oep_candidates":            "binary_structure.oep_candidates",
		"section_info":              "binary_structure.section_info",

		"analyst_output":            "analyst_output",
		"analyst_summary":           "analyst_output.analyst_summary",
		"analyst_targets":           "analyst_output.analyst_targets",
		"analyst_playbook":          "analyst_output.analyst_playbook",
	}

	allowed := make([]string, 0, len(fieldMap))
	for k := range fieldMap {
		allowed = append(allowed, k)
	}
	sort.Strings(allowed)

	path, ok := fieldMap[field]
	if !ok {
		return nil, allowed, fmt.Errorf("unsupported output field: %s", field)
	}

	value, exists := pathGet(raw, path)
	if !exists {
		return nil, allowed, fmt.Errorf("field exists in map but not in report: %s", field)
	}

	return value, allowed, nil
}