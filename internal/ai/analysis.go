package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func BuildInputPayload(raw map[string]any, reportPath string) InputPayload {
	globalAnalysis := getMap(raw["global_analysis"])
	functionAnalysis := getMap(raw["function_analysis"])
	behaviorAnalysis := getMap(raw["behavior_analysis"])
	binaryStructure := getMap(raw["binary_structure"])
	rustBlock := getMap(raw["rust_enrichment"])
	analystOutput := getMap(raw["analyst_output"])
	summary := getMap(raw["summary"])
	sample := getMap(raw["sample"])

	return InputPayload{
		SourceReportPath: reportPath,
		SourceReportKind: detectReportKind(reportPath),
		Sample: map[string]any{
			"name":   sample["name"],
			"format": sample["format"],
		},
		Summary: map[string]any{
			"sample_name":              summary["sample_name"],
			"risk_level":               summary["risk_level"],
			"overall_score":            summary["overall_score"],
			"capability_count":         summary["capability_count"],
			"suspicious_api_count":     summary["suspicious_api_count"],
			"packed_warning":           summary["packed_warning"],
			"packing_likelihood_score": summary["packing_likelihood_score"],
			"packer_confidence":        summary["packer_confidence"],
			"packer_family_hint":       summary["packer_family_hint"],
			"top_indicators":           clipStringLike(summary["top_indicators"], 6, 120),
		},
		GlobalSignals: map[string]any{
			"suspicious_apis":     normalizeSuspiciousAPIs(getSlice(globalAnalysis["suspicious_apis"]), 10),
			"capabilities":        normalizeCapabilities(getSlice(globalAnalysis["capabilities"]), 10),
			"interesting_strings": normalizeInterestingStrings(getSlice(globalAnalysis["interesting_strings"]), 6),
			"benign_contexts":     clipStringLike(globalAnalysis["benign_contexts"], 5, 120),
			"score_adjustments":   clipStringLike(globalAnalysis["score_adjustments"], 5, 120),
		},
		TopFunctions: normalizeTopFunctions(getSlice(functionAnalysis["top_functions"]), 4),
		Behavior: map[string]any{
			"behavior_summary": shortText(behaviorAnalysis["behavior_summary"], 500),
			"behavior_story":   shortText(behaviorAnalysis["behavior_story"], 700),
		},
		Packer: map[string]any{
			"likely_packed":      getNestedBool(binaryStructure, "packer_analysis", "likely_packed"),
			"packing_score":      getNestedNumber(binaryStructure, "packer_analysis", "packing_score"),
			"family_hint":        getNestedString(binaryStructure, "packer_analysis", "family_hint", 80),
			"indicator_summary":  getNestedString(binaryStructure, "packer_analysis", "indicator_summary", 180),
			"oep_candidates":     summarizeOEPs(getSlice(binaryStructure["oep_candidates"]), 4),
			"high_entropy_count": countHighEntropySections(getSlice(binaryStructure["section_info"])),
		},
		Rust: map[string]any{
			"decision_summary":      shortText(rustBlock["decision_summary"], 500),
			"malware_risk":          rustBlock["malware_risk"],
			"packing_risk":          rustBlock["packing_risk"],
			"risk_split_summary":    shortText(rustBlock["risk_split_summary"], 300),
			"derived_capabilities":  summarizeNamedScores(getSlice(rustBlock["derived_capabilities"]), 8),
			"confidence_notes":      clipStringLike(rustBlock["confidence_notes"], 6, 120),
			"manual_review_reasons": clipStringLike(rustBlock["manual_review_reasons"], 6, 120),
		},
		AnalystOutput: map[string]any{
			"analyst_summary":  compactAnalystSummary(analystOutput["analyst_summary"]),
			"analyst_targets":  summarizeAnalystTargets(getSlice(analystOutput["analyst_targets"]), 5),
			"analyst_playbook": clipStringLike(analystOutput["analyst_playbook"], 5, 120),
		},
	}
}

func SidecarReportPath(reportPath string) string {
	ext := filepath.Ext(reportPath)
	base := strings.TrimSuffix(reportPath, ext)
	return base + "_ai.json"
}

func SaveAIReport(path string, rep AIOnlyReport) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func detectReportKind(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, "_raw.json"):
		return "raw"
	case strings.HasSuffix(lower, "_ai.json"):
		return "ai_only"
	default:
		return "enriched_or_final"
	}
}

func normalizeSuspiciousAPIs(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"name":                 m["name"],
			"entry":                m["entry"],
			"score":                m["score"],
			"risk_level":           m["risk_level"],
			"roles":                m["roles"],
			"structure_role":       m["structure_role"],
			"matched_capabilities": m["matched_capabilities"],
			"local_api_hits":       clipAnySlice(getSlice(m["local_api_hits"]), 6),
			"primary_reason":       truncateString(getString(m["primary_reason"]), 120),
			"reason_summary":       truncateString(getString(m["reason_summary"]), 180),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		wi := getInt(out[i]["weight"])
		wj := getInt(out[j]["weight"])
		if wi != wj {
			return wi > wj
		}
		return getString(out[i]["name"]) < getString(out[j]["name"])
	})
	return out
}

func normalizeCapabilities(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"name":         m["name"],
			"confidence":   m["confidence"],
			"score":        m["score"],
			"match_count":  m["match_count"],
			"min_matches":  m["min_matches"],
			"matched_apis": m["matched_apis"],
			"source":       m["source"],
		})
	}
	return out
}

func normalizeInterestingStrings(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"address":     m["address"],
			"value":       truncateString(getString(m["value"]), 180),
			"tags":        m["tags"],
			"score":       m["score"],
			"benign_hint": m["benign_hint"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		si := getInt(out[i]["score"])
		sj := getInt(out[j]["score"])
		if si != sj {
			return si > sj
		}
		return getString(out[i]["value"]) < getString(out[j]["value"])
	})
	return out
}

func normalizeTopFunctions(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"name":                    m["name"],
			"entry":                   m["entry"],
			"score":                   m["score"],
			"risk_level":              m["risk_level"],
			"roles":                   m["roles"],
			"structure_role":          m["structure_role"],
			"tags":                    m["tags"],
			"matched_capabilities":    m["matched_capabilities"],
			"local_api_hits":          m["local_api_hits"],
			"primary_reason":          m["primary_reason"],
			"reason_summary":          m["reason_summary"],
			"score_driver_summary":    m["score_driver_summary"],
			"external_call_count":     m["external_call_count"],
			"internal_call_count":     m["internal_call_count"],
			"referenced_string_count": m["referenced_string_count"],
			"evidence":                m["evidence"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		si := getInt(out[i]["score"])
		sj := getInt(out[j]["score"])
		if si != sj {
			return si > sj
		}
		return getString(out[i]["name"]) < getString(out[j]["name"])
	})
	return out
}

func clipAnySlice(items []any, max int) []any {
	if len(items) == 0 {
		return []any{}
	}
	if max <= 0 || len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
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
	s, _ := v.(string)
	return s
}

func getInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case int32:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	default:
		return 0
	}
}

func shortText(v any, max int) string {
	return truncateString(getString(v), max)
}

func clipStringLike(v any, maxItems int, maxLen int) []string {
	items := getSlice(v)
	out := make([]string, 0, len(items))
	for _, item := range clipAnySlice(items, maxItems) {
		s := truncateString(getString(item), maxLen)
		if strings.TrimSpace(s) == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func summarizeOEPs(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"address": m["address"],
			"reason":  truncateString(getString(m["reason"]), 120),
			"score":   m["score"],
		})
	}
	return out
}

func summarizeNamedScores(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"name":       m["name"],
			"score":      m["score"],
			"confidence": m["confidence"],
			"reason":     truncateString(getString(m["reason"]), 100),
		})
	}
	return out
}

func summarizeAnalystTargets(items []any, max int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range clipAnySlice(items, max) {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"function": m["function"],
			"why":      truncateString(getString(m["why"]), 120),
			"priority": m["priority"],
		})
	}
	return out
}

func compactAnalystSummary(v any) any {
	m := getMap(v)
	if len(m) == 0 {
		return nil
	}
	return map[string]any{
		"key_points": clipStringLike(m["key_points"], 5, 120),
	}
}

func countHighEntropySections(items []any) int {
	count := 0
	for _, item := range items {
		m := getMap(item)
		if len(m) == 0 {
			continue
		}
		label := strings.ToLower(getString(m["entropy_label"]))
		if strings.Contains(label, "high") {
			count++
		}
	}
	return count
}

func getNestedBool(root map[string]any, key string, nested string) bool {
	m := getMap(root[key])
	v, _ := m[nested].(bool)
	return v
}

func getNestedNumber(root map[string]any, key string, nested string) any {
	m := getMap(root[key])
	return m[nested]
}

func getNestedString(root map[string]any, key string, nested string, max int) string {
	m := getMap(root[key])
	return truncateString(getString(m[nested]), max)
}
