package report

import (
	"path/filepath"
	"sort"
)

func BuildDiff(leftRaw, rightRaw map[string]any, leftPath, rightPath string) map[string]any {
	leftSummary := getMap(leftRaw["summary"])
	rightSummary := getMap(rightRaw["summary"])

	leftGlobal := getMap(leftRaw["global_analysis"])
	rightGlobal := getMap(rightRaw["global_analysis"])

	leftFunctions := getMap(leftRaw["function_analysis"])
	rightFunctions := getMap(rightRaw["function_analysis"])

	leftBinary := getMap(leftRaw["binary_structure"])
	rightBinary := getMap(rightRaw["binary_structure"])

	leftPacker := getMap(leftBinary["packer_analysis"])
	rightPacker := getMap(rightBinary["packer_analysis"])

	leftCapabilities := getNameList(leftGlobal["capabilities"])
	rightCapabilities := getNameList(rightGlobal["capabilities"])

	leftTopFunctions := getNameList(leftFunctions["top_functions"])
	rightTopFunctions := getNameList(rightFunctions["top_functions"])

	leftStrings := getValueList(leftGlobal["interesting_strings"], "value")
	rightStrings := getValueList(rightGlobal["interesting_strings"], "value")

	return map[string]any{
		"inspect_type": "report_diff",
		"left_report": map[string]any{
			"name":        filepath.Base(leftPath),
			"sample_name": getString(getMap(leftRaw["sample"])["name"]),
		},
		"right_report": map[string]any{
			"name":        filepath.Base(rightPath),
			"sample_name": getString(getMap(rightRaw["sample"])["name"]),
		},
		"summary_diff": map[string]any{
			"left_risk_level":                leftSummary["risk_level"],
			"right_risk_level":               rightSummary["risk_level"],
			"left_overall_score":             getInt(leftSummary["overall_score"]),
			"right_overall_score":            getInt(rightSummary["overall_score"]),
			"overall_score_delta":            getInt(rightSummary["overall_score"]) - getInt(leftSummary["overall_score"]),
			"left_raw_score":                 getInt(leftSummary["raw_score"]),
			"right_raw_score":                getInt(rightSummary["raw_score"]),
			"raw_score_delta":                getInt(rightSummary["raw_score"]) - getInt(leftSummary["raw_score"]),
			"left_capability_count":          getInt(leftSummary["capability_count"]),
			"right_capability_count":         getInt(rightSummary["capability_count"]),
			"capability_count_delta":         getInt(rightSummary["capability_count"]) - getInt(leftSummary["capability_count"]),
			"left_suspicious_api_count":      getInt(leftSummary["suspicious_api_count"]),
			"right_suspicious_api_count":     getInt(rightSummary["suspicious_api_count"]),
			"suspicious_api_count_delta":     getInt(rightSummary["suspicious_api_count"]) - getInt(leftSummary["suspicious_api_count"]),
			"left_interesting_string_count":  getInt(leftSummary["interesting_string_count"]),
			"right_interesting_string_count": getInt(rightSummary["interesting_string_count"]),
			"interesting_string_count_delta": getInt(rightSummary["interesting_string_count"]) - getInt(leftSummary["interesting_string_count"]),
		},
		"capability_diff":        compareStringSets(leftCapabilities, rightCapabilities),
		"top_function_diff":      compareStringSets(leftTopFunctions, rightTopFunctions),
		"interesting_string_diff": compareStringSets(leftStrings, rightStrings),
		"packer_diff": map[string]any{
			"left_likely_packed":            getBool(leftPacker["likely_packed"]),
			"right_likely_packed":           getBool(rightPacker["likely_packed"]),
			"left_packed_likelihood_score":  getInt(leftPacker["packed_likelihood_score"]),
			"right_packed_likelihood_score": getInt(rightPacker["packed_likelihood_score"]),
			"packed_likelihood_score_delta": getInt(rightPacker["packed_likelihood_score"]) - getInt(leftPacker["packed_likelihood_score"]),
			"left_family_hint":              leftPacker["packer_family_hint"],
			"right_family_hint":             rightPacker["packer_family_hint"],
		},
	}
}

func getNameList(v any) []string {
	items := getSlice(v)
	out := make([]string, 0)
	for _, item := range items {
		m := getMap(item)
		if name := getString(m["name"]); name != "" {
			out = append(out, name)
			continue
		}
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func getValueList(v any, property string) []string {
	items := getSlice(v)
	out := make([]string, 0)
	for _, item := range items {
		m := getMap(item)
		if value := getString(m[property]); value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func compareStringSets(left, right []string) map[string]any {
	added := make([]string, 0)
	removed := make([]string, 0)

	leftSet := make(map[string]struct{}, len(left))
	rightSet := make(map[string]struct{}, len(right))

	for _, x := range left {
		leftSet[x] = struct{}{}
	}
	for _, x := range right {
		rightSet[x] = struct{}{}
	}

	for _, x := range right {
		if _, ok := leftSet[x]; !ok {
			added = append(added, x)
		}
	}
	for _, x := range left {
		if _, ok := rightSet[x]; !ok {
			removed = append(removed, x)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	return map[string]any{
		"added":   uniqueStrings(added),
		"removed": uniqueStrings(removed),
	}
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	last := ""
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
			last = s
		}
	}
	return out
}