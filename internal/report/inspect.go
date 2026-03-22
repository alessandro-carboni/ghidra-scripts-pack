package report

import (
	"fmt"
	"sort"
)

func InspectFunction(raw map[string]any, functionName string) (map[string]any, error) {
	functionAnalysis := getMap(raw["function_analysis"])
	functions := getSlice(functionAnalysis["functions"])
	topFunctions := getSlice(functionAnalysis["top_functions"])

	if len(functions) == 0 {
		return nil, fmt.Errorf("no function analysis found in report")
	}

	var topFunctionView map[string]any

	for _, item := range topFunctions {
		tf := getMap(item)
		if getString(tf["name"]) == functionName {
			topFunctionView = map[string]any{
				"primary_reason":       tf["primary_reason"],
				"reason_summary":       tf["reason_summary"],
				"score_driver_summary": tf["score_driver_summary"],
				"evidence":             tf["evidence"],
			}
			break
		}
	}

	for _, item := range functions {
		fn := getMap(item)
		if getString(fn["name"]) == functionName {
			return map[string]any{
				"inspect_type":         "function",
				"name":                 fn["name"],
				"entry":                fn["entry"],
				"score":                fn["score"],
				"risk_level":           fn["risk_level"],
				"structure_role":       fn["structure_role"],
				"roles":                fn["roles"],
				"tags":                 fn["tags"],
				"matched_capabilities": fn["matched_capabilities"],
				"local_api_hits":       fn["local_api_hits"],
				"external_calls":       fn["external_calls"],
				"internal_calls":       fn["internal_calls"],
				"incoming_calls":       fn["incoming_calls"],
				"referenced_strings":   fn["referenced_strings"],
				"score_breakdown":      fn["score_breakdown"],
				"top_function_view":    topFunctionView,
			}, nil
		}
	}

	return nil, fmt.Errorf("function not found: %s", functionName)
}

func InspectCapability(raw map[string]any, capabilityName string) (map[string]any, error) {
	globalAnalysis := getMap(raw["global_analysis"])
	functionAnalysis := getMap(raw["function_analysis"])
	rustBlock := getMap(raw["rust_enrichment"])

	capabilities := getSlice(globalAnalysis["capabilities"])
	functions := getSlice(functionAnalysis["functions"])

	var capability any
	for _, item := range capabilities {
		capMap := getMap(item)
		if getString(capMap["name"]) == capabilityName {
			capability = capMap
			break
		}
	}

	var rustCapabilityConfidence any
	rustCaps := getSlice(rustBlock["capability_confidence"])
	for _, item := range rustCaps {
		m := getMap(item)
		if getString(m["name"]) == capabilityName {
			rustCapabilityConfidence = m
			break
		}
	}

	related := make([]map[string]any, 0)

	for _, item := range functions {
		fn := getMap(item)

		matchedCaps := getStringSlice(fn["matched_capabilities"])
		tags := getStringSlice(fn["tags"])
		roles := getStringSlice(fn["roles"])

		match := contains(matchedCaps, capabilityName) ||
			contains(tags, capabilityName) ||
			contains(roles, capabilityName) ||
			(capabilityName == "networking" && contains(roles, "network")) ||
			(capabilityName == "process_injection" && contains(roles, "injection")) ||
			(capabilityName == "dynamic_loading" && contains(roles, "loader"))

		if match {
			related = append(related, map[string]any{
				"name":                 fn["name"],
				"entry":                fn["entry"],
				"score":                fn["score"],
				"risk_level":           fn["risk_level"],
				"structure_role":       fn["structure_role"],
				"roles":                fn["roles"],
				"tags":                 fn["tags"],
				"matched_capabilities": fn["matched_capabilities"],
				"local_api_hits":       fn["local_api_hits"],
			})
		}
	}

	sort.Slice(related, func(i, j int) bool {
		si := getInt(related[i]["score"])
		sj := getInt(related[j]["score"])
		if si != sj {
			return si > sj
		}
		return getString(related[i]["name"]) < getString(related[j]["name"])
	})

	if len(related) > 12 {
		related = related[:12]
	}

	if capability == nil && len(related) == 0 && rustCapabilityConfidence == nil {
		return nil, fmt.Errorf("capability not found and no related functions matched: %s", capabilityName)
	}

	return map[string]any{
		"inspect_type":                        "capability",
		"requested_capability":                capabilityName,
		"capability_found_in_global_analysis": capability != nil,
		"capability":                          capability,
		"rust_capability_confidence":          rustCapabilityConfidence,
		"related_function_count":              len(related),
		"related_functions":                   related,
	}, nil
}

func InspectPacker(raw map[string]any) (map[string]any, error) {
	binaryStructure := getMap(raw["binary_structure"])
	packer := getMap(binaryStructure["packer_analysis"])
	if len(packer) == 0 {
		return nil, fmt.Errorf("no packer analysis found in report")
	}

	return map[string]any{
		"inspect_type":      "packer",
		"packer_analysis":   binaryStructure["packer_analysis"],
		"entrypoint_info":   binaryStructure["entrypoint_info"],
		"entrypoint_window": binaryStructure["entrypoint_window"],
		"oep_candidates":    binaryStructure["oep_candidates"],
		"section_info":      binaryStructure["section_info"],
	}, nil
}

func InspectStrings(raw map[string]any) (map[string]any, error) {
	globalAnalysis := getMap(raw["global_analysis"])
	items := getSlice(globalAnalysis["interesting_strings"])
	if len(items) == 0 {
		return nil, fmt.Errorf("no interesting strings found in report")
	}

	return map[string]any{
		"inspect_type": "interesting_strings",
		"count":        len(items),
		"items":        items,
	}, nil
}

func InspectRust(raw map[string]any) (map[string]any, error) {
	rustBlock := getMap(raw["rust_enrichment"])
	if len(rustBlock) == 0 {
		return nil, fmt.Errorf("no rust enrichment found in report")
	}

	return map[string]any{
		"inspect_type":          "rust_enrichment",
		"engine_metadata":       rustBlock["engine_metadata"],
		"rules_metadata":        rustBlock["rules_metadata"],
		"schema_validation":     rustBlock["schema_validation"],
		"score_calibration":     rustBlock["score_calibration"],
		"score_bands":           rustBlock["score_bands"],
		"decision_summary":      rustBlock["decision_summary"],
		"malware_risk":          rustBlock["malware_risk"],
		"packing_risk":          rustBlock["packing_risk"],
		"risk_split_summary":    rustBlock["risk_split_summary"],
		"score_drivers":         rustBlock["score_drivers"],
		"capability_confidence": rustBlock["capability_confidence"],
		"derived_capabilities":  rustBlock["derived_capabilities"],
		"confidence_notes":      rustBlock["confidence_notes"],
		"risk_annotations":      rustBlock["risk_annotations"],
		"manual_review_reasons": rustBlock["manual_review_reasons"],
	}, nil
}

func contains(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}
