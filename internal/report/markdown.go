package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func WriteMarkdownFromRaw(reportPath string, raw map[string]any) (string, error) {
	mdPath := strings.TrimSuffix(reportPath, filepath.Ext(reportPath)) + ".md"

	sample := getMap(raw["sample"])
	summary := getMap(raw["summary"])
	analysisMetadata := getMap(raw["analysis_metadata"])
	globalAnalysis := getMap(raw["global_analysis"])
	analystOutput := getMap(raw["analyst_output"])
	binaryStructure := getMap(raw["binary_structure"])
	rustEnrichment := getMap(raw["rust_enrichment"])
	aiAnalysis := getMap(raw["ai_analysis"])
	functionAnalysis := getMap(raw["function_analysis"])

	capabilities := getSlice(globalAnalysis["capabilities"])
	suspiciousAPIs := getSlice(globalAnalysis["suspicious_apis"])
	interestingStrings := getSlice(globalAnalysis["interesting_strings"])
	topFunctions := getSlice(functionAnalysis["top_functions"])

	analystSummary := getMap(analystOutput["analyst_summary"])
	analystTargets := getSlice(analystOutput["analyst_targets"])
	packer := getMap(binaryStructure["packer_analysis"])

	lines := make([]string, 0)

	lines = append(lines, "# Malware Triage Report", "")
	lines = append(lines, "## Sample", "")
	lines = append(lines, fmt.Sprintf("- **Name:** %s", getString(sample["name"])))
	lines = append(lines, fmt.Sprintf("- **Path:** %s", getString(sample["path"])))
	lines = append(lines, fmt.Sprintf("- **Format:** %s", getString(sample["format"])))
	lines = append(lines, "")

	if len(analysisMetadata) > 0 {
		lines = append(lines, "## Analysis Metadata", "")
		lines = append(lines, fmt.Sprintf("- **Schema version:** %s", getString(analysisMetadata["schema_version"])))
		lines = append(lines, fmt.Sprintf("- **Analysis mode:** %s", getString(analysisMetadata["analysis_mode"])))

		rulesMetadata := getMap(analysisMetadata["rules_metadata"])
		if len(rulesMetadata) > 0 {
			lines = append(lines, fmt.Sprintf("- **Rules dir:** %s", getString(rulesMetadata["rules_dir"])))
		}

		lines = append(lines, "")
	}

	lines = append(lines, "## Summary", "")
	lines = append(lines, fmt.Sprintf("- **Risk level:** %s", getString(summary["risk_level"])))
	lines = append(lines, fmt.Sprintf("- **Overall score:** %d", getInt(summary["overall_score"])))
	lines = append(lines, fmt.Sprintf("- **Raw score:** %d", getInt(summary["raw_score"])))
	lines = append(lines, fmt.Sprintf("- **Adjustment total:** %d", getInt(summary["score_adjustment_total"])))
	lines = append(lines, fmt.Sprintf("- **Contract version:** %s", getString(summary["contract_version"])))
	lines = append(lines, fmt.Sprintf("- **Packing likelihood score:** %d", getInt(summary["packing_likelihood_score"])))

	if c := getString(summary["packer_confidence"]); c != "" {
		lines = append(lines, fmt.Sprintf("- **Packer confidence:** %s", c))
	}
	if family := getMeaningfulString(summary["packer_family_hint"]); family != "" {
		lines = append(lines, fmt.Sprintf("- **Packer family hint:** %s", family))
	}

	lines = append(lines, "")

	if pw := getString(summary["packed_warning"]); pw != "" {
		lines = append(lines, fmt.Sprintf("> %s", pw), "")
	}

	if len(analystSummary) > 0 {
		lines = append(lines, "## Analyst Summary", "")
		for _, item := range getSlice(analystSummary["key_points"]) {
			if s, ok := item.(string); ok {
				lines = append(lines, "- "+s)
			}
		}
		lines = append(lines, "")
	}

	if len(aiAnalysis) > 0 {
		lines = append(lines, "## AI Analysis", "")

		if executive := getString(aiAnalysis["executive_summary"]); executive != "" {
			lines = append(lines, "### Executive Summary", "")
			lines = append(lines, executive, "")
		}

		if technical := getString(aiAnalysis["technical_summary"]); technical != "" {
			lines = append(lines, "### Technical Summary", "")
			lines = append(lines, technical, "")
		}

		triageRecommendation := getMap(aiAnalysis["triage_recommendation"])
		if len(triageRecommendation) > 0 {
			lines = append(lines, "### Triage Recommendation", "")
			lines = append(lines, fmt.Sprintf("- **Verdict:** %s", getString(triageRecommendation["verdict"])))
			lines = append(lines, fmt.Sprintf("- **Priority:** %s", getString(triageRecommendation["priority"])))
			lines = append(lines, fmt.Sprintf("- **Next step:** %s", getString(triageRecommendation["next_step"])))
			lines = append(lines, "")
		}

		suspiciousFunctionPriorities := getSlice(aiAnalysis["suspicious_function_priorities"])
		if len(suspiciousFunctionPriorities) > 0 {
			lines = append(lines, "### Suspicious Function Priorities", "")
			for _, item := range suspiciousFunctionPriorities {
				m := getMap(item)
				lines = append(lines, fmt.Sprintf("- **%s**", getString(m["function"])))
				lines = append(lines, fmt.Sprintf("  - Why: %s", getString(m["why"])))
				lines = append(lines, fmt.Sprintf("  - Review focus: %s", getString(m["review_focus"])))
			}
			lines = append(lines, "")
		}

		analystQuestions := getSlice(aiAnalysis["analyst_questions"])
		if len(analystQuestions) > 0 {
			lines = append(lines, "### Analyst Questions", "")
			for _, item := range analystQuestions {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
			lines = append(lines, "")
		}

		confidenceNotes := getSlice(aiAnalysis["confidence_notes"])
		if len(confidenceNotes) > 0 {
			lines = append(lines, "### Confidence Notes", "")
			for _, item := range confidenceNotes {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
			lines = append(lines, "")
		}
	}

	lines = append(lines, "## Top Indicators", "")
	topIndicators := getSlice(summary["top_indicators"])
	if len(topIndicators) == 0 {
		lines = append(lines, "- None")
	} else {
		for _, item := range topIndicators {
			if s, ok := item.(string); ok {
				lines = append(lines, "- "+s)
			}
		}
	}
	lines = append(lines, "")

	lines = append(lines, "## Capabilities", "")
	if len(capabilities) == 0 {
		lines = append(lines, "- None detected")
	} else {
		for _, item := range capabilities {
			m := getMap(item)
			lines = append(lines, fmt.Sprintf("- **%s** (+%d)", getString(m["name"]), getInt(m["score"])))
			lines = append(lines, fmt.Sprintf("  - Confidence: %s", getString(m["confidence"])))
			lines = append(lines, fmt.Sprintf("  - Matched APIs: %s", joinOrNone(getStringSlice(m["matched_apis"]))))
		}
	}
	lines = append(lines, "")

	lines = append(lines, "## Top Functions", "")
	if len(topFunctions) == 0 {
		lines = append(lines, "- None")
	} else {
		limit := len(topFunctions)
		if limit > 10 {
			limit = 10
		}

		for _, item := range topFunctions[:limit] {
			m := getMap(item)

			lines = append(lines, fmt.Sprintf("- **%s** @ %s", getString(m["name"]), getString(m["entry"])))
			lines = append(lines, fmt.Sprintf(
				"  - Score: %d | Risk: %s | Structure: %s",
				getInt(m["score"]),
				getString(m["risk_level"]),
				getString(m["structure_role"]),
			))

			if reason := getString(m["primary_reason"]); reason != "" {
				lines = append(lines, fmt.Sprintf("  - Primary reason: %s", reason))
			}
			if reasonSummary := getString(m["reason_summary"]); reasonSummary != "" {
				lines = append(lines, fmt.Sprintf("  - Reason summary: %s", reasonSummary))
			}
			if drivers := getString(m["score_driver_summary"]); drivers != "" {
				lines = append(lines, fmt.Sprintf("  - Score drivers: %s", drivers))
			}
		}
	}
	lines = append(lines, "")

	lines = append(lines, "## Top Suspicious APIs", "")
	if len(suspiciousAPIs) == 0 {
		lines = append(lines, "- None detected")
	} else {
		limit := len(suspiciousAPIs)
		if limit > 15 {
			limit = 15
		}

		for _, item := range suspiciousAPIs[:limit] {
			m := getMap(item)
			lines = append(lines, fmt.Sprintf("- **%s** (+%d)", getString(m["name"]), getInt(m["weight"])))

			variants := getStringSlice(m["variants"])
			if len(variants) > 0 {
				lines = append(lines, fmt.Sprintf("  - Variants: %s", strings.Join(variants, ", ")))
			}
		}
	}
	lines = append(lines, "")

	lines = append(lines, "## Top Interesting Strings", "")
	if len(interestingStrings) == 0 {
		lines = append(lines, "- None detected")
	} else {
		limit := len(interestingStrings)
		if limit > 10 {
			limit = 10
		}

		for _, item := range interestingStrings[:limit] {
			m := getMap(item)
			lines = append(lines, fmt.Sprintf("- **%s** (+%d)", getString(m["value"]), getInt(m["score"])))
			lines = append(lines, fmt.Sprintf("  - Tags: %s", joinOrNone(getStringSlice(m["tags"]))))

			if getBool(m["benign_hint"]) {
				lines = append(lines, "  - Benign hint: true")
			}
		}
	}
	lines = append(lines, "")

	if len(analystTargets) > 0 {
		lines = append(lines, "## Analyst Targets", "")
		for _, item := range analystTargets {
			m := getMap(item)
			lines = append(lines, fmt.Sprintf("- **%s** @ %s", getString(m["name"]), getString(m["entry"])))
			lines = append(lines, fmt.Sprintf("  - Score: %d | Risk: %s", getInt(m["score"]), getString(m["risk_level"])))
			lines = append(lines, fmt.Sprintf("  - Why: %s", getString(m["why"])))
			lines = append(lines, fmt.Sprintf("  - What to check: %s", getString(m["what_to_check"])))
		}
		lines = append(lines, "")
	}

	if len(packer) > 0 {
		lines = append(lines, "## Packer Analysis", "")
		lines = append(lines, fmt.Sprintf("- **Likely packed:** %v", getBool(packer["likely_packed"])))
		lines = append(lines, fmt.Sprintf("- **Packed likelihood score:** %d", getInt(packer["packed_likelihood_score"])))

		if c := getString(packer["confidence"]); c != "" {
			lines = append(lines, fmt.Sprintf("- **Confidence:** %s", c))
		}
		if family := getMeaningfulString(packer["packer_family_hint"]); family != "" {
			lines = append(lines, fmt.Sprintf("- **Family hint:** %s", family))
		}
		if status := getString(packer["status"]); status != "" {
			lines = append(lines, fmt.Sprintf("- **Status:** %s", status))
		}

		if topOEP := getMap(packer["oep_candidate_summary"]); len(topOEP) > 0 {
			lines = append(lines, fmt.Sprintf(
				"- **Top OEP candidate:** %s (%s)",
				getString(topOEP["address"]),
				getString(topOEP["reason"]),
			))
		}

		indicators := getSlice(packer["indicators"])
		if len(indicators) > 0 {
			lines = append(lines, "- **Indicators:**")
			limit := len(indicators)
			if limit > 10 {
				limit = 10
			}

			for _, item := range indicators[:limit] {
				m := getMap(item)
				lines = append(lines, fmt.Sprintf(
					"  - %s (+%d): %s",
					getString(m["name"]),
					getInt(m["score"]),
					getString(m["reason"]),
				))
			}
		}

		analysisNotes := getSlice(packer["analysis_notes"])
		if len(analysisNotes) > 0 {
			lines = append(lines, "- **Analysis notes:**")
			for _, item := range analysisNotes {
				if s, ok := item.(string); ok {
					lines = append(lines, "  - "+s)
				}
			}
		}

		lines = append(lines, "")
	}

	if len(rustEnrichment) > 0 {
		lines = append(lines, "## Rust Enrichment", "")

		engineMetadata := getMap(rustEnrichment["engine_metadata"])
		if len(engineMetadata) > 0 {
			lines = append(lines, "### Engine Metadata", "")
			lines = append(lines, fmt.Sprintf("- **Engine:** %s", getString(engineMetadata["engine_name"])))
			lines = append(lines, fmt.Sprintf("- **Version:** %s", getString(engineMetadata["engine_version"])))
			lines = append(lines, fmt.Sprintf("- **Input contract version:** %s", getString(engineMetadata["input_contract_version"])))
			lines = append(lines, "")
		}

		schemaValidation := getMap(rustEnrichment["schema_validation"])
		if len(schemaValidation) > 0 {
			lines = append(lines, "### Schema Validation", "")
			lines = append(lines, fmt.Sprintf("- **Valid minimum contract:** %v", getBool(schemaValidation["valid_minimum_contract"])))

			missing := getStringSlice(schemaValidation["missing_fields"])
			if len(missing) > 0 {
				lines = append(lines, fmt.Sprintf("- **Missing fields:** %s", strings.Join(missing, ", ")))
			} else {
				lines = append(lines, "- **Missing fields:** none")
			}

			lines = append(lines, "")
		}

		scoreCalibration := getMap(rustEnrichment["score_calibration"])
		scoreBands := getMap(rustEnrichment["score_bands"])
		if len(scoreCalibration) > 0 || len(scoreBands) > 0 {
			lines = append(lines, "### Score Calibration", "")

			if len(scoreCalibration) > 0 {
				lines = append(lines, fmt.Sprintf("- **Original score:** %d", getInt(scoreCalibration["original_score"])))
				lines = append(lines, fmt.Sprintf("- **Calibrated score:** %d", getInt(scoreCalibration["calibrated_score"])))
				lines = append(lines, fmt.Sprintf("- **Score delta:** %d", getInt(scoreCalibration["delta"])))

				rationale := getSlice(scoreCalibration["rationale"])
				if len(rationale) > 0 {
					lines = append(lines, "- **Calibration rationale:**")
					for _, item := range rationale {
						if s, ok := item.(string); ok {
							lines = append(lines, "  - "+s)
						}
					}
				}
			}

			if len(scoreBands) > 0 {
				lines = append(lines, fmt.Sprintf("- **Original band:** %s", getString(scoreBands["original_band"])))
				lines = append(lines, fmt.Sprintf("- **Calibrated band:** %s", getString(scoreBands["calibrated_band"])))
			}

			lines = append(lines, "")
		}

		decisionSummary := getMap(rustEnrichment["decision_summary"])
		if len(decisionSummary) > 0 {
			lines = append(lines, "### Decision Summary", "")
			lines = append(lines, fmt.Sprintf("- **Primary assessment:** %s", getString(decisionSummary["primary_assessment"])))
			lines = append(lines, fmt.Sprintf("- **Malicious signal strength:** %s", getString(decisionSummary["malicious_signal_strength"])))
			lines = append(lines, fmt.Sprintf("- **Analysis confidence:** %s", getString(decisionSummary["analysis_confidence"])))
			lines = append(lines, fmt.Sprintf("- **Needs manual review:** %v", getBool(decisionSummary["needs_manual_review"])))
			lines = append(lines, fmt.Sprintf("- **Manual review priority:** %s", getString(decisionSummary["manual_review_priority"])))
			lines = append(lines, "")
		}

		malwareRisk := getMap(rustEnrichment["malware_risk"])
		if len(malwareRisk) > 0 {
			lines = append(lines, "### Malware Risk", "")
			lines = append(lines, fmt.Sprintf("- **Score:** %d", getInt(malwareRisk["score"])))
			lines = append(lines, fmt.Sprintf("- **Level:** %s", getString(malwareRisk["level"])))

			rationale := getSlice(malwareRisk["rationale"])
			if len(rationale) > 0 {
				lines = append(lines, "- **Rationale:**")
				for _, item := range rationale {
					if s, ok := item.(string); ok {
						lines = append(lines, "  - "+s)
					}
				}
			}

			lines = append(lines, "")
		}

		packingRisk := getMap(rustEnrichment["packing_risk"])
		if len(packingRisk) > 0 {
			lines = append(lines, "### Packing Risk", "")
			lines = append(lines, fmt.Sprintf("- **Score:** %d", getInt(packingRisk["score"])))
			lines = append(lines, fmt.Sprintf("- **Level:** %s", getString(packingRisk["level"])))

			rationale := getSlice(packingRisk["rationale"])
			if len(rationale) > 0 {
				lines = append(lines, "- **Rationale:**")
				for _, item := range rationale {
					if s, ok := item.(string); ok {
						lines = append(lines, "  - "+s)
					}
				}
			}

			lines = append(lines, "")
		}

		riskSplitSummary := getMap(rustEnrichment["risk_split_summary"])
		if len(riskSplitSummary) > 0 {
			lines = append(lines, "### Risk Split Summary", "")
			lines = append(lines, fmt.Sprintf("- **Dominant risk:** %s", getString(riskSplitSummary["dominant_risk"])))
			lines = append(lines, fmt.Sprintf("- **Interpretation:** %s", getString(riskSplitSummary["interpretation"])))
			lines = append(lines, "")
		}

		scoreDrivers := getSlice(rustEnrichment["score_drivers"])
		if len(scoreDrivers) > 0 {
			lines = append(lines, "### Score Drivers", "")
			for _, item := range scoreDrivers {
				m := getMap(item)
				lines = append(lines, fmt.Sprintf(
					"- **%s** | direction=%s | weight=%d",
					getString(m["driver"]),
					getString(m["direction"]),
					getInt(m["weight"]),
				))
				if rationale := getString(m["rationale"]); rationale != "" {
					lines = append(lines, "  - "+rationale)
				}
			}
			lines = append(lines, "")
		}

		capabilityConfidence := getSlice(rustEnrichment["capability_confidence"])
		if len(capabilityConfidence) > 0 {
			lines = append(lines, "### Capability Confidence", "")
			for _, item := range capabilityConfidence {
				m := getMap(item)
				lines = append(lines, fmt.Sprintf(
					"- **%s** | base=%s | calibrated=%s",
					getString(m["name"]),
					getString(m["base_confidence"]),
					getString(m["calibrated_confidence"]),
				))

				rationale := getSlice(m["rationale"])
				for _, r := range rationale {
					if s, ok := r.(string); ok {
						lines = append(lines, "  - "+s)
					}
				}
			}
			lines = append(lines, "")
		}

		derivedCapabilities := getSlice(rustEnrichment["derived_capabilities"])
		if len(derivedCapabilities) > 0 {
			lines = append(lines, "### Derived Capabilities", "")
			for _, item := range derivedCapabilities {
				m := getMap(item)
				lines = append(lines, fmt.Sprintf("- **%s** (%s)", getString(m["name"]), getString(m["confidence"])))

				rationale := getSlice(m["rationale"])
				for _, r := range rationale {
					if s, ok := r.(string); ok {
						lines = append(lines, "  - "+s)
					}
				}
			}
			lines = append(lines, "")
		}

		confidenceNotes := getSlice(rustEnrichment["confidence_notes"])
		if len(confidenceNotes) > 0 {
			lines = append(lines, "### Confidence Notes", "")
			for _, item := range confidenceNotes {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
			lines = append(lines, "")
		}

		riskAnnotations := getSlice(rustEnrichment["risk_annotations"])
		if len(riskAnnotations) > 0 {
			lines = append(lines, "### Risk Annotations", "")
			for _, item := range riskAnnotations {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
			lines = append(lines, "")
		}

		manualReviewReasons := getSlice(rustEnrichment["manual_review_reasons"])
		if len(manualReviewReasons) > 0 {
			lines = append(lines, "### Manual Review Reasons", "")
			for _, item := range manualReviewReasons {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
			lines = append(lines, "")
		}
	}

	content := strings.Join(lines, "\n")
	if err := os.WriteFile(mdPath, []byte(content), 0o644); err != nil {
		return "", err
	}

	return mdPath, nil
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func getMeaningfulString(v any) string {
	s := strings.TrimSpace(getString(v))
	if s == "" {
		return ""
	}

	switch strings.ToLower(s) {
	case "none", "unknown", "n/a", "na", "null":
		return ""
	default:
		return s
	}
}
