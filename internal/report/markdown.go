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

	capabilities := getSlice(globalAnalysis["capabilities"])
	suspiciousAPIs := getSlice(globalAnalysis["suspicious_apis"])
	interestingStrings := getSlice(globalAnalysis["interesting_strings"])

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

	lines = append(lines, "## Top Indicators", "")
	for _, item := range getSlice(summary["top_indicators"]) {
		if s, ok := item.(string); ok {
			lines = append(lines, "- "+s)
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
			lines = append(lines, fmt.Sprintf("  - Matched APIs: %s", strings.Join(getStringSlice(m["matched_apis"]), ", ")))
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
			lines = append(lines, fmt.Sprintf("  - Tags: %s", strings.Join(getStringSlice(m["tags"]), ", ")))
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
		if family := getString(packer["packer_family_hint"]); family != "" {
			lines = append(lines, fmt.Sprintf("- **Family hint:** %s", family))
		}
	rustEnrichment := getMap(raw["rust_enrichment"])
	if len(rustEnrichment) > 0 {
		lines = append(lines, "", "## Rust Enrichment", "")

		engineMetadata := getMap(rustEnrichment["engine_metadata"])
		if len(engineMetadata) > 0 {
			lines = append(lines, fmt.Sprintf("- **Engine:** %s", getString(engineMetadata["engine_name"])))
			lines = append(lines, fmt.Sprintf("- **Version:** %s", getString(engineMetadata["engine_version"])))
			lines = append(lines, fmt.Sprintf("- **Input contract version:** %s", getString(engineMetadata["input_contract_version"])))
		}

		scoreCalibration := getMap(rustEnrichment["score_calibration"])
		if len(scoreCalibration) > 0 {
			lines = append(lines, fmt.Sprintf("- **Calibrated score:** %d", getInt(scoreCalibration["calibrated_score"])))
			lines = append(lines, fmt.Sprintf("- **Score delta:** %d", getInt(scoreCalibration["delta"])))
		}

		scoreBands := getMap(rustEnrichment["score_bands"])
		if len(scoreBands) > 0 {
			lines = append(lines, fmt.Sprintf("- **Original band:** %s", getString(scoreBands["original_band"])))
			lines = append(lines, fmt.Sprintf("- **Calibrated band:** %s", getString(scoreBands["calibrated_band"])))
		}

		decisionSummary := getMap(rustEnrichment["decision_summary"])
		if len(decisionSummary) > 0 {
			lines = append(lines, fmt.Sprintf("- **Malicious signal strength:** %s", getString(decisionSummary["malicious_signal_strength"])))
			lines = append(lines, fmt.Sprintf("- **Analysis confidence:** %s", getString(decisionSummary["analysis_confidence"])))
			lines = append(lines, fmt.Sprintf("- **Needs manual review:** %v", getBool(decisionSummary["needs_manual_review"])))
		}

		derivedCapabilities := getSlice(rustEnrichment["derived_capabilities"])
		if len(derivedCapabilities) > 0 {
			lines = append(lines, "", "### Derived Capabilities", "")
			for _, item := range derivedCapabilities {
				m := getMap(item)
				lines = append(lines, fmt.Sprintf("- **%s** (%s)", getString(m["name"]), getString(m["confidence"])))
			}
		}

		confidenceNotes := getSlice(rustEnrichment["confidence_notes"])
		if len(confidenceNotes) > 0 {
			lines = append(lines, "", "### Confidence Notes", "")
			for _, item := range confidenceNotes {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
		}

		riskAnnotations := getSlice(rustEnrichment["risk_annotations"])
		if len(riskAnnotations) > 0 {
			lines = append(lines, "", "### Risk Annotations", "")
			for _, item := range riskAnnotations {
				if s, ok := item.(string); ok {
					lines = append(lines, "- "+s)
				}
			}
		}
	}
	}

	content := strings.Join(lines, "\n")
	if err := os.WriteFile(mdPath, []byte(content), 0o644); err != nil {
		return "", err
	}

	return mdPath, nil
}