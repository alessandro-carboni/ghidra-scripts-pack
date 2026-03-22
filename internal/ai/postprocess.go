package ai

import (
	"fmt"
	"strings"
)

func ApplyGuardrails(analysis *AIAnalysis, input InputPayload) {
	if analysis == nil {
		return
	}

	summaryRisk := strings.ToLower(stringifyAny(input.Summary["risk_level"]))
	packedWarning := strings.ToLower(stringifyAny(input.Summary["packed_warning"]))
	benignContexts := strings.Join(toStringSlice(input.GlobalSignals["benign_contexts"]), " | ")
	scoreAdjustments := strings.Join(toStringSlice(input.GlobalSignals["score_adjustments"]), " | ")

	malwareRisk := getMap(input.Rust["malware_risk"])
	packingRisk := getMap(input.Rust["packing_risk"])

	malwareRiskLevel := strings.ToLower(stringifyAny(malwareRisk["level"]))
	packingRiskLevel := strings.ToLower(stringifyAny(packingRisk["level"]))

	execLower := strings.ToLower(strings.TrimSpace(analysis.ExecutiveSummary))
	techLower := strings.ToLower(strings.TrimSpace(analysis.TechnicalSummary))

	hasBenignHints := containsAny(strings.ToLower(benignContexts),
		"desktop", "ui", "editor", "notepad", "benign", "shell utility", "system tool",
	) || containsAny(strings.ToLower(scoreAdjustments),
		"benign", "deboost", "reduced", "contextual benign",
	)

	aiLooksBenign := containsAny(execLower,
		"likely benign", "benign", "low malware risk", "not strong enough to conclude malicious intent",
	) || containsAny(techLower,
		"low malware risk", "mixed signals", "normal program behavior", "benign",
	)

	likelyPacked := strings.Contains(packedWarning, "packed") ||
		packingRiskLevel == "high"

	likelyStrongMalware := malwareRiskLevel == "high" ||
		summaryRisk == "critical" ||
		strings.EqualFold(analysis.TriageRecommendation.Verdict, "likely-malicious")

	likelyLowRiskBenign := (summaryRisk == "low" || malwareRiskLevel == "low") && !likelyStrongMalware

	switch {
	case likelyPacked && !likelyStrongMalware:
		analysis.TriageRecommendation.Verdict = "likely-packed-needs-unpacking"
		analysis.TriageRecommendation.Priority = normalizePriority(analysis.TriageRecommendation.Priority, "medium")
		if strings.TrimSpace(analysis.TriageRecommendation.NextStep) == "" {
			analysis.TriageRecommendation.NextStep = "Validate whether the sample is packed, inspect entrypoint/OEP candidates, and avoid over-interpreting stub-level signals before deeper unpacking."
		}
		addConfidenceNote(analysis, "Static visibility may be limited by packing or stub-dominated code paths.")

	case (hasBenignHints || aiLooksBenign || likelyLowRiskBenign) && !likelyStrongMalware:
		analysis.TriageRecommendation.Verdict = "benign-leaning"
		analysis.TriageRecommendation.Priority = "low"
		if strings.TrimSpace(analysis.TriageRecommendation.NextStep) == "" {
			analysis.TriageRecommendation.NextStep = "Review the top functions to confirm the suspicious APIs are explained by normal application or system-tool behavior before treating the sample as malicious."
		}
		analysis.ExecutiveSummary = softenExecutiveSummary(analysis.ExecutiveSummary)
		addConfidenceNote(analysis, "The structured report remains low-risk overall, so suspicious APIs alone are not sufficient to conclude malicious intent.")

	case !likelyStrongMalware && strings.TrimSpace(analysis.TriageRecommendation.NextStep) == "":
		analysis.TriageRecommendation.NextStep = "Manually review the highest-ranked functions and confirm whether the suspicious APIs form a coherent malicious workflow or only reflect normal program behavior."
	}

	if len(analysis.SuspiciousFunctionPriorities) == 0 {
		analysis.SuspiciousFunctionPriorities = deriveFunctionPriorities(input)
	}

	if len(analysis.AnalystQuestions) == 0 {
		analysis.AnalystQuestions = deriveAnalystQuestions(input, analysis)
	}

	if len(analysis.ConfidenceNotes) == 0 && likelyLowRiskBenign {
		addConfidenceNote(analysis, "This sample is low-risk in the structured report and should be treated conservatively unless manual review reveals a stronger malicious chain.")
	}

	analysis.Normalize()
}

func softenExecutiveSummary(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "The sample shows some suspicious static signals, but the current evidence remains compatible with benign or routine application behavior."
	}

	replacements := map[string]string{
		"indicating potential for malicious behavior": "but the current evidence is not strong enough to conclude malicious intent",
		"indicating malicious behavior":               "but the current evidence is not strong enough to conclude malicious intent",
		"likely malicious":                            "not conclusively malicious",
	}

	out := s
	lower := strings.ToLower(out)
	for old, newVal := range replacements {
		if strings.Contains(lower, strings.ToLower(old)) {
			out = replaceCaseInsensitive(out, old, newVal)
		}
	}

	if !strings.Contains(strings.ToLower(out), "not strong enough to conclude malicious intent") &&
		!strings.Contains(strings.ToLower(out), "benign") {
		out += " The current evidence is not strong enough to conclude malicious intent."
	}

	return out
}

func deriveFunctionPriorities(input InputPayload) []SuspiciousFunctionPriority {
	items := getSlice(input.TopFunctions)
	out := make([]SuspiciousFunctionPriority, 0, len(items))

	for _, item := range items {
		m := getMap(item)
		name := stringifyAny(m["name"])
		if strings.TrimSpace(name) == "" {
			continue
		}

		why := stringifyAny(m["reason_summary"])
		if strings.TrimSpace(why) == "" {
			why = stringifyAny(m["primary_reason"])
		}
		if strings.TrimSpace(why) == "" {
			why = "High-ranking function with suspicious local signals."
		}

		reviewFocus := buildReviewFocus(m)

		out = append(out, SuspiciousFunctionPriority{
			Function:    name,
			Why:         why,
			ReviewFocus: reviewFocus,
		})

		if len(out) >= 4 {
			break
		}
	}

	return out
}

func deriveAnalystQuestions(input InputPayload, analysis *AIAnalysis) []string {
	out := []string{}

	verdict := strings.ToLower(strings.TrimSpace(analysis.TriageRecommendation.Verdict))
	if verdict == "likely-packed-needs-unpacking" {
		out = append(out, "Do the entrypoint and OEP candidates suggest a packed stub rather than the true behavioral core?")
	}

	if verdict == "benign-leaning" {
		out = append(out, "Can the suspicious APIs be fully explained by normal UI, file, or system-tool behavior?")
	} else {
		out = append(out, "Do the top-ranked functions form a coherent malicious workflow, or are the suspicious signals isolated?")
	}

	caps := getSlice(input.GlobalSignals["capabilities"])
	if len(caps) > 0 {
		out = append(out, "Which inferred capabilities are supported by multiple independent signals, and which remain borderline?")
	}

	out = append(out, "Would manual review of the top functions strengthen or weaken the current triage verdict?")
	return normalizeStringList(out)
}

func buildReviewFocus(m map[string]any) string {
	caps := toStringSlice(m["matched_capabilities"])
	apis := stringifyAny(m["local_api_hits"])

	switch {
	case len(caps) > 0 && strings.TrimSpace(apis) != "":
		return fmt.Sprintf("Validate whether the local API usage (%s) really supports the inferred capabilities: %s.", apis, strings.Join(caps, ", "))
	case len(caps) > 0:
		return fmt.Sprintf("Validate whether the local evidence really supports the inferred capabilities: %s.", strings.Join(caps, ", "))
	case strings.TrimSpace(apis) != "":
		return fmt.Sprintf("Inspect the local API mix and confirm whether it represents a real malicious behavior chain: %s.", apis)
	default:
		return "Inspect control flow, local API usage, and surrounding callers/callees to confirm why this function was ranked highly."
	}
}

func addConfidenceNote(a *AIAnalysis, note string) {
	note = strings.TrimSpace(note)
	if note == "" {
		return
	}
	a.ConfidenceNotes = append(a.ConfidenceNotes, note)
	a.ConfidenceNotes = normalizeStringList(a.ConfidenceNotes)
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func replaceCaseInsensitive(s, old, newVal string) string {
	lowerS := strings.ToLower(s)
	lowerOld := strings.ToLower(old)
	idx := strings.Index(lowerS, lowerOld)
	if idx < 0 {
		return s
	}
	return s[:idx] + newVal + s[idx+len(old):]
}

func normalizePriority(current string, fallback string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	switch current {
	case "low", "medium", "high":
		return current
	default:
		return fallback
	}
}
