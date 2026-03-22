package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

type InputPayload struct {
	SourceReportPath string           `json:"source_report_path"`
	SourceReportKind string           `json:"source_report_kind"`
	Sample           map[string]any   `json:"sample"`
	Summary          map[string]any   `json:"summary"`
	GlobalSignals    map[string]any   `json:"global_signals"`
	TopFunctions     []map[string]any `json:"top_functions"`
	Behavior         map[string]any   `json:"behavior"`
	Packer           map[string]any   `json:"packer"`
	Rust             map[string]any   `json:"rust"`
	AnalystOutput    map[string]any   `json:"analyst_output"`
}

type AIAnalysis struct {
	ExecutiveSummary             string                       `json:"executive_summary"`
	TechnicalSummary             string                       `json:"technical_summary"`
	TriageRecommendation         TriageRecommendation         `json:"triage_recommendation"`
	SuspiciousFunctionPriorities []SuspiciousFunctionPriority `json:"suspicious_function_priorities"`
	AnalystQuestions             []string                     `json:"analyst_questions"`
	ConfidenceNotes              []string                     `json:"confidence_notes"`
}

type TriageRecommendation struct {
	Verdict  string `json:"verdict"`
	Priority string `json:"priority"`
	NextStep string `json:"next_step"`
}

type SuspiciousFunctionPriority struct {
	Function    string `json:"function"`
	Why         string `json:"why"`
	ReviewFocus string `json:"review_focus"`
}

type AIProviderInfo struct {
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`
	Timeout int    `json:"timeout_seconds"`
}

type AIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type AIOnlyReport struct {
	ReportType       string         `json:"report_type"`
	GeneratedAt      string         `json:"generated_at"`
	SourceReportPath string         `json:"source_report_path"`
	AIProvider       AIProviderInfo `json:"ai_provider"`
	AIUsage          AIUsage        `json:"ai_usage"`
	AIAnalysis       AIAnalysis     `json:"ai_analysis"`
}

func (a *AIAnalysis) Normalize() {
	a.ExecutiveSummary = strings.TrimSpace(a.ExecutiveSummary)
	a.TechnicalSummary = strings.TrimSpace(a.TechnicalSummary)

	if a.AnalystQuestions == nil {
		a.AnalystQuestions = []string{}
	}
	if a.ConfidenceNotes == nil {
		a.ConfidenceNotes = []string{}
	}
	if a.SuspiciousFunctionPriorities == nil {
		a.SuspiciousFunctionPriorities = []SuspiciousFunctionPriority{}
	}

	a.AnalystQuestions = normalizeStringList(a.AnalystQuestions)
	a.ConfidenceNotes = normalizeStringList(a.ConfidenceNotes)

	if strings.TrimSpace(a.TriageRecommendation.Verdict) == "" {
		a.TriageRecommendation.Verdict = "suspicious"
	}
	if strings.TrimSpace(a.TriageRecommendation.Priority) == "" {
		a.TriageRecommendation.Priority = "medium"
	}
	a.TriageRecommendation.NextStep = strings.TrimSpace(a.TriageRecommendation.NextStep)

	for i := range a.SuspiciousFunctionPriorities {
		a.SuspiciousFunctionPriorities[i].Function = strings.TrimSpace(a.SuspiciousFunctionPriorities[i].Function)
		a.SuspiciousFunctionPriorities[i].Why = strings.TrimSpace(a.SuspiciousFunctionPriorities[i].Why)
		a.SuspiciousFunctionPriorities[i].ReviewFocus = strings.TrimSpace(a.SuspiciousFunctionPriorities[i].ReviewFocus)
	}
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}

	for _, item := range items {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}

func stringifyAny(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			s := stringifyAny(item)
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "; ")
	case map[string]any:
		if len(x) == 0 {
			return ""
		}

		preferredKeys := []string{
			"summary",
			"overall_summary",
			"description",
			"text",
			"value",
			"risk_level",
			"overall_score",
		}

		parts := []string{}
		used := map[string]struct{}{}

		for _, key := range preferredKeys {
			if val, ok := x[key]; ok {
				s := stringifyAny(val)
				if s != "" {
					parts = append(parts, fmt.Sprintf("%s: %s", key, s))
					used[key] = struct{}{}
				}
			}
		}

		for key, val := range x {
			if _, ok := used[key]; ok {
				continue
			}
			s := stringifyAny(val)
			if s != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", key, s))
			}
		}

		return strings.Join(parts, " | ")
	default:
		data, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprintf("%v", x)
		}
		return strings.TrimSpace(string(data))
	}
}

func toStringSlice(v any) []string {
	switch x := v.(type) {
	case nil:
		return []string{}
	case []string:
		return normalizeStringList(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s := stringifyAny(item)
			if s != "" {
				out = append(out, s)
			}
		}
		return normalizeStringList(out)
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return []string{}
		}
		return []string{s}
	default:
		s := stringifyAny(x)
		if s == "" {
			return []string{}
		}
		return []string{s}
	}
}
