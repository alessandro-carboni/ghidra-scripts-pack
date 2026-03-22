package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"ghidra-malware-triage/internal/config"
)

type Client struct {
	baseURL    string
	model      string
	apiKey     string
	httpClient *http.Client
	timeoutSec int
}

type GenerationResult struct {
	Report      *AIOnlyReport
	RawResponse string
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func NewClient(cfg config.Config) (*Client, error) {
	if err := cfg.ValidateForAI(); err != nil {
		return nil, err
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.AIBaseURL), "/")

	return &Client{
		baseURL:    baseURL,
		model:      strings.TrimSpace(cfg.AIModel),
		apiKey:     cfg.AIAPIKey,
		timeoutSec: cfg.AITimeoutSeconds,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.AITimeoutSeconds) * time.Second,
		},
	}, nil
}

func GenerateAIOnlyReport(cfg config.Config, input InputPayload) (*GenerationResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}

	systemMsg, userMsg, err := BuildMessages(input)
	if err != nil {
		return nil, err
	}

	content, usage, err := client.complete(systemMsg, userMsg)
	if err != nil {
		return nil, err
	}

	analysis, err := parseAIAnalysis(content)
	if err != nil {
		return &GenerationResult{
			RawResponse: content,
		}, fmt.Errorf("parse AI JSON response: %w", err)
	}
	ApplyGuardrails(analysis, input)
	analysis.Normalize()

	rep := &AIOnlyReport{
		ReportType:       "ai_only",
		GeneratedAt:      time.Now().Format(time.RFC3339),
		SourceReportPath: input.SourceReportPath,
		AIProvider: AIProviderInfo{
			BaseURL: client.baseURL,
			Model:   client.model,
			Timeout: client.timeoutSec,
		},
		AIUsage:    usage,
		AIAnalysis: *analysis,
	}

	return &GenerationResult{
		Report:      rep,
		RawResponse: content,
	}, nil
}

func (c *Client) complete(systemMsg, userMsg string) (string, AIUsage, error) {
	reqBody := chatCompletionRequest{
		Model: c.model,
		Messages: []chatMessage{
			{
				Role:    "system",
				Content: systemMsg,
			},
			{
				Role:    "user",
				Content: userMsg,
			},
		},
		Temperature: 0.0,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", AIUsage{}, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", AIUsage{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", AIUsage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", AIUsage{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := string(body)
		if strings.Contains(strings.ToLower(msg), "memory layout cannot be allocated") {
			return "", AIUsage{}, fmt.Errorf("AI request failed: local model ran out of allocatable memory; try a smaller AI input or a lighter model")
		}
		return "", AIUsage{}, fmt.Errorf("AI request failed: status=%d body=%s", resp.StatusCode, msg)
	}

	var parsed chatCompletionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", AIUsage{}, fmt.Errorf("decode AI response: %w", err)
	}

	if len(parsed.Choices) == 0 {
		return "", AIUsage{}, fmt.Errorf("AI response has no choices")
	}

	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return "", AIUsage{}, fmt.Errorf("AI response content is empty")
	}

	return content, AIUsage{
		PromptTokens:     parsed.Usage.PromptTokens,
		CompletionTokens: parsed.Usage.CompletionTokens,
		TotalTokens:      parsed.Usage.TotalTokens,
	}, nil
}

func parseAIAnalysis(content string) (*AIAnalysis, error) {
	candidates := buildJSONCandidates(content)

	var lastErr error
	for _, candidate := range candidates {
		if out, err := parseAIAnalysisCandidate(candidate); err == nil {
			return out, nil
		} else {
			lastErr = err
		}
	}

	return nil, fmt.Errorf("%w | raw_response_preview=%q", lastErr, truncateForError(content, 400))
}

func parseAIAnalysisCandidate(candidate string) (*AIAnalysis, error) {
	var direct AIAnalysis
	if err := json.Unmarshal([]byte(candidate), &direct); err == nil {
		direct.Normalize()
		return &direct, nil
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(candidate), &raw); err != nil {
		return nil, err
	}

	out := &AIAnalysis{
		ExecutiveSummary: stringifyAny(raw["executive_summary"]),
		TechnicalSummary: stringifyAny(raw["technical_summary"]),
		AnalystQuestions: toStringSlice(raw["analyst_questions"]),
		ConfidenceNotes:  toStringSlice(raw["confidence_notes"]),
	}

	triage := getMap(raw["triage_recommendation"])
	out.TriageRecommendation = TriageRecommendation{
		Verdict:  stringifyAny(triage["verdict"]),
		Priority: stringifyAny(triage["priority"]),
		NextStep: stringifyAny(triage["next_step"]),
	}

	sfpItems := getSlice(raw["suspicious_function_priorities"])
	out.SuspiciousFunctionPriorities = make([]SuspiciousFunctionPriority, 0, len(sfpItems))
	for _, item := range sfpItems {
		m := getMap(item)
		if len(m) == 0 {
			s := stringifyAny(item)
			if strings.TrimSpace(s) == "" {
				continue
			}
			out.SuspiciousFunctionPriorities = append(out.SuspiciousFunctionPriorities, SuspiciousFunctionPriority{
				Function:    s,
				Why:         "",
				ReviewFocus: "",
			})
			continue
		}

		out.SuspiciousFunctionPriorities = append(out.SuspiciousFunctionPriorities, SuspiciousFunctionPriority{
			Function:    stringifyAny(m["function"]),
			Why:         stringifyAny(m["why"]),
			ReviewFocus: stringifyAny(m["review_focus"]),
		})
	}

	out.Normalize()
	return out, nil
}

func buildJSONCandidates(content string) []string {
	raw := strings.TrimSpace(content)

	candidates := []string{}

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, existing := range candidates {
			if existing == s {
				return
			}
		}
		candidates = append(candidates, s)
	}

	add(raw)

	clean := raw
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```JSON")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	clean = strings.TrimSpace(clean)
	add(clean)

	if extracted := extractFirstJSONObject(clean); extracted != "" {
		add(extracted)
	}
	if extracted := extractFirstJSONObject(raw); extracted != "" {
		add(extracted)
	}

	if fixed := stripLeadingNoiseBeforeJSONObject(clean); fixed != "" {
		add(fixed)
	}
	if fixed := stripLeadingNoiseBeforeJSONObject(raw); fixed != "" {
		add(fixed)
	}

	return candidates
}

func stripLeadingNoiseBeforeJSONObject(s string) string {
	s = strings.TrimSpace(s)
	idx := strings.Index(s, "{")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(s[idx:])
}

func truncateForError(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func extractFirstJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}

	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(s); i++ {
		ch := s[i]

		if escaped {
			escaped = false
			continue
		}

		if ch == '\\' && inString {
			escaped = true
			continue
		}

		if ch == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return strings.TrimSpace(s[start : i+1])
			}
		}
	}

	return ""
}

func SaveRawAIResponse(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
