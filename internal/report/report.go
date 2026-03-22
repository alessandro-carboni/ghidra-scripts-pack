package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Report struct {
	AnalysisMetadata map[string]any   `json:"analysis_metadata"`
	RuleContract     map[string]any   `json:"rule_contract"`
	Sample           SampleInfo       `json:"sample"`
	Summary          Summary          `json:"summary"`
	GlobalAnalysis   GlobalAnalysis   `json:"global_analysis"`
	FunctionAnalysis FunctionAnalysis `json:"function_analysis"`
	BehaviorAnalysis map[string]any   `json:"behavior_analysis"`
	BinaryStructure  BinaryStructure  `json:"binary_structure"`
	AnalystOutput    map[string]any   `json:"analyst_output"`
	RustEnrichment   map[string]any   `json:"rust_enrichment"`
}

type SampleInfo struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Format string `json:"format"`
}

type Summary struct {
	SampleName             string   `json:"sample_name"`
	PackedWarning          any      `json:"packed_warning"`
	RiskLevel              string   `json:"risk_level"`
	OverallScore           int      `json:"overall_score"`
	RawScore               int      `json:"raw_score"`
	ScoreAdjustmentTotal   int      `json:"score_adjustment_total"`
	AdjustmentCount        int      `json:"adjustment_count"`
	ExternalSymbolCount    int      `json:"external_symbol_count"`
	SuspiciousAPICount     int      `json:"suspicious_api_count"`
	CapabilityCount        int      `json:"capability_count"`
	FunctionCount          int      `json:"function_count"`
	StringCount            int      `json:"string_count"`
	InterestingStringCount int      `json:"interesting_string_count"`
	TopFunctionCount       int      `json:"top_function_count"`
	PackingLikelihoodScore int      `json:"packing_likelihood_score"`
	PackerConfidence       string   `json:"packer_confidence"`
	PackerFamilyHint       string   `json:"packer_family_hint"`
	TopIndicators          []string `json:"top_indicators"`
	ContractVersion        string   `json:"contract_version"`
}

type GlobalAnalysis struct {
	ExternalSymbols    []string            `json:"external_symbols"`
	SuspiciousAPIs     []SuspiciousAPI     `json:"suspicious_apis"`
	Capabilities       []Capability        `json:"capabilities"`
	InterestingStrings []InterestingString `json:"interesting_strings"`
	Strings            []StringItem        `json:"strings"`
	BenignContexts     []map[string]any    `json:"benign_contexts"`
	ScoreAdjustments   []map[string]any    `json:"score_adjustments"`
}

type SuspiciousAPI struct {
	Name     string   `json:"name"`
	Weight   int      `json:"weight"`
	Variants []string `json:"variants"`
}

type Capability struct {
	Name        string   `json:"name"`
	MatchedAPIs []string `json:"matched_apis"`
	MatchCount  int      `json:"match_count"`
	MinMatches  int      `json:"min_matches"`
	Confidence  string   `json:"confidence"`
	Score       int      `json:"score"`
	Source      string   `json:"source"`
}

type InterestingString struct {
	Address    string   `json:"address"`
	Value      string   `json:"value"`
	Tags       []string `json:"tags"`
	Score      int      `json:"score"`
	BenignHint bool     `json:"benign_hint"`
}

type StringItem struct {
	Address string `json:"address"`
	Value   string `json:"value"`
}

type FunctionAnalysis struct {
	Functions           []FunctionInfo    `json:"functions"`
	TopFunctions        []TopFunctionInfo `json:"top_functions"`
	FunctionRoleSummary map[string]any    `json:"function_role_summary"`
}

type FunctionInfo struct {
	Name                string           `json:"name"`
	Entry               string           `json:"entry"`
	External            bool             `json:"external"`
	Thunk               bool             `json:"thunk"`
	InternalCalls       []string         `json:"internal_calls"`
	ExternalCalls       []string         `json:"external_calls"`
	IncomingCalls       int              `json:"incoming_calls"`
	ReferencedStrings   []StringRef      `json:"referenced_strings"`
	MatchedCapabilities []string         `json:"matched_capabilities"`
	Roles               []string         `json:"roles"`
	StructureRole       string           `json:"structure_role"`
	Tags                []string         `json:"tags"`
	LocalAPIHits        []string         `json:"local_api_hits"`
	Score               int              `json:"score"`
	RiskLevel           string           `json:"risk_level"`
	ScoreBreakdown      []map[string]any `json:"score_breakdown"`
}

type StringRef struct {
	Address    string   `json:"address"`
	Value      string   `json:"value"`
	Score      int      `json:"score"`
	Tags       []string `json:"tags"`
	BenignHint bool     `json:"benign_hint"`
}

type TopFunctionInfo struct {
	Name                  string              `json:"name"`
	Entry                 string              `json:"entry"`
	Score                 int                 `json:"score"`
	RiskLevel             string              `json:"risk_level"`
	Roles                 []string            `json:"roles"`
	StructureRole         string              `json:"structure_role"`
	IncomingCalls         int                 `json:"incoming_calls"`
	ExternalCallCount     int                 `json:"external_call_count"`
	InternalCallCount     int                 `json:"internal_call_count"`
	ReferencedStringCount int                 `json:"referenced_string_count"`
	Tags                  []string            `json:"tags"`
	MatchedCapabilities   []string            `json:"matched_capabilities"`
	LocalAPIHits          []string            `json:"local_api_hits"`
	PrimaryReason         string              `json:"primary_reason"`
	ReasonSummary         string              `json:"reason_summary"`
	ScoreDriverSummary    string              `json:"score_driver_summary"`
	Evidence              TopFunctionEvidence `json:"evidence"`
}

type TopFunctionEvidence struct {
	LocalAPIHits            []string         `json:"local_api_hits"`
	MatchedCapabilities     []string         `json:"matched_capabilities"`
	ReferencedStringSamples []string         `json:"referenced_string_samples"`
	TopScoreDrivers         []map[string]any `json:"top_score_drivers"`
}

type BinaryStructure struct {
	PackerAnalysis   map[string]any   `json:"packer_analysis"`
	EntrypointInfo   map[string]any   `json:"entrypoint_info"`
	EntrypointWindow []map[string]any `json:"entrypoint_window"`
	OEPCandidates    []map[string]any `json:"oep_candidates"`
	SectionInfo      []map[string]any `json:"section_info"`
}

func Load(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

func MustPretty(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":"%v"}`, err)
	}
	return string(data)
}

func ListReportFiles(reportsDir string) ([]string, error) {
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) == ".json" {
			files = append(files, entry.Name())
		}
	}

	sort.Strings(files)
	return files, nil
}

func FindFunction(r *Report, name string) *FunctionInfo {
	for i := range r.FunctionAnalysis.Functions {
		if r.FunctionAnalysis.Functions[i].Name == name {
			return &r.FunctionAnalysis.Functions[i]
		}
	}
	return nil
}
