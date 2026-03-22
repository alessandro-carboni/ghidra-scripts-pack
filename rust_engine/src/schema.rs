use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Report {
    #[serde(default)]
    pub analysis_metadata: Value,

    #[serde(default)]
    pub rule_contract: Value,

    #[serde(default)]
    pub sample: SampleInfo,

    #[serde(default)]
    pub summary: Summary,

    #[serde(default)]
    pub global_analysis: GlobalAnalysis,

    #[serde(default)]
    pub function_analysis: FunctionAnalysis,

    #[serde(default)]
    pub behavior_analysis: Value,

    #[serde(default)]
    pub binary_structure: BinaryStructure,

    #[serde(default)]
    pub analyst_output: Value,

    #[serde(default)]
    pub rust_enrichment: Option<RustEnrichment>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SampleInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub format: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Summary {
    #[serde(default)]
    pub sample_name: String,
    #[serde(default)]
    pub packed_warning: Option<String>,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub overall_score: i32,
    #[serde(default)]
    pub raw_score: i32,
    #[serde(default)]
    pub score_adjustment_total: i32,
    #[serde(default)]
    pub adjustment_count: i32,
    #[serde(default)]
    pub external_symbol_count: i32,
    #[serde(default)]
    pub suspicious_api_count: i32,
    #[serde(default)]
    pub capability_count: i32,
    #[serde(default)]
    pub function_count: i32,
    #[serde(default)]
    pub string_count: i32,
    #[serde(default)]
    pub interesting_string_count: i32,
    #[serde(default)]
    pub top_function_count: i32,
    #[serde(default)]
    pub packing_likelihood_score: i32,
    #[serde(default)]
    pub packer_confidence: String,
    #[serde(default)]
    pub packer_family_hint: String,
    #[serde(default)]
    pub top_indicators: Vec<String>,
    #[serde(default)]
    pub contract_version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GlobalAnalysis {
    #[serde(default)]
    pub external_symbols: Vec<String>,
    #[serde(default)]
    pub suspicious_apis: Vec<SuspiciousApi>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub interesting_strings: Vec<InterestingString>,
    #[serde(default)]
    pub benign_contexts: Vec<BenignContext>,
    #[serde(default)]
    pub score_adjustments: Vec<ScoreAdjustment>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SuspiciousApi {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub weight: i32,
    #[serde(default)]
    pub variants: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Capability {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub matched_apis: Vec<String>,
    #[serde(default)]
    pub match_count: i32,
    #[serde(default)]
    pub min_matches: i32,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct InterestingString {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub benign_hint: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BenignContext {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub score_adjustment: i32,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreAdjustment {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub delta: i32,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FunctionAnalysis {
    #[serde(default)]
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub top_functions: Vec<TopFunction>,
    #[serde(default)]
    pub function_role_summary: Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FunctionInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub thunk: bool,
    #[serde(default)]
    pub internal_calls: Vec<String>,
    #[serde(default)]
    pub external_calls: Vec<String>,
    #[serde(default)]
    pub incoming_calls: i32,
    #[serde(default)]
    pub referenced_strings: Vec<ReferencedString>,
    #[serde(default)]
    pub matched_capabilities: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub local_api_hits: Vec<String>,
    #[serde(default)]
    pub score_breakdown: Vec<LocalScoreBreakdown>,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub structure_role: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ReferencedString {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub benign_hint: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LocalScoreBreakdown {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub delta: i32,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TopFunction {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub structure_role: String,
    #[serde(default)]
    pub incoming_calls: i32,
    #[serde(default)]
    pub external_call_count: i32,
    #[serde(default)]
    pub internal_call_count: i32,
    #[serde(default)]
    pub referenced_string_count: i32,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub matched_capabilities: Vec<String>,
    #[serde(default)]
    pub local_api_hits: Vec<String>,
    #[serde(default)]
    pub primary_reason: String,
    #[serde(default)]
    pub reason_summary: String,
    #[serde(default)]
    pub score_driver_summary: String,
    #[serde(default)]
    pub evidence: TopFunctionEvidence,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TopFunctionEvidence {
    #[serde(default)]
    pub local_api_hits: Vec<String>,
    #[serde(default)]
    pub matched_capabilities: Vec<String>,
    #[serde(default)]
    pub referenced_string_samples: Vec<String>,
    #[serde(default)]
    pub top_score_drivers: Vec<LocalScoreBreakdown>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BinaryStructure {
    #[serde(default)]
    pub packer_analysis: PackerAnalysis,
    #[serde(default)]
    pub entrypoint_info: EntrypointInfo,
    #[serde(default)]
    pub entrypoint_window: Vec<EntrypointInstruction>,
    #[serde(default)]
    pub oep_candidates: Vec<OepCandidate>,
    #[serde(default)]
    pub section_info: Vec<SectionInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PackerAnalysis {
    #[serde(default)]
    pub packed_likelihood_score: i32,
    #[serde(default)]
    pub likely_packed: bool,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub packer_family_hint: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub indicators: Vec<PackerIndicator>,
    #[serde(default)]
    pub suspicious_section_count: i32,
    #[serde(default)]
    pub high_entropy_section_count: i32,
    #[serde(default)]
    pub high_entropy_executable_count: i32,
    #[serde(default)]
    pub entrypoint_section_entropy: Option<f64>,
    #[serde(default)]
    pub oep_candidate_summary: Option<OepCandidate>,
    #[serde(default)]
    pub analysis_notes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PackerIndicator {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub matched_apis: Vec<String>,
    #[serde(default)]
    pub sections: Vec<String>,
    #[serde(default)]
    pub count: i32,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub candidate: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EntrypointInfo {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub section_is_executable: bool,
    #[serde(default)]
    pub section_is_writable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EntrypointInstruction {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub mnemonic: String,
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OepCandidate {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub instruction: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub transition_kind: String,
    #[serde(default)]
    pub late_transfer: bool,
    #[serde(default)]
    pub popad_nearby: bool,
    #[serde(default)]
    pub pushad_nearby: bool,
    #[serde(default)]
    pub target_function: Option<String>,
    #[serde(default)]
    pub memory_backed: bool,
    #[serde(default)]
    pub target_is_executable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SectionInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub end: String,
    #[serde(default)]
    pub size: i32,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub execute: bool,
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub entropy_class: String,
    #[serde(default)]
    pub entropy_sampled_bytes: i32,
    #[serde(default)]
    pub suspicious: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RustEnrichment {
    #[serde(default)]
    pub engine_metadata: EngineMetadata,
    #[serde(default)]
    pub rules_metadata: RulesMetadata,
    #[serde(default)]
    pub schema_validation: SchemaValidation,
    #[serde(default)]
    pub score_calibration: ScoreCalibration,
    #[serde(default)]
    pub capability_confidence: Vec<CapabilityConfidence>,
    #[serde(default)]
    pub derived_capabilities: Vec<DerivedCapability>,
    #[serde(default)]
    pub confidence_notes: Vec<String>,
    #[serde(default)]
    pub score_bands: ScoreBands,
    #[serde(default)]
    pub decision_summary: DecisionSummary,
    #[serde(default)]
    pub risk_annotations: Vec<String>,
    #[serde(default)]
    pub malware_risk: RiskScore,
    #[serde(default)]
    pub packing_risk: RiskScore,
    #[serde(default)]
    pub risk_split_summary: RiskSplitSummary,
    #[serde(default)]
    pub score_drivers: Vec<ScoreDriver>,
    #[serde(default)]
    pub manual_review_reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EngineMetadata {
    #[serde(default)]
    pub engine_name: String,
    #[serde(default)]
    pub engine_version: String,
    #[serde(default)]
    pub input_contract_version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RulesMetadata {
    #[serde(default)]
    pub rules_dir: String,
    #[serde(default)]
    pub score_rules_loaded: bool,
    #[serde(default)]
    pub derived_rules_loaded: bool,
    #[serde(default)]
    pub using_defaults: bool,
    #[serde(default)]
    pub load_errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SchemaValidation {
    #[serde(default)]
    pub valid_minimum_contract: bool,
    #[serde(default)]
    pub checked_fields: Vec<String>,
    #[serde(default)]
    pub missing_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreCalibration {
    #[serde(default)]
    pub original_score: i32,
    #[serde(default)]
    pub calibrated_score: i32,
    #[serde(default)]
    pub delta: i32,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CapabilityConfidence {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub base_confidence: String,
    #[serde(default)]
    pub calibrated_confidence: String,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DerivedCapability {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreBands {
    #[serde(default)]
    pub original_band: String,
    #[serde(default)]
    pub calibrated_band: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DecisionSummary {
    #[serde(default)]
    pub malicious_signal_strength: String,
    #[serde(default)]
    pub analysis_confidence: String,
    #[serde(default)]
    pub needs_manual_review: bool,
    #[serde(default)]
    pub primary_assessment: String,
    #[serde(default)]
    pub manual_review_priority: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RiskScore {
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RiskSplitSummary {
    #[serde(default)]
    pub dominant_risk: String,
    #[serde(default)]
    pub interpretation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreDriver {
    #[serde(default)]
    pub driver: String,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub weight: i32,
    #[serde(default)]
    pub rationale: String,
}