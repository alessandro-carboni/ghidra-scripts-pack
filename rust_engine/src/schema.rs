use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub top_indicators: Vec<String>,
    #[serde(default)]
    pub contract_version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GlobalAnalysis {
    #[serde(default)]
    pub suspicious_apis: Vec<SuspiciousApi>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub interesting_strings: Vec<InterestingString>,
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
pub struct FunctionAnalysis {
    #[serde(default)]
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub top_functions: Vec<TopFunction>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FunctionInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub matched_capabilities: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub local_api_hits: Vec<String>,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub structure_role: String,
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
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BinaryStructure {
    #[serde(default)]
    pub packer_analysis: PackerAnalysis,
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
    pub packer_family_hint: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RustEnrichment {
    pub engine_metadata: EngineMetadata,
    pub schema_validation: SchemaValidation,
    pub score_calibration: ScoreCalibration,
    pub capability_confidence: Vec<CapabilityConfidence>,
    pub derived_capabilities: Vec<DerivedCapability>,
    pub confidence_notes: Vec<String>,
    pub score_bands: ScoreBands,
    pub decision_summary: DecisionSummary,
    pub risk_annotations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EngineMetadata {
    pub engine_name: String,
    pub engine_version: String,
    pub input_contract_version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SchemaValidation {
    pub valid_minimum_contract: bool,
    pub checked_fields: Vec<String>,
    pub missing_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreCalibration {
    pub original_score: i32,
    pub calibrated_score: i32,
    pub delta: i32,
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CapabilityConfidence {
    pub name: String,
    pub base_confidence: String,
    pub calibrated_confidence: String,
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DerivedCapability {
    pub name: String,
    pub confidence: String,
    pub rationale: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreBands {
    pub original_band: String,
    pub calibrated_band: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DecisionSummary {
    pub malicious_signal_strength: String,
    pub analysis_confidence: String,
    pub needs_manual_review: bool,
}