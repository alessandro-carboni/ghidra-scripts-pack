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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_graph: Option<Value>,

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seeded_fingerprinting: Option<SeededFingerprintingResult>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeededFingerprintingStatus {
    #[default]
    Disabled,
    NotImplemented,
    Failed,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SeededFingerprintingResult {
    #[serde(default)]
    pub status: SeededFingerprintingStatus,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[allow(dead_code)]
pub const SEED_MODEL_VERSION: &str = "0.2.0";

#[allow(dead_code)]
pub fn build_seed_id(anchor_function_id: &str, trigger_id: &str) -> Result<String, String> {
    let anchor = anchor_function_id.trim();
    let trigger = trigger_id.trim();

    if !anchor.starts_with("fn:") || anchor.len() <= "fn:".len() {
        return Err(
            "seed anchor_function_id must be a stable FUNCTION id starting with 'fn:'".to_string(),
        );
    }

    if trigger.is_empty() {
        return Err("seed trigger_id cannot be empty".to_string());
    }

    Ok(format!("seed:{anchor}:{trigger}"))
}

#[allow(dead_code)]
pub fn build_consolidated_seed_id(anchor_function_id: &str) -> Result<String, String> {
    let anchor = anchor_function_id.trim();

    if !anchor.starts_with("fn:") || anchor.len() <= "fn:".len() {
        return Err(
            "consolidated seed anchor_function_id must be a stable FUNCTION id starting with 'fn:'"
                .to_string(),
        );
    }

    Ok(format!("seed:{anchor}"))
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeedEvidence {
    pub kind: String,
    pub value: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_type: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsite: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeedCandidate {
    pub seed_id: String,

    pub anchor_function_id: String,

    pub trigger_id: String,

    #[serde(default)]
    pub evidence: Vec<SeedEvidence>,

    pub reason: String,
}

#[allow(dead_code)]
impl SeedCandidate {
    pub fn validate(&self) -> Result<(), String> {
        let expected_seed_id = build_seed_id(&self.anchor_function_id, &self.trigger_id)?;

        if self.seed_id != expected_seed_id {
            return Err(format!(
                "seed_id does not match \
                 anchor_function_id + trigger_id: \
                 expected {expected_seed_id}"
            ));
        }

        if self.evidence.is_empty() {
            return Err("seed must contain at least one evidence item".to_string());
        }

        if self.reason.trim().is_empty() {
            return Err("seed reason cannot be empty".to_string());
        }

        for evidence in &self.evidence {
            if evidence.kind.trim().is_empty() {
                return Err("seed evidence kind cannot be empty".to_string());
            }

            if evidence.value.trim().is_empty() {
                return Err("seed evidence value cannot be empty".to_string());
            }

            if let Some(value) = &evidence.node_id {
                if value.trim().is_empty() {
                    return Err("seed evidence node_id cannot be \
                         empty when present"
                        .to_string());
                }
            }

            if let Some(value) = &evidence.edge_type {
                if value.trim().is_empty() {
                    return Err("seed evidence edge_type cannot be \
                         empty when present"
                        .to_string());
                }
            }

            if let Some(value) = &evidence.callsite {
                if value.trim().is_empty() {
                    return Err("seed evidence callsite cannot be \
                         empty when present"
                        .to_string());
                }
            }
        }

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsolidatedSeed {
    pub seed_id: String,

    pub anchor_function_id: String,

    #[serde(default)]
    pub trigger_ids: Vec<String>,

    #[serde(default)]
    pub source_candidate_ids: Vec<String>,

    #[serde(default)]
    pub evidence: Vec<SeedEvidence>,

    #[serde(default)]
    pub reasons: Vec<String>,
}

#[allow(dead_code)]
impl ConsolidatedSeed {
    pub fn validate(&self) -> Result<(), String> {
        let expected_seed_id = build_consolidated_seed_id(&self.anchor_function_id)?;

        if self.seed_id != expected_seed_id {
            return Err(format!(
                "consolidated seed_id does not match \
                 anchor_function_id: expected \
                 {expected_seed_id}"
            ));
        }

        if self.trigger_ids.is_empty() {
            return Err("consolidated seed must contain \
                 at least one trigger_id"
                .to_string());
        }

        if self.source_candidate_ids.is_empty() {
            return Err("consolidated seed must contain \
                 at least one source_candidate_id"
                .to_string());
        }

        if self.evidence.is_empty() {
            return Err("consolidated seed must contain \
                 at least one evidence item"
                .to_string());
        }

        if self.reasons.is_empty() {
            return Err("consolidated seed must contain \
                 at least one reason"
                .to_string());
        }

        validate_sorted_unique_nonempty(&self.trigger_ids, "trigger_ids")?;

        validate_sorted_unique_nonempty(&self.source_candidate_ids, "source_candidate_ids")?;

        validate_sorted_unique_nonempty(&self.reasons, "reasons")?;

        let expected_source_candidate_ids: Vec<String> = self
            .trigger_ids
            .iter()
            .map(|trigger_id| build_seed_id(&self.anchor_function_id, trigger_id))
            .collect::<Result<Vec<_>, _>>()?;

        if self.source_candidate_ids != expected_source_candidate_ids {
            return Err("consolidated seed \
                 source_candidate_ids must correspond \
                 exactly to anchor + trigger_ids"
                .to_string());
        }

        for evidence in &self.evidence {
            if evidence.kind.trim().is_empty() {
                return Err("consolidated seed evidence kind \
                     cannot be empty"
                    .to_string());
            }

            if evidence.value.trim().is_empty() {
                return Err("consolidated seed evidence value \
                     cannot be empty"
                    .to_string());
            }

            for (field_name, value) in [
                ("node_id", evidence.node_id.as_deref()),
                ("edge_type", evidence.edge_type.as_deref()),
                ("callsite", evidence.callsite.as_deref()),
            ] {
                if value.is_some_and(|text| text.trim().is_empty()) {
                    return Err(format!(
                        "consolidated seed evidence \
                         {field_name} cannot be empty \
                         when present"
                    ));
                }
            }
        }

        Ok(())
    }
}

fn validate_sorted_unique_nonempty(values: &[String], field_name: &str) -> Result<(), String> {
    let mut previous: Option<&str> = None;

    for value in values {
        let value = value.trim();

        if value.is_empty() {
            return Err(format!(
                "consolidated seed {field_name} \
                 cannot contain empty values"
            ));
        }

        if let Some(previous_value) = previous {
            if previous_value >= value {
                return Err(format!(
                    "consolidated seed {field_name} \
                     must be sorted and unique"
                ));
            }
        }

        previous = Some(value);
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_fingerprinting_status_disabled_serializes_as_snake_case() {
        let serialized = serde_json::to_string(&SeededFingerprintingStatus::Disabled)
            .expect("disabled status should serialize");

        assert_eq!(serialized, "\"disabled\"");
    }

    #[test]
    fn seeded_fingerprinting_status_not_implemented_serializes_as_snake_case() {
        let serialized = serde_json::to_string(&SeededFingerprintingStatus::NotImplemented)
            .expect("not implemented status should serialize");

        assert_eq!(serialized, "\"not_implemented\"");
    }

    #[test]
    fn seeded_fingerprinting_status_failed_serializes_as_snake_case() {
        let serialized = serde_json::to_string(&SeededFingerprintingStatus::Failed)
            .expect("failed status should serialize");

        assert_eq!(serialized, "\"failed\"");
    }

    #[test]
    fn seeded_fingerprinting_status_deserializes_not_implemented() {
        let status: SeededFingerprintingStatus = serde_json::from_str("\"not_implemented\"")
            .expect("not_implemented should deserialize");

        assert!(matches!(status, SeededFingerprintingStatus::NotImplemented));
    }

    #[test]
    fn seeded_fingerprinting_status_rejects_unknown_value() {
        let result = serde_json::from_str::<SeededFingerprintingStatus>("\"running\"");

        assert!(result.is_err());
    }

    #[test]
    fn seeded_fingerprinting_result_round_trip_preserves_fields() {
        let original = SeededFingerprintingResult {
            status: SeededFingerprintingStatus::NotImplemented,
            schema_version: Some("0.1.0".to_string()),
            message: Some(
                "Seeded fingerprinting is enabled but not implemented in this milestone."
                    .to_string(),
            ),
        };

        let serialized = serde_json::to_string(&original)
            .expect("seeded fingerprinting result should serialize");

        let deserialized: SeededFingerprintingResult = serde_json::from_str(&serialized)
            .expect("seeded fingerprinting result should deserialize");

        assert!(matches!(
            deserialized.status,
            SeededFingerprintingStatus::NotImplemented
        ));
        assert_eq!(deserialized.schema_version, original.schema_version);
        assert_eq!(deserialized.message, original.message);
    }

    #[test]
    fn seed_id_is_deterministic() {
        let first = build_seed_id("fn:140001000", "api.virtualalloc")
            .expect("valid seed id should be built");

        let second = build_seed_id("fn:140001000", "api.virtualalloc")
            .expect("valid seed id should be built");

        assert_eq!(first, "seed:fn:140001000:api.virtualalloc");

        assert_eq!(first, second);
    }

    #[test]
    fn seed_candidate_round_trip_preserves_observed_evidence() {
        let candidate = SeedCandidate {
            seed_id: "seed:fn:140001000:api.virtualalloc".to_string(),

            anchor_function_id: "fn:140001000".to_string(),

            trigger_id: "api.virtualalloc".to_string(),

            evidence: vec![SeedEvidence {
                kind: "api".to_string(),

                value: "VirtualAlloc".to_string(),

                node_id: Some("api:virtualalloc".to_string()),

                edge_type: Some("calls_api".to_string()),

                callsite: Some("140001050".to_string()),
            }],

            reason: "Function references VirtualAlloc".to_string(),
        };

        candidate
            .validate()
            .expect("well-formed seed candidate should validate");

        let serialized =
            serde_json::to_string(&candidate).expect("seed candidate should serialize");

        let deserialized: SeedCandidate =
            serde_json::from_str(&serialized).expect("seed candidate should deserialize");

        assert_eq!(deserialized, candidate);
    }

    #[test]
    fn seed_candidate_serialization_contains_no_scoring_fields() {
        let candidate = SeedCandidate {
            seed_id: "seed:fn:140001000:api.virtualalloc".to_string(),

            anchor_function_id: "fn:140001000".to_string(),

            trigger_id: "api.virtualalloc".to_string(),

            evidence: vec![SeedEvidence {
                kind: "api".to_string(),

                value: "VirtualAlloc".to_string(),

                node_id: Some("api:virtualalloc".to_string()),

                edge_type: Some("calls_api".to_string()),

                callsite: Some("140001050".to_string()),
            }],

            reason: "Function references VirtualAlloc".to_string(),
        };

        let serialized = serde_json::to_value(&candidate).expect("seed candidate should serialize");

        for forbidden_field in [
            "score",
            "priority",
            "confidence",
            "risk_level",
            "legacy_metadata",
            "function_score",
        ] {
            assert!(
                serialized.get(forbidden_field).is_none(),
                "seed candidate must not expose \
                scoring field: {forbidden_field}"
            );
        }
    }

    #[test]
    fn seed_candidate_deserialization_rejects_scoring_fields() {
        let json = serde_json::json!({
            "seed_id":
                "seed:fn:140001000:api.virtualalloc",

            "anchor_function_id":
                "fn:140001000",

            "trigger_id":
                "api.virtualalloc",

            "evidence": [
                {
                    "kind": "api",
                    "value": "VirtualAlloc",
                    "node_id": "api:virtualalloc",
                    "edge_type": "calls_api",
                    "callsite": "140001050"
                }
            ],

            "reason":
                "Function references VirtualAlloc",

            "priority": 80
        });

        let result = serde_json::from_value::<SeedCandidate>(json);

        assert!(result.is_err());
    }

    #[test]
    fn seed_candidate_validation_rejects_invalid_anchor() {
        let candidate = SeedCandidate {
            seed_id: "seed:140001000:api.virtualalloc".to_string(),

            anchor_function_id: "140001000".to_string(),

            trigger_id: "api.virtualalloc".to_string(),

            evidence: vec![SeedEvidence {
                kind: "api".to_string(),

                value: "VirtualAlloc".to_string(),

                node_id: None,
                edge_type: None,
                callsite: None,
            }],

            reason: "Function references VirtualAlloc".to_string(),
        };

        assert!(candidate.validate().is_err());
    }

    #[test]
    fn seed_candidate_validation_rejects_empty_trigger_reason_or_evidence() {
        let base = SeedCandidate {
            seed_id: "seed:fn:140001000:api.virtualalloc".to_string(),

            anchor_function_id: "fn:140001000".to_string(),

            trigger_id: "api.virtualalloc".to_string(),

            evidence: vec![SeedEvidence {
                kind: "api".to_string(),

                value: "VirtualAlloc".to_string(),

                node_id: None,
                edge_type: None,
                callsite: None,
            }],

            reason: "Function references VirtualAlloc".to_string(),
        };

        let mut no_trigger = base.clone();
        no_trigger.trigger_id = "   ".to_string();

        assert!(no_trigger.validate().is_err());

        let mut no_reason = base.clone();
        no_reason.reason = "   ".to_string();

        assert!(no_reason.validate().is_err());

        let mut no_evidence = base;
        no_evidence.evidence.clear();

        assert!(no_evidence.validate().is_err());
    }

    #[test]
    fn seed_candidate_validation_rejects_mismatched_seed_id() {
        let candidate = SeedCandidate {
            seed_id: "seed:fn:140001000:api.getprocaddress".to_string(),

            anchor_function_id: "fn:140001000".to_string(),

            trigger_id: "api.virtualalloc".to_string(),

            evidence: vec![SeedEvidence {
                kind: "api".to_string(),

                value: "VirtualAlloc".to_string(),

                node_id: None,
                edge_type: None,
                callsite: None,
            }],

            reason: "Function references VirtualAlloc".to_string(),
        };

        assert!(candidate.validate().is_err());
    }

    #[test]
    fn seed_candidate_validation_rejects_blank_evidence_fields() {
        let candidate = SeedCandidate {
            seed_id: "seed:fn:140001000:api.virtualalloc".to_string(),

            anchor_function_id: "fn:140001000".to_string(),

            trigger_id: "api.virtualalloc".to_string(),

            evidence: vec![SeedEvidence {
                kind: " ".to_string(),

                value: "VirtualAlloc".to_string(),

                node_id: None,
                edge_type: None,
                callsite: None,
            }],

            reason: "Function references VirtualAlloc".to_string(),
        };

        assert!(candidate.validate().is_err());
    }

    #[test]
    fn legacy_rust_enrichment_without_seeded_field_deserializes_as_none() {
        let enrichment: RustEnrichment =
            serde_json::from_str("{}").expect("legacy Rust enrichment should deserialize");

        assert!(enrichment.seeded_fingerprinting.is_none());
    }
}

#[test]
fn seeded_fingerprinting_default_result_serializes_null_optional_fields() {
    let result = SeededFingerprintingResult::default();

    let serialized = serde_json::to_value(&result)
        .expect("default seeded fingerprinting result should serialize");

    assert_eq!(
        serialized,
        serde_json::json!({
            "status": "disabled",
            "schema_version": null,
            "message": null
        })
    );
}
