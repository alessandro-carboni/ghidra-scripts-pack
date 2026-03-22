use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScoreRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub condition: String,
    #[serde(default)]
    pub delta: i32,
    #[serde(default)]
    pub rationale: String,

    #[serde(default)]
    pub requires_all_capabilities: Vec<String>,
    #[serde(default)]
    pub requires_any_capabilities: Vec<String>,
    #[serde(default)]
    pub forbids_capabilities: Vec<String>,
    #[serde(default)]
    pub requires_high_confidence_capabilities: Vec<String>,
    #[serde(default)]
    pub min_high_risk_top_functions: Option<usize>,
    #[serde(default)]
    pub min_top_function_score: Option<i32>,
    #[serde(default)]
    pub min_non_benign_interesting_strings: Option<usize>,
    #[serde(default)]
    pub requires_likely_packed: Option<bool>,
    #[serde(default)]
    pub min_packing_score: Option<i32>,
    #[serde(default)]
    pub min_high_entropy_executable_sections: Option<usize>,
    #[serde(default)]
    pub min_suspicious_section_count: Option<usize>,
    #[serde(default)]
    pub requires_primary_reasoned_top_function: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DerivedCapabilityRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub requires_all: Vec<String>,
    #[serde(default)]
    pub requires_any: Vec<String>,
    #[serde(default)]
    pub forbids: Vec<String>,
    #[serde(default)]
    pub requires_high_confidence: Vec<String>,
    #[serde(default)]
    pub require_likely_packed: Option<bool>,
    #[serde(default)]
    pub require_high_entropy_executable: Option<bool>,
    #[serde(default)]
    pub min_high_risk_functions: Option<usize>,
    #[serde(default)]
    pub min_top_function_score: Option<i32>,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RustRules {
    pub score_rules: Vec<ScoreRule>,
    pub derived_capability_rules: Vec<DerivedCapabilityRule>,
    pub score_rules_loaded: bool,
    pub derived_rules_loaded: bool,
    pub using_defaults: bool,
    pub load_errors: Vec<String>,
    pub rules_dir: String,
}

pub fn load_rules_from_dir(rules_dir: &str) -> RustRules {
    let mut out = RustRules {
        score_rules: default_score_rules(),
        derived_capability_rules: default_derived_capability_rules(),
        score_rules_loaded: false,
        derived_rules_loaded: false,
        using_defaults: true,
        load_errors: Vec::new(),
        rules_dir: rules_dir.to_string(),
    };

    let score_path = Path::new(rules_dir).join("rust_score_rules.json");
    match fs::read_to_string(&score_path) {
        Ok(data) => match serde_json::from_str::<Vec<ScoreRule>>(&data) {
            Ok(parsed) if !parsed.is_empty() => {
                out.score_rules = parsed;
                out.score_rules_loaded = true;
            }
            Ok(_) => {
                out.load_errors.push(format!(
                    "score rules file '{}' was valid but empty; using defaults",
                    score_path.display()
                ));
            }
            Err(err) => {
                out.load_errors.push(format!(
                    "failed to parse score rules '{}': {}; using defaults",
                    score_path.display(),
                    err
                ));
            }
        },
        Err(err) => {
            out.load_errors.push(format!(
                "failed to read score rules '{}': {}; using defaults",
                score_path.display(),
                err
            ));
        }
    }

    let derived_path = Path::new(rules_dir).join("rust_derived_rules.json");
    match fs::read_to_string(&derived_path) {
        Ok(data) => match serde_json::from_str::<Vec<DerivedCapabilityRule>>(&data) {
            Ok(parsed) if !parsed.is_empty() => {
                out.derived_capability_rules = parsed;
                out.derived_rules_loaded = true;
            }
            Ok(_) => {
                out.load_errors.push(format!(
                    "derived capability rules file '{}' was valid but empty; using defaults",
                    derived_path.display()
                ));
            }
            Err(err) => {
                out.load_errors.push(format!(
                    "failed to parse derived capability rules '{}': {}; using defaults",
                    derived_path.display(),
                    err
                ));
            }
        },
        Err(err) => {
            out.load_errors.push(format!(
                "failed to read derived capability rules '{}': {}; using defaults",
                derived_path.display(),
                err
            ));
        }
    }

    out.using_defaults = !(out.score_rules_loaded && out.derived_rules_loaded);
    out
}

fn default_score_rules() -> Vec<ScoreRule> {
    vec![
        ScoreRule {
            id: "multiple_high_risk_top_functions".to_string(),
            condition: "multiple_high_risk_top_functions".to_string(),
            delta: 10,
            rationale: "two or more top functions are already classified as high or critical risk".to_string(),
        },
        ScoreRule {
            id: "packed_sample_static_visibility_penalty".to_string(),
            condition: "packed_sample_static_visibility_penalty".to_string(),
            delta: -10,
            rationale: "packing reduces visibility of true runtime behavior during static triage".to_string(),
        },
        ScoreRule {
            id: "process_injection_capability".to_string(),
            condition: "process_injection_capability".to_string(),
            delta: 15,
            rationale: "process injection is a high-impact malicious behavior cluster".to_string(),
        },
        ScoreRule {
            id: "high_signal_interesting_strings".to_string(),
            condition: "high_signal_interesting_strings".to_string(),
            delta: 5,
            rationale: "non-benign high-score strings support suspicious interpretation".to_string(),
        },
        ScoreRule {
            id: "top_function_reasoned_evidence".to_string(),
            condition: "top_function_reasoned_evidence".to_string(),
            delta: 6,
            rationale: "at least one top function has explicit local evidence and reasoning".to_string(),
        },
        ScoreRule {
            id: "strong_packing_with_weak_visible_behavior".to_string(),
            condition: "strong_packing_with_weak_visible_behavior".to_string(),
            delta: -6,
            rationale: "strong packing combined with weak visible malicious evidence should reduce malware-oriented calibration".to_string(),
        },
        ScoreRule {
            id: "benign_context_heavy_discount".to_string(),
            condition: "benign_context_heavy_discount".to_string(),
            delta: -10,
            rationale: "multiple benign-context adjustments in the raw report justify a more conservative calibration".to_string(),
        },
        ScoreRule {
            id: "soft_capability_only_discount".to_string(),
            condition: "soft_capability_only_discount".to_string(),
            delta: -8,
            rationale: "only soft capabilities are present, so the global score should remain conservative".to_string(),
        },
    ]
}

fn default_derived_capability_rules() -> Vec<DerivedCapabilityRule> {
    vec![
        DerivedCapabilityRule {
            name: "in_memory_loader".to_string(),
            confidence: "high".to_string(),
            requires_all: vec!["process_injection".to_string(), "dynamic_loading".to_string()],
            requires_high_confidence: vec!["process_injection".to_string()],
            rationale: vec![
                "process injection and dynamic loading are both present".to_string(),
                "this combination is consistent with staged or memory-resident execution".to_string(),
            ],
            ..Default::default()
        },
        DerivedCapabilityRule {
            name: "persistent_networked_payload".to_string(),
            confidence: "medium".to_string(),
            requires_all: vec!["networking".to_string(), "persistence".to_string()],
            rationale: vec![
                "networking and persistence signals are both present".to_string(),
                "the combination suggests potential long-lived malicious utility".to_string(),
            ],
            ..Default::default()
        },
        DerivedCapabilityRule {
            name: "evasion_aware_injector".to_string(),
            confidence: "medium".to_string(),
            requires_all: vec!["anti_analysis".to_string(), "process_injection".to_string()],
            rationale: vec![
                "anti-analysis and process injection signals co-occur".to_string(),
                "this pairing is commonly associated with stealthier payload deployment".to_string(),
            ],
            ..Default::default()
        },
        DerivedCapabilityRule {
            name: "packed_loader_stub".to_string(),
            confidence: "medium".to_string(),
            requires_any: vec!["dynamic_loading".to_string()],
            require_likely_packed: Some(true),
            require_high_entropy_executable: Some(true),
            rationale: vec![
                "sample is likely packed and still exposes dynamic loading behavior".to_string(),
                "this is consistent with a loader or unpacking stub stage".to_string(),
            ],
            ..Default::default()
        },
    ]
}