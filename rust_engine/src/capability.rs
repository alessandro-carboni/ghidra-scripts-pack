use std::collections::{HashMap, HashSet};

use crate::rules::DerivedCapabilityRule;
use crate::schema::{CapabilityConfidence, DerivedCapability, Report};

fn confidence_rank(value: &str) -> i32 {
    match value.trim().to_lowercase().as_str() {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 1,
    }
}

fn rank_to_confidence(rank: i32) -> String {
    match rank {
        3..=i32::MAX => "high".to_string(),
        2 => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn is_soft_capability(name: &str) -> bool {
    matches!(name, "anti_analysis" | "persistence" | "dynamic_loading")
}

fn is_high_impact_capability(name: &str) -> bool {
    matches!(name, "process_injection" | "networking" | "crypto")
}

fn capability_name_set(report: &Report) -> HashSet<String> {
    report
        .global_analysis
        .capabilities
        .iter()
        .map(|c| c.name.clone())
        .collect()
}

fn function_supports_capability(
    capability_name: &str,
    matched_capabilities: &[String],
    roles: &[String],
    tags: &[String],
) -> bool {
    if matched_capabilities.iter().any(|x| x == capability_name) {
        return true;
    }

    if tags.iter().any(|x| x == capability_name) {
        return true;
    }

    match capability_name {
        "networking" => roles.iter().any(|r| r == "network"),
        "process_injection" => roles.iter().any(|r| r == "injection"),
        "dynamic_loading" => roles.iter().any(|r| r == "loader"),
        _ => roles.iter().any(|r| r == capability_name),
    }
}

fn count_high_risk_functions(report: &Report) -> usize {
    report
        .function_analysis
        .functions
        .iter()
        .filter(|f| f.risk_level == "high" || f.risk_level == "critical")
        .count()
}

fn count_high_entropy_executable_sections(report: &Report) -> usize {
    let from_sections = report
        .binary_structure
        .section_info
        .iter()
        .filter(|s| s.execute && (s.entropy_class == "high" || s.entropy_class == "very_high"))
        .count();

    let from_summary = report
        .binary_structure
        .packer_analysis
        .high_entropy_executable_count
        .max(0) as usize;

    from_sections.max(from_summary)
}

fn top_function_support_count(report: &Report, capability_name: &str) -> usize {
    report
        .function_analysis
        .top_functions
        .iter()
        .filter(|f| {
            function_supports_capability(
                capability_name,
                &f.matched_capabilities,
                &f.roles,
                &f.tags,
            ) || function_supports_capability(
                capability_name,
                &f.evidence.matched_capabilities,
                &f.roles,
                &f.tags,
            )
        })
        .count()
}

fn function_support_count(report: &Report, capability_name: &str) -> usize {
    report
        .function_analysis
        .functions
        .iter()
        .filter(|f| {
            function_supports_capability(
                capability_name,
                &f.matched_capabilities,
                &f.roles,
                &f.tags,
            )
        })
        .count()
}

fn medium_or_higher_function_support_count(report: &Report, capability_name: &str) -> usize {
    report
        .function_analysis
        .functions
        .iter()
        .filter(|f| {
            (f.risk_level == "medium" || f.risk_level == "high" || f.risk_level == "critical")
                && function_supports_capability(
                    capability_name,
                    &f.matched_capabilities,
                    &f.roles,
                    &f.tags,
                )
        })
        .count()
}

fn benign_context_count(report: &Report) -> usize {
    report.global_analysis.benign_contexts.len()
}

fn negative_benign_adjustment_total(report: &Report) -> i32 {
    report
        .global_analysis
        .score_adjustments
        .iter()
        .filter(|a| a.delta < 0)
        .map(|a| a.delta.abs())
        .sum()
}

fn has_high_confidence_capability(
    confidence_by_name: &HashMap<String, String>,
    capability_name: &str,
) -> bool {
    confidence_by_name
        .get(capability_name)
        .map(|v| v == "high")
        .unwrap_or(false)
}

pub fn calibrate_capability_confidence(report: &Report) -> Vec<CapabilityConfidence> {
    let mut output = Vec::new();

    let benign_contexts = benign_context_count(report);
    let benign_adjustment_total = negative_benign_adjustment_total(report);

    for cap in &report.global_analysis.capabilities {
        let mut rank = confidence_rank(&cap.confidence);
        let mut rationale = Vec::new();

        let supporting_functions = function_support_count(report, &cap.name);
        let supporting_medium_or_higher =
            medium_or_higher_function_support_count(report, &cap.name);
        let top_support = top_function_support_count(report, &cap.name);

        if is_high_impact_capability(&cap.name) {
            if cap.match_count >= cap.min_matches + 2 {
                rank = rank.max(3);
                rationale.push("match count exceeds minimum threshold by a strong margin".to_string());
            } else if cap.match_count >= cap.min_matches + 1 {
                rank = rank.max(2);
                rationale.push("match count exceeds minimum threshold".to_string());
            }

            if supporting_functions >= 2 {
                rank = rank.max(3);
                rationale.push("multiple functions locally support this capability".to_string());
            } else if supporting_functions == 1 {
                rank = rank.max(2);
                rationale.push("one function locally supports this capability".to_string());
            }

            if top_support >= 1 {
                rank = rank.max(2);
                rationale.push("top-function evidence reinforces this capability".to_string());
            }

            if cap.name == "process_injection" && (top_support >= 1 || supporting_medium_or_higher >= 1) {
                rank = rank.max(3);
                rationale.push("process injection receives stronger weighting because it is high-impact and locally supported".to_string());
            }
        } else {
            if supporting_functions >= 2 {
                rank = rank.max(2);
                rationale.push("multiple functions locally support this soft capability".to_string());
            } else if supporting_functions == 1 {
                rank = rank.min(1).max(1);
                rationale.push("soft capability remains isolated or minimally supported".to_string());
            }

            if cap.match_count >= cap.min_matches + 2 && supporting_functions >= 2 && top_support >= 1 {
                rank = rank.max(3);
                rationale.push("soft capability is backed by stronger global evidence plus top-function support".to_string());
            } else if cap.match_count >= cap.min_matches + 1 && supporting_functions >= 2 {
                rank = rank.max(2);
                rationale.push("soft capability has some reinforcing local evidence".to_string());
            }

            if benign_contexts >= 2 && top_support == 0 {
                rank = 1;
                rationale.push("benign contexts reduce confidence for isolated soft capability signals".to_string());
            } else if benign_adjustment_total >= 20 && supporting_medium_or_higher == 0 {
                rank = 1;
                rationale.push("raw report already contains meaningful benign score adjustments that weaken this soft capability".to_string());
            }
        }

        if report.binary_structure.packer_analysis.likely_packed {
            if is_high_impact_capability(&cap.name) {
                rationale.push("sample appears packed, so static capability confidence should still be interpreted cautiously".to_string());
            } else if supporting_functions == 0 && top_support == 0 {
                rank = (rank - 1).max(1);
                rationale.push("sample appears packed and this soft capability lacks local functional support, so confidence is reduced".to_string());
            } else {
                rationale.push("sample appears packed, so soft static capability confidence should be interpreted cautiously".to_string());
            }
        }

        output.push(CapabilityConfidence {
            name: cap.name.clone(),
            base_confidence: cap.confidence.clone(),
            calibrated_confidence: rank_to_confidence(rank),
            rationale,
        });
    }

    output
}

pub fn derive_capabilities(
    report: &Report,
    calibrated_confidence: &[CapabilityConfidence],
    rules: &[DerivedCapabilityRule],
) -> Vec<DerivedCapability> {
    let mut derived = Vec::new();

    let capability_names = capability_name_set(report);
    let confidence_by_name: HashMap<String, String> = calibrated_confidence
        .iter()
        .map(|c| (c.name.clone(), c.calibrated_confidence.clone()))
        .collect();

    let high_risk_function_count = count_high_risk_functions(report);
    let high_entropy_executable_count = count_high_entropy_executable_sections(report);
    let top_function_max_score = report
        .function_analysis
        .top_functions
        .iter()
        .map(|f| f.score)
        .max()
        .unwrap_or(0);

    for rule in rules {
        let mut checked_any = false;
        let mut rule_matches = true;

        if !rule.requires_all.is_empty() {
            checked_any = true;
            rule_matches &= rule
                .requires_all
                .iter()
                .all(|required| capability_names.contains(required));
        }

        if !rule.requires_any.is_empty() {
            checked_any = true;
            rule_matches &= rule
                .requires_any
                .iter()
                .any(|required| capability_names.contains(required));
        }

        if !rule.forbids.is_empty() {
            checked_any = true;
            rule_matches &= !rule
                .forbids
                .iter()
                .any(|forbidden| capability_names.contains(forbidden));
        }

        if !rule.requires_high_confidence.is_empty() {
            checked_any = true;
            rule_matches &= rule
                .requires_high_confidence
                .iter()
                .all(|required| has_high_confidence_capability(&confidence_by_name, required));
        }

        if let Some(require_packed) = rule.require_likely_packed {
            checked_any = true;
            rule_matches &= report.binary_structure.packer_analysis.likely_packed == require_packed;
        }

        if let Some(require_high_entropy) = rule.require_high_entropy_executable {
            checked_any = true;
            let has_high_entropy_exec = high_entropy_executable_count > 0;
            rule_matches &= has_high_entropy_exec == require_high_entropy;
        }

        if let Some(min_high_risk_functions) = rule.min_high_risk_functions {
            checked_any = true;
            rule_matches &= high_risk_function_count >= min_high_risk_functions;
        }

        if let Some(min_top_function_score) = rule.min_top_function_score {
            checked_any = true;
            rule_matches &= top_function_max_score >= min_top_function_score;
        }

        if checked_any && rule_matches {
            derived.push(DerivedCapability {
                name: rule.name.clone(),
                confidence: rule.confidence.clone(),
                rationale: rule.rationale.clone(),
            });
        }
    }

    derived
}