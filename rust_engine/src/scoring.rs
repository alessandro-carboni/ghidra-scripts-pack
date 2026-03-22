use std::collections::HashSet;

use crate::rules::ScoreRule;
use crate::schema::{Report, RiskScore, ScoreDriver};

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

fn count_high_risk_top_functions(report: &Report) -> usize {
    report
        .function_analysis
        .top_functions
        .iter()
        .filter(|f| f.risk_level == "high" || f.risk_level == "critical")
        .count()
}

fn top_function_max_score(report: &Report) -> i32 {
    report
        .function_analysis
        .top_functions
        .iter()
        .map(|f| f.score)
        .max()
        .unwrap_or(0)
}

fn count_non_benign_interesting_strings(report: &Report, min_score: i32) -> usize {
    report
        .global_analysis
        .interesting_strings
        .iter()
        .filter(|s| !s.benign_hint && s.score >= min_score)
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

fn count_suspicious_sections(report: &Report) -> usize {
    let from_sections = report
        .binary_structure
        .section_info
        .iter()
        .filter(|s| s.suspicious)
        .count();

    let from_summary = report
        .binary_structure
        .packer_analysis
        .suspicious_section_count
        .max(0) as usize;

    from_sections.max(from_summary)
}

fn has_primary_reasoned_top_function(report: &Report) -> bool {
    report
        .function_analysis
        .top_functions
        .iter()
        .any(|f| !f.primary_reason.trim().is_empty() || !f.reason_summary.trim().is_empty())
}

fn has_high_confidence_global_capability(report: &Report, capability_name: &str) -> bool {
    report.global_analysis.capabilities.iter().any(|c| {
        c.name == capability_name
            && (c.confidence.trim().eq_ignore_ascii_case("high")
                || c.match_count >= c.min_matches + 1)
    })
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

fn count_high_impact_capabilities(report: &Report) -> usize {
    report
        .global_analysis
        .capabilities
        .iter()
        .filter(|c| is_high_impact_capability(&c.name))
        .count()
}

fn count_soft_capabilities(report: &Report) -> usize {
    report
        .global_analysis
        .capabilities
        .iter()
        .filter(|c| is_soft_capability(&c.name))
        .count()
}

fn resource_only_high_entropy_signal(report: &Report) -> bool {
    let mut high_entropy_names = Vec::new();

    for s in &report.binary_structure.section_info {
        if s.entropy_class == "high" || s.entropy_class == "very_high" {
            high_entropy_names.push(s.name.trim().to_lowercase());
        }
    }

    !high_entropy_names.is_empty()
        && count_high_entropy_executable_sections(report) == 0
        && high_entropy_names
            .iter()
            .all(|name| name == ".rsrc" || name == "rsrc")
}

fn evaluate_score_condition(report: &Report, condition: &str) -> bool {
    match condition {
        "multiple_high_risk_top_functions" => count_high_risk_top_functions(report) >= 2,

        "packed_sample_static_visibility_penalty" => {
            report.binary_structure.packer_analysis.likely_packed
        }

        "process_injection_capability" => report
            .global_analysis
            .capabilities
            .iter()
            .any(|c| c.name == "process_injection"),

        "high_signal_interesting_strings" => count_non_benign_interesting_strings(report, 15) > 0,

        "top_function_reasoned_evidence" => has_primary_reasoned_top_function(report),

        "strong_packing_with_weak_visible_behavior" => {
            report.binary_structure.packer_analysis.likely_packed
                && report.summary.suspicious_api_count <= 4
                && report.summary.capability_count <= 1
                && top_function_max_score(report) < 35
        }

        "benign_context_heavy_discount" => {
            benign_context_count(report) >= 2 && negative_benign_adjustment_total(report) >= 20
        }

        "soft_capability_only_discount" => {
            count_high_impact_capabilities(report) == 0 && count_soft_capabilities(report) > 0
        }

        _ => false,
    }
}

fn evaluate_score_rule(report: &Report, rule: &ScoreRule) -> bool {
    let capability_names = capability_name_set(report);

    let mut checked_any = false;
    let mut matched = true;

    if !rule.condition.trim().is_empty() {
        checked_any = true;
        matched &= evaluate_score_condition(report, &rule.condition);
    }

    if !rule.requires_all_capabilities.is_empty() {
        checked_any = true;
        matched &= rule
            .requires_all_capabilities
            .iter()
            .all(|required| capability_names.contains(required));
    }

    if !rule.requires_any_capabilities.is_empty() {
        checked_any = true;
        matched &= rule
            .requires_any_capabilities
            .iter()
            .any(|required| capability_names.contains(required));
    }

    if !rule.forbids_capabilities.is_empty() {
        checked_any = true;
        matched &= !rule
            .forbids_capabilities
            .iter()
            .any(|forbidden| capability_names.contains(forbidden));
    }

    if !rule.requires_high_confidence_capabilities.is_empty() {
        checked_any = true;
        matched &= rule
            .requires_high_confidence_capabilities
            .iter()
            .all(|required| has_high_confidence_global_capability(report, required));
    }

    if let Some(min_high_risk_top_functions) = rule.min_high_risk_top_functions {
        checked_any = true;
        matched &= count_high_risk_top_functions(report) >= min_high_risk_top_functions;
    }

    if let Some(min_top_function_score) = rule.min_top_function_score {
        checked_any = true;
        matched &= top_function_max_score(report) >= min_top_function_score;
    }

    if let Some(min_non_benign_interesting_strings) = rule.min_non_benign_interesting_strings {
        checked_any = true;
        matched &= count_non_benign_interesting_strings(report, 12)
            >= min_non_benign_interesting_strings;
    }

    if let Some(requires_likely_packed) = rule.requires_likely_packed {
        checked_any = true;
        matched &= report.binary_structure.packer_analysis.likely_packed == requires_likely_packed;
    }

    if let Some(min_packing_score) = rule.min_packing_score {
        checked_any = true;
        matched &= report.binary_structure.packer_analysis.packed_likelihood_score >= min_packing_score;
    }

    if let Some(min_high_entropy_executable_sections) = rule.min_high_entropy_executable_sections {
        checked_any = true;
        matched &= count_high_entropy_executable_sections(report) >= min_high_entropy_executable_sections;
    }

    if let Some(min_suspicious_section_count) = rule.min_suspicious_section_count {
        checked_any = true;
        matched &= count_suspicious_sections(report) >= min_suspicious_section_count;
    }

    if let Some(requires_primary_reasoned_top_function) =
        rule.requires_primary_reasoned_top_function
    {
        checked_any = true;
        matched &= has_primary_reasoned_top_function(report) == requires_primary_reasoned_top_function;
    }

    checked_any && matched
}

pub fn calibrate_score(
    report: &Report,
    score_rules: &[ScoreRule],
) -> (i32, Vec<String>, Vec<ScoreDriver>) {
    let mut calibrated = report.summary.overall_score;
    let mut rationale = Vec::new();
    let mut drivers = Vec::new();

    for rule in score_rules {
        if evaluate_score_rule(report, rule) {
            calibrated += rule.delta;
            rationale.push(format!("rule '{}' applied: {}", rule.id, rule.rationale));
            drivers.push(ScoreDriver {
                driver: rule.id.clone(),
                direction: if rule.delta >= 0 {
                    "increase".to_string()
                } else {
                    "decrease".to_string()
                },
                weight: rule.delta.abs(),
                rationale: rule.rationale.clone(),
            });
        }
    }

    if calibrated < 0 {
        calibrated = 0;
    }

    (calibrated, rationale, drivers)
}

pub fn score_to_band(score: i32) -> String {
    if score >= 120 {
        return "critical".to_string();
    }
    if score >= 85 {
        return "high".to_string();
    }
    if score >= 30 {
        return "medium".to_string();
    }
    "low".to_string()
}

pub fn compute_malware_risk(report: &Report, calibrated_score: i32) -> RiskScore {
    let mut score = calibrated_score;
    let mut rationale = Vec::new();

    let capability_names = capability_name_set(report);

    let has_process_injection = capability_names.contains("process_injection");
    let has_networking = capability_names.contains("networking");
    let has_persistence = capability_names.contains("persistence");
    let has_dynamic_loading = capability_names.contains("dynamic_loading");
    let has_anti_analysis = capability_names.contains("anti_analysis");
    let has_crypto = capability_names.contains("crypto");

    let high_risk_top_functions = count_high_risk_top_functions(report) as i32;
    let benign_contexts = benign_context_count(report);
    let benign_adjustment_total = negative_benign_adjustment_total(report);
    let high_impact_cap_count = count_high_impact_capabilities(report);

    let top_functions_with_local_api_evidence = report
        .function_analysis
        .top_functions
        .iter()
        .filter(|f| !f.local_api_hits.is_empty() || !f.evidence.local_api_hits.is_empty())
        .count() as i32;

    if has_process_injection {
        score += 18;
        rationale.push("process injection strongly increases malware-oriented risk".to_string());
    }

    if has_networking && has_persistence {
        score += 8;
        rationale.push("networking combined with persistence suggests sustained malicious utility".to_string());
    } else if has_networking && has_crypto {
        score += 8;
        rationale.push("networking combined with crypto increases suspicious utility".to_string());
    } else if has_networking {
        score += 4;
        rationale.push("networking contributes to malware-oriented risk but is not decisive alone".to_string());
    }

    if has_dynamic_loading && has_process_injection {
        score += 8;
        rationale.push("dynamic loading combined with process injection is consistent with staged or memory-resident execution".to_string());
    }

    if has_anti_analysis && (has_process_injection || has_dynamic_loading || has_networking || has_crypto) {
        score += 6;
        rationale.push("anti-analysis combined with stronger offensive signals increases suspicion".to_string());
    }

    if high_risk_top_functions >= 3 {
        score += 10;
        rationale.push("multiple high-risk functions reinforce the malware hypothesis".to_string());
    }

    if top_functions_with_local_api_evidence >= 2 {
        score += 6;
        rationale.push("multiple top functions expose local suspicious API evidence".to_string());
    }

    if high_impact_cap_count == 0 && (has_persistence || has_dynamic_loading || has_anti_analysis) {
        score -= 15;
        rationale.push("only soft capabilities are present, so malware attribution should remain conservative".to_string());
    }

    if benign_contexts >= 2 {
        score -= 12;
        rationale.push("multiple benign contexts reduce malware-oriented confidence".to_string());
    }

    if benign_adjustment_total >= 20 {
        score -= 10;
        rationale.push("contextual benign adjustments in the raw report reduce malware-oriented interpretation".to_string());
    }

    if !has_process_injection && !has_networking && !has_crypto && high_risk_top_functions == 0 {
        score -= 8;
        rationale.push("no high-impact capability or high-risk function materially strengthens the malware case".to_string());
    }

    if report.binary_structure.packer_analysis.likely_packed {
        if !has_process_injection && top_functions_with_local_api_evidence == 0 {
            score -= 10;
            rationale.push("packing with weak visible local evidence reduces confidence in direct malware attribution".to_string());
        } else {
            score -= 5;
            rationale.push("possible packing slightly reduces confidence in complete static malware attribution".to_string());
        }
    }

    if score < 0 {
        score = 0;
    }

    let level = score_to_band(score);
    RiskScore {
        score,
        level,
        rationale,
    }
}

pub fn compute_packing_risk(report: &Report) -> RiskScore {
    let mut score = report
        .binary_structure
        .packer_analysis
        .packed_likelihood_score
        .max(report.summary.packing_likelihood_score);

    let mut rationale = Vec::new();

    if report.binary_structure.packer_analysis.likely_packed {
        score += 20;
        rationale.push("report explicitly flags the sample as likely packed".to_string());
    }

    let family = if !report.binary_structure.packer_analysis.packer_family_hint.trim().is_empty() {
        report.binary_structure.packer_analysis.packer_family_hint.trim().to_string()
    } else {
        report.summary.packer_family_hint.trim().to_string()
    };

    let normalized_family = family.to_lowercase();
    let meaningful_family = !normalized_family.is_empty()
        && normalized_family != "none"
        && normalized_family != "unknown"
        && normalized_family != "n/a"
        && normalized_family != "na"
        && normalized_family != "null";

    if meaningful_family {
        score += 10;
        rationale.push(format!("packer family hint present: {}", family));
    }

    let suspicious_api_count = report.summary.suspicious_api_count;
    let capability_count = report.summary.capability_count;

    let suspicious_section_count = count_suspicious_sections(report) as i32;
    if suspicious_section_count > 0 {
        let bump = (suspicious_section_count * 4).min(12);
        score += bump;
        rationale.push("suspicious or non-standard sections reinforce packing-oriented risk".to_string());
    }

    let high_entropy_section_count = report
        .binary_structure
        .packer_analysis
        .high_entropy_section_count
        .max(0);

    if high_entropy_section_count > 0 {
        let bump = (high_entropy_section_count * 4).min(12);
        score += bump;
        rationale.push("high-entropy sections are consistent with compression, encryption, or packing".to_string());
    }

    let high_entropy_executable_count = count_high_entropy_executable_sections(report) as i32;
    if high_entropy_executable_count > 0 {
        let bump = (high_entropy_executable_count * 6).min(18);
        score += bump;
        rationale.push("high-entropy executable sections are strongly consistent with stub or packed code".to_string());
    }

    if let Some(ep_entropy) = report.binary_structure.packer_analysis.entrypoint_section_entropy {
        if ep_entropy >= 7.6 {
            score += 10;
            rationale.push("entrypoint section entropy is very high".to_string());
        } else if ep_entropy >= 7.2 {
            score += 6;
            rationale.push("entrypoint section entropy is high".to_string());
        }
    }

    if let Some(ref top_oep) = report.binary_structure.packer_analysis.oep_candidate_summary {
        if top_oep.score >= 35 {
            score += 12;
            rationale.push("strong OEP candidate near entrypoint supports a stub-to-real-code handoff hypothesis".to_string());
        } else if top_oep.score >= 20 {
            score += 6;
            rationale.push("moderate OEP candidate near entrypoint supports possible handoff behavior".to_string());
        }
    }

    if suspicious_api_count <= 3 && report.binary_structure.packer_analysis.likely_packed {
        score += 10;
        rationale.push("low visible API surface combined with packing is consistent with stub-like behavior".to_string());
    }

    if capability_count == 0 && report.binary_structure.packer_analysis.likely_packed {
        score += 10;
        rationale.push("few or no explicit capabilities with likely packing suggests hidden behavior".to_string());
    }

    if !report.binary_structure.packer_analysis.analysis_notes.is_empty() {
        score += 4;
        rationale.push("packer analysis notes reinforce the interpretation that static visibility may be stub-dominated".to_string());
    }

    if resource_only_high_entropy_signal(report) {
        score -= 10;
        rationale.push("resource-only high entropy without executable high-entropy code reduces packing confidence".to_string());
    }

    if count_high_entropy_executable_sections(report) == 0
        && !report.binary_structure.packer_analysis.likely_packed
    {
        score -= 6;
        rationale.push("no executable high-entropy section was observed, which weakens the packing hypothesis".to_string());
    }

    if score < 0 {
        score = 0;
    }

    let level = score_to_band(score);
    RiskScore {
        score,
        level,
        rationale,
    }
}