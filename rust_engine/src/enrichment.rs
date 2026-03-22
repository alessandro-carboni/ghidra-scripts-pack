use crate::capability::{calibrate_capability_confidence, derive_capabilities};
use crate::rules::load_rules_from_dir;
use crate::schema::{
    DecisionSummary, EngineMetadata, Report, RiskSplitSummary, RulesMetadata, RustEnrichment,
    SchemaValidation, ScoreBands, ScoreCalibration,
};
use crate::scoring::{calibrate_score, compute_malware_risk, compute_packing_risk, score_to_band};

fn push_unique(vec: &mut Vec<String>, value: String) {
    if !vec.iter().any(|x| x == &value) {
        vec.push(value);
    }
}

fn is_high_impact_capability(name: &str) -> bool {
    matches!(name, "process_injection" | "networking" | "crypto")
}

fn count_high_risk_top_functions(report: &Report) -> usize {
    report
        .function_analysis
        .top_functions
        .iter()
        .filter(|f| f.risk_level == "high" || f.risk_level == "critical")
        .count()
}

fn count_reasoned_top_functions(report: &Report) -> usize {
    report
        .function_analysis
        .top_functions
        .iter()
        .filter(|f| !f.primary_reason.trim().is_empty() || !f.reason_summary.trim().is_empty())
        .count()
}

fn has_high_scoring_oep_candidate(report: &Report) -> bool {
    report
        .binary_structure
        .packer_analysis
        .oep_candidate_summary
        .as_ref()
        .map(|oep| oep.score >= 35)
        .unwrap_or(false)
}

fn benign_context_count(report: &Report) -> usize {
    report.global_analysis.benign_contexts.len()
}

fn has_high_impact_capability(report: &Report) -> bool {
    report
        .global_analysis
        .capabilities
        .iter()
        .any(|c| is_high_impact_capability(&c.name))
}

fn count_high_conf_high_impact_capabilities(report: &Report) -> usize {
    let calibrated = calibrate_capability_confidence(report);

    calibrated
        .iter()
        .filter(|c| c.calibrated_confidence == "high" && is_high_impact_capability(&c.name))
        .count()
}

pub fn validate_minimum_contract(report: &Report) -> SchemaValidation {
    let checked_fields = vec![
        "sample.name".to_string(),
        "summary.overall_score".to_string(),
        "summary.risk_level".to_string(),
        "summary.contract_version".to_string(),
        "global_analysis.capabilities".to_string(),
        "function_analysis.top_functions".to_string(),
        "binary_structure.packer_analysis".to_string(),
    ];

    let mut missing_fields = Vec::new();

    if report.sample.name.trim().is_empty() {
        missing_fields.push("sample.name".to_string());
    }
    if report.summary.risk_level.trim().is_empty() {
        missing_fields.push("summary.risk_level".to_string());
    }
    if report.summary.contract_version.trim().is_empty() {
        missing_fields.push("summary.contract_version".to_string());
    }

    SchemaValidation {
        valid_minimum_contract: missing_fields.is_empty(),
        checked_fields,
        missing_fields,
    }
}

pub fn build_rust_enrichment(report: &Report) -> RustEnrichment {
    let rules_dir = resolve_rules_dir(report);
    let loaded_rules = load_rules_from_dir(&rules_dir);

    let schema_validation = validate_minimum_contract(report);
    let (calibrated_score, rationale, score_drivers) =
        calibrate_score(report, &loaded_rules.score_rules);

    let capability_confidence = calibrate_capability_confidence(report);
    let derived_capabilities =
        derive_capabilities(report, &capability_confidence, &loaded_rules.derived_capability_rules);

    let malware_risk = compute_malware_risk(report, calibrated_score);
    let packing_risk = compute_packing_risk(report);

    let mut confidence_notes = Vec::new();
    let mut risk_annotations = Vec::new();
    let mut manual_review_reasons = Vec::new();

    let original_band = score_to_band(report.summary.overall_score);
    let calibrated_band = score_to_band(calibrated_score);

    let benign_contexts = benign_context_count(report);
    let has_hi_cap = has_high_impact_capability(report);
    let high_conf_high_impact_caps = count_high_conf_high_impact_capabilities(report);
    let high_risk_top_functions = count_high_risk_top_functions(report);
    let reasoned_top_functions = count_reasoned_top_functions(report);

    if report.binary_structure.packer_analysis.likely_packed {
        push_unique(
            &mut risk_annotations,
            "sample appears packed; static findings may underrepresent real behavior".to_string(),
        );
        push_unique(
            &mut confidence_notes,
            "packing reduces confidence in complete static visibility".to_string(),
        );
        push_unique(
            &mut manual_review_reasons,
            "sample is likely packed, so visible behavior may reflect only a loader or unpacking stub".to_string(),
        );
    }

    if report.binary_structure.packer_analysis.high_entropy_executable_count > 0 {
        push_unique(
            &mut risk_annotations,
            "high-entropy executable sections reinforce a packing or stub-dominated interpretation".to_string(),
        );
    }

    if let Some(ref oep) = report.binary_structure.packer_analysis.oep_candidate_summary {
        push_unique(
            &mut risk_annotations,
            format!(
                "top OEP candidate suggests a likely handoff target at {} in section {}",
                oep.address, oep.section
            ),
        );
    }

    if report
        .global_analysis
        .capabilities
        .iter()
        .any(|c| c.name == "process_injection")
    {
        push_unique(
            &mut risk_annotations,
            "process injection signals are present and materially significant".to_string(),
        );
        push_unique(
            &mut confidence_notes,
            "process injection is a high-impact capability with strong triage relevance".to_string(),
        );
        push_unique(
            &mut manual_review_reasons,
            "process injection indicators deserve manual validation because they materially affect severity".to_string(),
        );
    }

    if !derived_capabilities.is_empty() {
        push_unique(
            &mut confidence_notes,
            "derived capability combinations strengthen behavioral interpretation".to_string(),
        );
        push_unique(
            &mut manual_review_reasons,
            "derived capability combinations should be reviewed to validate the behavioral narrative".to_string(),
        );
    }

    if let Some(top_fn) = report.function_analysis.top_functions.first() {
        if !top_fn.primary_reason.trim().is_empty() {
            push_unique(
                &mut confidence_notes,
                format!(
                    "top function '{}' includes explicit reasoning: {}",
                    top_fn.name, top_fn.primary_reason
                ),
            );
        } else if !top_fn.reason_summary.trim().is_empty() {
            push_unique(
                &mut confidence_notes,
                format!(
                    "top function '{}' includes explicit reasoning: {}",
                    top_fn.name, top_fn.reason_summary
                ),
            );
        }
    }

    if benign_contexts >= 2 {
        push_unique(
            &mut confidence_notes,
            format!(
                "raw report already contains {} benign-context adjustments",
                benign_contexts
            ),
        );
    }

    if report.summary.risk_level == "critical" && calibrated_score >= report.summary.overall_score {
        push_unique(
            &mut risk_annotations,
            "critical classification is reinforced by calibrated scoring".to_string(),
        );
    }

    if !schema_validation.valid_minimum_contract {
        push_unique(
            &mut confidence_notes,
            "minimum contract validation failed; enrichment should be interpreted cautiously".to_string(),
        );
        push_unique(
            &mut manual_review_reasons,
            "report is missing minimum contract fields required for stronger automation confidence".to_string(),
        );
    }

    if loaded_rules.using_defaults {
        push_unique(
            &mut confidence_notes,
            "one or more Rust rule files were unavailable or invalid, so fallback defaults were used".to_string(),
        );
    }

    let malicious_signal_strength = if benign_contexts >= 2 && !has_hi_cap && malware_risk.score < 65 {
        "low".to_string()
    } else if malware_risk.score >= 120
        || high_conf_high_impact_caps >= 1
        || (report
            .global_analysis
            .capabilities
            .iter()
            .any(|c| c.name == "process_injection")
            && high_risk_top_functions >= 1)
    {
        "high".to_string()
    } else if malware_risk.score >= 60 || high_conf_high_impact_caps >= 1 {
        "medium".to_string()
    } else {
        "low".to_string()
    };

    let analysis_confidence = if !schema_validation.valid_minimum_contract {
        "low".to_string()
    } else if report.binary_structure.packer_analysis.likely_packed && reasoned_top_functions == 0 {
        "low".to_string()
    } else if report.binary_structure.packer_analysis.likely_packed {
        "medium".to_string()
    } else if high_conf_high_impact_caps > 0 || reasoned_top_functions >= 2 || high_risk_top_functions >= 2 {
        "high".to_string()
    } else {
        "medium".to_string()
    };

    let needs_manual_review = report.binary_structure.packer_analysis.likely_packed
        || (calibrated_band == "critical" && has_hi_cap)
        || malware_risk.level == "high"
        || malware_risk.level == "critical"
        || !derived_capabilities.is_empty()
        || !schema_validation.valid_minimum_contract
        || has_high_scoring_oep_candidate(report);

    let manual_review_priority = if (report.binary_structure.packer_analysis.likely_packed
        && malware_risk.level == "high")
        || malware_risk.level == "critical"
        || (calibrated_band == "critical" && has_hi_cap)
        || (packing_risk.level == "high" && has_high_scoring_oep_candidate(report))
    {
        "high".to_string()
    } else if needs_manual_review {
        "medium".to_string()
    } else {
        "low".to_string()
    };

    let derived_names: Vec<String> = derived_capabilities.iter().map(|d| d.name.clone()).collect();

    let primary_assessment = if benign_contexts >= 2 && !has_hi_cap && malware_risk.score < 65 {
        "sample contains mixed signals with meaningful benign context and should be interpreted conservatively".to_string()
    } else if packing_risk.score >= malware_risk.score + 25 && malware_risk.score < 85 {
        "sample shows stronger packing or obfuscation signals than directly observable malicious behavior".to_string()
    } else if derived_names.iter().any(|x| x == "in_memory_loader") {
        "sample shows materially suspicious staged or memory-resident execution characteristics under static triage".to_string()
    } else if malware_risk.level == "critical" || malware_risk.level == "high" {
        "sample shows materially suspicious malware-oriented behavior under static triage".to_string()
    } else if packing_risk.level == "high" {
        "sample is primarily notable for strong packing or obfuscation indicators that limit static interpretation".to_string()
    } else {
        "sample contains limited or mixed signals and should be interpreted conservatively".to_string()
    };

    let dominant_risk = if benign_contexts >= 2 && !has_hi_cap && malware_risk.score < 65 && packing_risk.score < 65 {
        "balanced".to_string()
    } else if malware_risk.score < 35 && packing_risk.score < 35 {
        "low_signal".to_string()
    } else if packing_risk.score > malware_risk.score + 10 {
        "packing".to_string()
    } else if malware_risk.score > packing_risk.score + 10 {
        "malware".to_string()
    } else {
        "balanced".to_string()
    };

    let interpretation = match dominant_risk.as_str() {
        "low_signal" => {
            "both malware-oriented and packing-oriented signals remain weak under current static triage"
                .to_string()
        }
        "packing" => {
            "packing-oriented risk dominates, so the binary may require unpacking or deeper manual reversing before final judgement"
                .to_string()
        }
        "malware" => {
            "malware-oriented risk dominates, so the currently visible static indicators are already materially suspicious"
                .to_string()
        }
        _ => {
            "malware and packing signals should be balanced against the benign context already visible in the raw report"
                .to_string()
        }
    };

    RustEnrichment {
        engine_metadata: EngineMetadata {
            engine_name: "rust_engine".to_string(),
            engine_version: "0.6.0".to_string(),
            input_contract_version: report.summary.contract_version.clone(),
        },
        rules_metadata: RulesMetadata {
            rules_dir: loaded_rules.rules_dir.clone(),
            score_rules_loaded: loaded_rules.score_rules_loaded,
            derived_rules_loaded: loaded_rules.derived_rules_loaded,
            using_defaults: loaded_rules.using_defaults,
            load_errors: loaded_rules.load_errors.clone(),
        },
        schema_validation,
        score_calibration: ScoreCalibration {
            original_score: report.summary.overall_score,
            calibrated_score,
            delta: calibrated_score - report.summary.overall_score,
            rationale,
        },
        capability_confidence,
        derived_capabilities,
        confidence_notes,
        score_bands: ScoreBands {
            original_band,
            calibrated_band,
        },
        decision_summary: DecisionSummary {
            malicious_signal_strength,
            analysis_confidence,
            needs_manual_review,
            primary_assessment,
            manual_review_priority,
        },
        risk_annotations,
        malware_risk,
        packing_risk,
        risk_split_summary: RiskSplitSummary {
            dominant_risk,
            interpretation,
        },
        score_drivers,
        manual_review_reasons,
    }
}

fn resolve_rules_dir(report: &Report) -> String {
    if let Some(dir) = report
        .analysis_metadata
        .get("rules_metadata")
        .and_then(|v| v.get("rules_dir"))
        .and_then(|v| v.as_str())
    {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    "../rules".to_string()
}