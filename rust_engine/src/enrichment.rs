use crate::capability::{calibrate_capability_confidence, derive_capabilities};
use crate::schema::{
    DecisionSummary, EngineMetadata, Report, RustEnrichment, SchemaValidation, ScoreBands,
    ScoreCalibration,
};
use crate::scoring::{calibrate_score, score_to_band};

pub fn validate_minimum_contract(report: &Report) -> SchemaValidation {
    let checked_fields = vec![
        "sample.name".to_string(),
        "summary.overall_score".to_string(),
        "summary.risk_level".to_string(),
        "global_analysis.capabilities".to_string(),
        "function_analysis.top_functions".to_string(),
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
    let schema_validation = validate_minimum_contract(report);
    let (calibrated_score, rationale) = calibrate_score(report);
    let capability_confidence = calibrate_capability_confidence(report);
    let derived_capabilities = derive_capabilities(report);

    let mut confidence_notes = Vec::new();
    let mut risk_annotations = Vec::new();

    let original_band = score_to_band(report.summary.overall_score);
    let calibrated_band = score_to_band(calibrated_score);

    let high_conf_caps = capability_confidence
        .iter()
        .filter(|c| c.calibrated_confidence == "high")
        .count();

    if report.binary_structure.packer_analysis.likely_packed {
        risk_annotations.push("sample appears packed; static findings may underrepresent real behavior".to_string());
        confidence_notes.push("packing reduces confidence in complete static visibility".to_string());
    }

    if report
        .global_analysis
        .capabilities
        .iter()
        .any(|c| c.name == "process_injection")
    {
        risk_annotations.push("process injection signals are present and materially significant".to_string());
        confidence_notes.push("process injection is a high-impact capability with strong triage relevance".to_string());
    }

    if !derived_capabilities.is_empty() {
        confidence_notes.push("derived capability combinations strengthen behavioral interpretation".to_string());
    }

    if report.summary.risk_level == "critical" && calibrated_score >= report.summary.overall_score {
        risk_annotations.push("critical classification is reinforced by calibrated scoring".to_string());
    }

    let malicious_signal_strength = if calibrated_score >= 120 || high_conf_caps >= 2 {
        "high".to_string()
    } else if calibrated_score >= 60 {
        "medium".to_string()
    } else {
        "low".to_string()
    };

    let analysis_confidence = if report.binary_structure.packer_analysis.likely_packed {
        "medium".to_string()
    } else if schema_validation.valid_minimum_contract && high_conf_caps > 0 {
        "high".to_string()
    } else if schema_validation.valid_minimum_contract {
        "medium".to_string()
    } else {
        "low".to_string()
    };

    let needs_manual_review = report.binary_structure.packer_analysis.likely_packed
        || calibrated_band == "critical"
        || !derived_capabilities.is_empty();

    RustEnrichment {
        engine_metadata: EngineMetadata {
            engine_name: "rust_engine".to_string(),
            engine_version: "0.2.0".to_string(),
            input_contract_version: report.summary.contract_version.clone(),
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
        },
        risk_annotations,
    }
}