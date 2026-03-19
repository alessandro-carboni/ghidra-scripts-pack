use crate::schema::Report;

pub fn calibrate_score(report: &Report) -> (i32, Vec<String>) {
    let mut calibrated = report.summary.overall_score;
    let mut rationale = Vec::new();

    let high_risk_top_functions = report
        .function_analysis
        .top_functions
        .iter()
        .filter(|f| f.risk_level == "high" || f.risk_level == "critical")
        .count() as i32;

    if high_risk_top_functions >= 2 {
        calibrated += 10;
        rationale.push("multiple high-risk top functions increased confidence in final score".to_string());
    }

    if report.binary_structure.packer_analysis.likely_packed {
        calibrated -= 10;
        rationale.push("packed sample reduced confidence in purely static score interpretation".to_string());
    }

    if report.global_analysis.capabilities.iter().any(|c| c.name == "process_injection") {
        calibrated += 15;
        rationale.push("process injection capability materially increases triage severity".to_string());
    }

    if report
        .global_analysis
        .interesting_strings
        .iter()
        .any(|s| !s.benign_hint && s.score >= 15)
    {
        calibrated += 5;
        rationale.push("high-signal interesting strings reinforce malicious interpretation".to_string());
    }

    if calibrated < 0 {
        calibrated = 0;
    }

    (calibrated, rationale)
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