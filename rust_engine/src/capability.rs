use crate::schema::{CapabilityConfidence, DerivedCapability, Report};

pub fn calibrate_capability_confidence(report: &Report) -> Vec<CapabilityConfidence> {
    let mut output = Vec::new();

    for cap in &report.global_analysis.capabilities {
        let mut calibrated = cap.confidence.clone();
        let mut rationale = Vec::new();

        if cap.match_count >= cap.min_matches + 2 {
            calibrated = "high".to_string();
            rationale.push("match count exceeds minimum threshold by a strong margin".to_string());
        }

        let supporting_functions = report
            .function_analysis
            .functions
            .iter()
            .filter(|f| f.matched_capabilities.iter().any(|x| x == &cap.name))
            .count();

        if supporting_functions >= 2 {
            calibrated = "high".to_string();
            rationale.push("multiple functions locally support this capability".to_string());
        } else if supporting_functions == 1 && calibrated == "low" {
            calibrated = "medium".to_string();
            rationale.push("one function locally supports this capability".to_string());
        }

        if report.binary_structure.packer_analysis.likely_packed && cap.name != "process_injection" {
            rationale.push("sample appears packed, so static capability confidence should be interpreted cautiously".to_string());
        }

        output.push(CapabilityConfidence {
            name: cap.name.clone(),
            base_confidence: cap.confidence.clone(),
            calibrated_confidence: calibrated,
            rationale,
        });
    }

    output
}

pub fn derive_capabilities(report: &Report) -> Vec<DerivedCapability> {
    let mut derived = Vec::new();

    let capability_names: Vec<String> = report
        .global_analysis
        .capabilities
        .iter()
        .map(|c| c.name.clone())
        .collect();

    let has_process_injection = capability_names.iter().any(|x| x == "process_injection");
    let has_dynamic_loading = capability_names.iter().any(|x| x == "dynamic_loading");
    let has_networking = capability_names.iter().any(|x| x == "networking");
    let has_persistence = capability_names.iter().any(|x| x == "persistence");
    let has_anti_analysis = capability_names.iter().any(|x| x == "anti_analysis");

    if has_process_injection && has_dynamic_loading {
        derived.push(DerivedCapability {
            name: "in_memory_loader".to_string(),
            confidence: "high".to_string(),
            rationale: vec![
                "process injection and dynamic loading are both present".to_string(),
                "this combination is consistent with staged or memory-resident execution".to_string(),
            ],
        });
    }

    if has_networking && has_persistence {
        derived.push(DerivedCapability {
            name: "persistent_networked_payload".to_string(),
            confidence: "medium".to_string(),
            rationale: vec![
                "networking and persistence signals are both present".to_string(),
            ],
        });
    }

    if has_anti_analysis && has_process_injection {
        derived.push(DerivedCapability {
            name: "evasion_aware_injector".to_string(),
            confidence: "medium".to_string(),
            rationale: vec![
                "anti-analysis and process injection signals co-occur".to_string(),
            ],
        });
    }

    derived
}