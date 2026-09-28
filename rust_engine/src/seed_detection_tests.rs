//! Seed-stage integration tests using actual bundled rules and a mixed graph fixture.
use crate::schema::{build_seed_id, Report, SeedCandidate, SeedEvidence, SeedTriggerFamily};
use crate::seed_detection::{detect_seed_candidates, detect_seeds, detect_seeds_from_report};
use crate::seed_limits::{SeedDetectionConfig, SeedDetectionResult, SeedTruncationReason};
use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules, SeedRulesConfig};
use serde_json::{json, Value};

fn graph() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap()
}

fn rules() -> SeedRulesConfig {
    load_seed_rules(bundled_seed_rules_path()).unwrap()
}

fn run(graph: &Value, max_seeds: Option<usize>) -> SeedDetectionResult {
    let result = detect_seeds(graph, &rules(), &SeedDetectionConfig { max_seeds }).unwrap();
    result.validate().unwrap();
    result
}

fn check_single_trigger(id: &str, family: SeedTriggerFamily, kind: &str, count: usize) {
    let mut config = rules();
    config.rules.retain(|rule| rule.id == id);
    let candidates = detect_seed_candidates(&graph(), &config).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].trigger_id, id);
    assert_eq!(candidates[0].family, family);
    assert_eq!(candidates[0].evidence.len(), count);
    assert!(candidates[0].evidence.iter().any(|e| e.kind == kind));
    let result = detect_seeds(&graph(), &config, &SeedDetectionConfig::default()).unwrap();
    assert_eq!(result.total_detected, 1);
    assert_eq!(result.returned, 1);
    assert!(!result.truncated);
    assert_eq!(result.seeds[0].families, vec![family]);
    assert_eq!(
        result.seeds[0].source_candidate_ids,
        vec![candidates[0].seed_id.clone()]
    );
}

#[test]
fn single_api_trigger_through_complete_seed_stage() {
    check_single_trigger(
        "api.virtualalloc",
        SeedTriggerFamily::MemoryManagement,
        "api",
        2,
    );
}

#[test]
fn string_category_trigger_through_complete_seed_stage() {
    check_single_trigger(
        "string_category.powershell",
        SeedTriggerFamily::CommandExecution,
        "string",
        2,
    );
}

#[test]
fn constant_trigger_through_complete_seed_stage() {
    check_single_trigger(
        "constant_category.memory_protection",
        SeedTriggerFamily::MemoryManagement,
        "constant",
        1,
    );
}

#[test]
fn section_trigger_through_complete_seed_stage() {
    check_single_trigger(
        "section_property.suspicious",
        SeedTriggerFamily::SectionContext,
        "section",
        1,
    );
}

#[test]
fn visibility_trigger_through_complete_seed_stage() {
    check_single_trigger(
        "visibility_signal.indirect_call",
        SeedTriggerFamily::CallVisibility,
        "visibility_signal",
        2,
    );
}

#[test]
fn unresolved_trigger_through_complete_seed_stage() {
    check_single_trigger(
        "unresolved_call.present",
        SeedTriggerFamily::CallVisibility,
        "unresolved_call",
        1,
    );
}

#[test]
fn no_observed_edges_or_calls_yields_no_seed() {
    let mut input = graph();
    input["edges"] = json!([]);
    input["unresolved_calls"] = json!([]);
    let result = run(&input, None);
    assert!(result.seeds.is_empty());
    assert_eq!(
        (result.total_detected, result.returned, result.truncated),
        (0, 0, false)
    );
    assert_eq!(result.truncation_reason, None);
    assert!(run(
        &json!({"nodes": [], "edges": [], "unresolved_calls": []}),
        None
    )
    .seeds
    .is_empty());
}

#[test]
fn mixed_triggers_consolidate_by_anchor_with_complete_provenance() {
    let input = graph();
    let candidates = detect_seed_candidates(&input, &rules()).unwrap();
    assert_eq!(candidates.len(), 7);
    let result = run(&input, None);
    assert_eq!(result.seeds.len(), 2);
    let first = &result.seeds[0];
    assert_eq!(first.anchor_function_id, "fn:00401000");
    assert_eq!(
        first.trigger_ids,
        vec![
            "api.virtualalloc",
            "constant_category.memory_protection",
            "section_property.suspicious",
            "string_category.powershell",
            "unresolved_call.present",
            "visibility_signal.indirect_call"
        ]
    );
    assert_eq!(first.evidence.len(), 9);
    assert_eq!(first.reasons.len(), 6);
    assert_eq!(
        first.families,
        vec![
            SeedTriggerFamily::MemoryManagement,
            SeedTriggerFamily::CommandExecution,
            SeedTriggerFamily::SectionContext,
            SeedTriggerFamily::CallVisibility
        ]
    );
    for candidate in candidates
        .iter()
        .filter(|c| c.anchor_function_id == first.anchor_function_id)
    {
        assert!(first.source_candidate_ids.contains(&candidate.seed_id));
        assert!(first.reasons.contains(&candidate.reason));
        for evidence in &candidate.evidence {
            assert!(first.evidence.contains(evidence));
        }
    }
    assert_eq!(
        result.seeds[1].families,
        vec![SeedTriggerFamily::ProcessMemoryAccess]
    );
}

#[test]
fn duplicate_graph_edges_callsites_and_unresolved_records_do_not_change_output() {
    let mut input = graph();
    let expected = run(&input, None);
    for edge in input["edges"].as_array_mut().unwrap() {
        for key in ["callsites", "reference_sites", "use_sites"] {
            if let Some(values) = edge.get_mut(key).and_then(Value::as_array_mut) {
                values.extend(values.clone());
            }
        }
    }
    for key in ["edges", "unresolved_calls"] {
        let entries = input[key].as_array_mut().unwrap();
        entries.extend(entries.clone());
    }
    assert_eq!(expected, run(&input, None));
}

#[test]
fn graph_and_rule_permutations_produce_byte_identical_full_and_limited_json() {
    let original = graph();
    for limit in [None, Some(0), Some(1), Some(2)] {
        let config = SeedDetectionConfig { max_seeds: limit };
        let expected = serde_json::to_vec(&run(&original, limit)).unwrap();
        for shift in 0..12 {
            let mut input = original.clone();
            for key in ["nodes", "edges", "unresolved_calls"] {
                let entries = input[key].as_array_mut().unwrap();
                let len = entries.len();
                entries.rotate_left(shift % len);
                if shift % 2 == 0 {
                    entries.reverse();
                }
                for entry in entries {
                    for value in entry.as_object_mut().unwrap().values_mut() {
                        if let Some(values) = value.as_array_mut() {
                            values.reverse();
                        }
                    }
                }
            }
            let mut config_rules = rules();
            config_rules.rules.rotate_left(shift);
            config_rules.rules.reverse();
            let result = detect_seeds(&input, &config_rules, &config).unwrap();
            assert_eq!(
                expected,
                serde_json::to_vec(&result).unwrap(),
                "limit {limit:?}, permutation {shift}"
            );
        }
    }
}

#[test]
fn seed_ids_are_stable_and_independent_of_provenance_order() {
    let candidates = detect_seed_candidates(&graph(), &rules()).unwrap();
    assert_eq!(candidates[0].seed_id, "seed:fn:00401000:api.virtualalloc");
    for candidate in candidates {
        assert_eq!(
            candidate.seed_id,
            build_seed_id(&candidate.anchor_function_id, &candidate.trigger_id).unwrap()
        );
    }
    let result = run(&graph(), None);
    assert_eq!(
        result
            .seeds
            .iter()
            .map(|s| s.seed_id.as_str())
            .collect::<Vec<_>>(),
        vec!["seed:fn:00401000", "seed:fn:00402000"]
    );
    assert_eq!(
        run(&graph(), Some(1)).seeds[0].seed_id,
        result.seeds[0].seed_id
    );
}

#[test]
fn unknown_callsites_and_distinct_unresolved_reasons_remain_provenance() {
    let mut input = graph();
    input["edges"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type": "calls_api", "source": "fn:00401000", "target": "api:virtualalloc"}));
    let mut unresolved = input["unresolved_calls"][0].clone();
    unresolved["reason"] = json!("target_not_in_program");
    input["unresolved_calls"]
        .as_array_mut()
        .unwrap()
        .push(unresolved.clone());
    unresolved["callsite"] = Value::Null;
    input["unresolved_calls"]
        .as_array_mut()
        .unwrap()
        .push(unresolved);
    let result = run(&input, None);
    let evidence = &result.seeds[0].evidence;
    assert!(evidence
        .iter()
        .any(|e| e.kind == "api" && e.callsite.is_none()));
    let unresolved: Vec<_> = evidence
        .iter()
        .filter(|e| e.kind == "unresolved_call")
        .collect();
    assert_eq!(unresolved.len(), 3);
    assert!(unresolved
        .iter()
        .all(|e| e.node_id.is_none() && e.edge_type.is_none()));
    assert!(unresolved.iter().any(|e| e.callsite.is_none()));
    assert!(unresolved
        .iter()
        .any(|e| e.value == "no_resolved_function_or_api_target"));
}

#[test]
fn truncation_is_applied_after_all_observations_for_returned_anchor() {
    let full = run(&graph(), None);
    let limited = run(&graph(), Some(1));
    assert_eq!((limited.total_detected, limited.returned), (2, 1));
    assert_eq!(limited.seeds, full.seeds[..1]);
    assert_eq!(
        limited.truncation_reason,
        Some(SeedTruncationReason::MaxSeeds)
    );
    assert!(!run(&graph(), Some(2)).truncated);
    assert!(run(&graph(), Some(0)).truncated);
}

fn assert_score_free(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    ![
                        "score",
                        "priority",
                        "minimum_priority",
                        "confidence",
                        "maliciousness_confidence",
                        "maliciousness",
                        "risk_level",
                        "function_score",
                        "legacy_metadata",
                        "verdict"
                    ]
                    .contains(&key.as_str()),
                    "forbidden field: {key}"
                );
                assert_score_free(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_score_free(value);
            }
        }
        _ => {}
    }
}

#[test]
fn all_seed_contracts_are_recursively_score_free_and_legacy_scores_are_ignored() {
    let input = graph();
    assert_score_free(
        &serde_json::to_value(detect_seed_candidates(&input, &rules()).unwrap()).unwrap(),
    );
    let expected = run(&input, Some(1));
    assert_score_free(&serde_json::to_value(&expected).unwrap());
    for score in [0, 99999] {
        let report: Report = serde_json::from_value(json!({
            "typed_graph": input,
            "summary": {"overall_score": score, "risk_level": "ignored"},
            "behavior_analysis": {"priority": score, "maliciousness_confidence": 1},
            "rule_contract": {"api_weights": {"VirtualAlloc": score}}
        }))
        .unwrap();
        assert_eq!(
            expected,
            detect_seeds_from_report(
                &report,
                &rules(),
                &SeedDetectionConfig { max_seeds: Some(1) }
            )
            .unwrap()
        );
    }
}

#[test]
fn scoring_fields_cannot_be_deserialized_into_seed_stage_contracts() {
    let candidate = detect_seed_candidates(&graph(), &rules())
        .unwrap()
        .remove(0);
    let result = run(&graph(), None);
    for key in [
        "score",
        "priority",
        "maliciousness_confidence",
        "minimum_priority",
    ] {
        let mut value = serde_json::to_value(&candidate).unwrap();
        value[key] = json!(1);
        assert!(serde_json::from_value::<SeedCandidate>(value).is_err());
        let mut value = serde_json::to_value(&candidate.evidence[0]).unwrap();
        value[key] = json!(1);
        assert!(serde_json::from_value::<SeedEvidence>(value).is_err());
        let mut value = serde_json::to_value(&result).unwrap();
        value[key] = json!(1);
        assert!(serde_json::from_value::<SeedDetectionResult>(value).is_err());
        let mut value = serde_json::to_value(&result.seeds[0]).unwrap();
        value[key] = json!(1);
        assert!(serde_json::from_value::<crate::schema::ConsolidatedSeed>(value).is_err());
    }
}

#[test]
fn malformed_graph_is_rejected_even_when_no_seeds_are_requested() {
    let config = SeedDetectionConfig { max_seeds: Some(0) };
    for input in [
        Value::Null,
        json!({}),
        json!({"nodes": {}, "edges": [], "unresolved_calls": []}),
    ] {
        assert!(detect_seeds(&input, &rules(), &config).is_err());
    }
    let mut input = graph();
    input["edges"][0]["source"] = json!("fn:missing");
    assert!(detect_seeds(&input, &rules(), &config).is_err());
    assert!(detect_seeds_from_report(&Report::default(), &rules(), &config).is_err());
}

#[test]
fn result_validation_rejects_duplicate_anchors_and_noncanonical_evidence() {
    let original = run(&graph(), None);
    let mut invalid = original.clone();
    invalid.seeds[1] = invalid.seeds[0].clone();
    assert!(invalid.validate().is_err());
    invalid = original.clone();
    invalid.seeds[0].evidence.reverse();
    assert!(invalid.validate().is_err());
    invalid = original;
    let repeated = invalid.seeds[0].evidence[0].clone();
    invalid.seeds[0].evidence.push(repeated);
    assert!(invalid.validate().is_err());
}
