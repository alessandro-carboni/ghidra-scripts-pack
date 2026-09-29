//! Step 4.13 acceptance tests for the complete local-subgraph stage.
use crate::graph::{NodeType, TypedGraph};
use crate::graph_indexes::GraphIndexes;
use crate::local_subgraph::{
    extract_local_subgraph, LocalExtractionConfig, LocalGraphLimitKind, TruncationReason,
};
use crate::local_subgraph_schema::LocalSubgraphDocument;
use crate::schema::ConsolidatedSeed;
use crate::seed_detection::detect_seeds;
use crate::seed_limits::SeedDetectionConfig;
use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn rules() -> crate::seed_rules::SeedRulesConfig {
    load_seed_rules(bundled_seed_rules_path()).unwrap()
}

fn seed_for(value: &Value) -> ConsolidatedSeed {
    detect_seeds(value, &rules(), &SeedDetectionConfig::default())
        .unwrap()
        .seeds
        .into_iter()
        .find(|seed| seed.anchor_function_id == "fn:a")
        .unwrap()
}

fn topology_fixture(calls: &[(&str, &str)]) -> (TypedGraph, ConsolidatedSeed) {
    let nodes: Vec<Value> = ["a", "b", "c", "d", "e"]
        .into_iter()
        .map(|id| json!({"id": format!("fn:{id}"), "type": "FUNCTION"}))
        .chain(std::iter::once(json!({
            "id": "api:virtualalloc",
            "type": "API",
            "normalized_name": "VirtualAlloc",
            "original_names": ["VirtualAlloc"]
        })))
        .collect();
    let mut edges: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(i, (source, target))| {
            json!({
                "type": "calls_function",
                "source": format!("fn:{source}"),
                "target": format!("fn:{target}"),
                "callsites": [format!("{:08x}", i + 1)]
            })
        })
        .collect();
    edges.push(json!({
        "type": "calls_api",
        "source": "fn:a",
        "target": "api:virtualalloc",
        "callsites": ["00001000"]
    }));
    let value = json!({
        "model_version": "0.12.0",
        "metadata": {},
        "nodes": nodes,
        "edges": edges,
        "unresolved_calls": []
    });
    let seed = seed_for(&value);
    (TypedGraph::from_value(&value).unwrap(), seed)
}

fn mixed_fixture() -> (TypedGraph, ConsolidatedSeed, Value) {
    let value: Value =
        serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
    let graph = TypedGraph::from_value(&value).unwrap();
    let seed = detect_seeds(&value, &rules(), &SeedDetectionConfig::default())
        .unwrap()
        .seeds
        .remove(0);
    (graph, seed, value)
}

#[test]
fn step_4_13_depth_zero_keeps_anchor_and_its_evidence() {
    let (graph, seed, _) = mixed_fixture();
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig {
            caller_depth: 0,
            callee_depth: 0,
            ..LocalExtractionConfig::default()
        },
    )
    .unwrap();
    assert_eq!(
        local.selection.function_ids,
        BTreeSet::from([seed.anchor_function_id.clone()])
    );
    assert!(
        local.nodes.len() > 1,
        "anchor evidence must still be attached"
    );
}

#[test]
fn step_4_13_caller_traversal_respects_requested_depth() {
    let (graph, seed) = topology_fixture(&[("b", "a"), ("c", "b"), ("d", "c")]);
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig {
            caller_depth: 2,
            callee_depth: 0,
            ..LocalExtractionConfig::default()
        },
    )
    .unwrap();
    assert_eq!(
        local.selection.function_ids,
        BTreeSet::from(["fn:a".into(), "fn:b".into(), "fn:c".into()])
    );
    assert_eq!(local.selection.caller_distances["fn:c"], 2);
}

#[test]
fn step_4_13_callee_traversal_respects_requested_depth() {
    let (graph, seed) = topology_fixture(&[("a", "b"), ("b", "c"), ("c", "d")]);
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig {
            caller_depth: 0,
            callee_depth: 2,
            ..LocalExtractionConfig::default()
        },
    )
    .unwrap();
    assert_eq!(
        local.selection.function_ids,
        BTreeSet::from(["fn:a".into(), "fn:b".into(), "fn:c".into()])
    );
    assert_eq!(local.selection.callee_distances["fn:c"], 2);
}

#[test]
fn step_4_13_cycles_and_self_loops_terminate_without_duplicate_functions() {
    let (graph, seed) =
        topology_fixture(&[("a", "a"), ("a", "b"), ("b", "c"), ("c", "a"), ("b", "b")]);
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig {
            caller_depth: 4,
            callee_depth: 4,
            ..LocalExtractionConfig::default()
        },
    )
    .unwrap();
    assert_eq!(local.selection.function_ids.len(), 3);
    assert!(local.selection.function_ids.contains("fn:a"));
    assert!(local.selection.function_ids.contains("fn:b"));
    assert!(local.selection.function_ids.contains("fn:c"));
}

#[test]
fn step_4_13_evidence_inclusion_preserves_all_six_evidence_types() {
    let (graph, seed, _) = mixed_fixture();
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig {
            caller_depth: 0,
            callee_depth: 0,
            ..LocalExtractionConfig::default()
        },
    )
    .unwrap();
    let kinds: BTreeSet<NodeType> = local.nodes.iter().map(|node| node.node_type).collect();
    for expected in [
        NodeType::Api,
        NodeType::String,
        NodeType::StringCategory,
        NodeType::Constant,
        NodeType::Section,
        NodeType::VisibilityIndicator,
    ] {
        assert!(
            kinds.contains(&expected),
            "missing evidence type {expected:?}"
        );
    }
}

#[test]
fn step_4_13_unresolved_evidence_is_local_and_has_no_fake_target() {
    let (graph, seed, _) = mixed_fixture();
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig::default(),
    )
    .unwrap();
    assert!(!local.unresolved_calls.is_empty());
    assert!(local
        .unresolved_calls
        .iter()
        .all(|call| call.callee.is_none() && call.unresolved));
    assert!(local
        .unresolved_calls
        .iter()
        .all(|call| local.selection.function_ids.contains(&call.caller)));
}

#[test]
fn step_4_13_duplicate_edges_and_unresolved_records_are_deduplicated() {
    let (_, seed, mut value) = mixed_fixture();
    let duplicate_edge = value["edges"][0].clone();
    value["edges"].as_array_mut().unwrap().push(duplicate_edge);
    let duplicate_unresolved = value["unresolved_calls"][0].clone();
    value["unresolved_calls"]
        .as_array_mut()
        .unwrap()
        .push(duplicate_unresolved);
    let graph = TypedGraph::from_value(&value).unwrap();
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig::default(),
    )
    .unwrap();
    assert_eq!(local.unresolved_calls.len(), 1);
    assert!(local.edges.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn step_4_13_deterministic_traversal_and_schema_ignore_input_order() {
    let (graph, seed, mut value) = mixed_fixture();
    let first = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig::default(),
    )
    .unwrap();
    let first_json = LocalSubgraphDocument::from_local(&first)
        .unwrap()
        .to_json_pretty()
        .unwrap();

    value["nodes"].as_array_mut().unwrap().reverse();
    value["edges"].as_array_mut().unwrap().reverse();
    value["unresolved_calls"].as_array_mut().unwrap().reverse();
    let permuted = TypedGraph::from_value(&value).unwrap();
    let second = extract_local_subgraph(
        &GraphIndexes::new(&permuted),
        &seed,
        &LocalExtractionConfig::default(),
    )
    .unwrap();
    let second_json = LocalSubgraphDocument::from_local(&second)
        .unwrap()
        .to_json_pretty()
        .unwrap();
    assert_eq!(first_json, second_json);
}

#[test]
fn step_4_13_size_limits_bound_functions_evidence_total_nodes_and_edges() {
    let (graph, seed, _) = mixed_fixture();
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig {
            caller_depth: 0,
            callee_depth: 0,
            max_function_nodes: Some(1),
            max_evidence_nodes: Some(2),
            max_total_nodes: Some(3),
            max_edges: Some(1),
        },
    )
    .unwrap();
    assert!(local.selection.function_ids.len() <= 1);
    assert!(local.nodes.len() <= 3);
    assert!(local.truncation.counts.evidence_nodes <= 2);
    assert!(local.edges.len() <= 1);
}

#[test]
fn step_4_13_truncation_metadata_names_reached_limits_depths_counts_and_reason() {
    let (graph, seed, _) = mixed_fixture();
    let config = LocalExtractionConfig {
        caller_depth: 0,
        callee_depth: 0,
        max_evidence_nodes: Some(1),
        max_edges: Some(0),
        ..LocalExtractionConfig::default()
    };
    let local = extract_local_subgraph(&GraphIndexes::new(&graph), &seed, &config).unwrap();
    assert!(local.truncation.truncated);
    assert_eq!(
        local.truncation.reason,
        Some(TruncationReason::ResourceLimit)
    );
    let reached: BTreeSet<LocalGraphLimitKind> = local
        .truncation
        .limits_reached
        .iter()
        .map(|limit| limit.kind)
        .collect();
    assert!(reached.contains(&LocalGraphLimitKind::EvidenceNodes));
    assert!(reached.contains(&LocalGraphLimitKind::Edges));
    assert_eq!(local.truncation.requested_depth.caller_depth, 0);
    assert_eq!(local.truncation.requested_depth.callee_depth, 0);
    assert_eq!(local.truncation.effective_depth.caller_depth, 0);
    assert_eq!(local.truncation.effective_depth.callee_depth, 0);
    assert_eq!(local.truncation.counts.total_nodes, local.nodes.len());
    assert_eq!(local.truncation.counts.edges, local.edges.len());
}

#[test]
fn step_4_13_invalid_seed_anchor_is_rejected_before_extraction() {
    let (graph, mut seed, _) = mixed_fixture();
    seed.anchor_function_id = "fn:missing".into();
    seed.seed_id = "seed:fn:missing".into();
    seed.source_candidate_ids = seed
        .trigger_ids
        .iter()
        .map(|trigger| format!("seed:fn:missing:{trigger}"))
        .collect();
    seed.validate().unwrap();
    assert!(extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig::default()
    )
    .is_err());
}

#[test]
fn step_4_13_schema_is_ready_for_gui_consumption() {
    let (graph, seed, _) = mixed_fixture();
    let local = extract_local_subgraph(
        &GraphIndexes::new(&graph),
        &seed,
        &LocalExtractionConfig::default(),
    )
    .unwrap();
    let document = LocalSubgraphDocument::from_local(&local).unwrap();
    let value: Value = serde_json::from_str(&document.to_json_pretty().unwrap()).unwrap();
    assert_eq!(value["seed_id"], json!(seed.seed_id));
    assert_eq!(value["anchor_function_id"], json!(seed.anchor_function_id));
    assert!(value["nodes"].is_array());
    assert!(value["edges"].is_array());
    assert!(value["unresolved_calls"].is_array());
    assert!(value["truncation"].is_object());
    assert!(value["extraction_config"].is_object());
}
