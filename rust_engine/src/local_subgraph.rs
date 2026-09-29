//! Deterministic function traversal for local seed context. No ranking or scoring.
use crate::graph::{GraphEdge, GraphNode, UnresolvedCall};
use crate::graph_indexes::{edge_sort_key, GraphIndexes};
use crate::schema::ConsolidatedSeed;
use crate::seed_validation::validate_consolidated_seed;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalExtractionConfig {
    pub caller_depth: usize,
    pub callee_depth: usize,
}

impl Default for LocalExtractionConfig {
    fn default() -> Self {
        Self {
            caller_depth: 1,
            callee_depth: 2,
        }
    }
}

/// Internal selection, not the final versioned local-subgraph export contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSelection {
    pub anchor_function_id: String,
    pub function_ids: BTreeSet<String>,
    pub caller_distances: BTreeMap<String, usize>,
    pub callee_distances: BTreeMap<String, usize>,
}

pub fn select_seed_functions(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
    config: &LocalExtractionConfig,
) -> Result<FunctionSelection, String> {
    validate_consolidated_seed(index, seed)?;
    // Separate traversals from the anchor: no implicit caller->callee or callee->caller turns.
    let caller_distances = function_distances(
        index,
        &seed.anchor_function_id,
        Direction::Callers,
        config.caller_depth,
    );
    let callee_distances = function_distances(
        index,
        &seed.anchor_function_id,
        Direction::Callees,
        config.callee_depth,
    );
    Ok(FunctionSelection {
        anchor_function_id: seed.anchor_function_id.clone(),
        function_ids: caller_distances
            .keys()
            .chain(callee_distances.keys())
            .cloned()
            .collect(),
        caller_distances,
        callee_distances,
    })
}

/// Local context with observed unresolved records; never infer missing targets.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalSubgraph {
    pub seed_id: String,
    pub source_graph_version: String,
    pub config: LocalExtractionConfig,
    pub selection: FunctionSelection,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub unresolved_calls: Vec<UnresolvedCall>,
}

pub fn unresolved_sort_key(call: &UnresolvedCall) -> String {
    serde_json::to_string(call).expect("unresolved JSON attributes are serializable")
}

pub fn extract_local_subgraph(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
    config: &LocalExtractionConfig,
) -> Result<LocalSubgraph, String> {
    let selection = select_seed_functions(index, seed, config)?;
    let mut included = selection.function_ids.clone();
    for function in &selection.function_ids {
        included.extend(index.evidence(function).map(str::to_string));
    }
    let nodes = included
        .iter()
        .map(|id| {
            index
                .node(id)
                .cloned()
                .ok_or_else(|| format!("indexed node '{id}' disappeared"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut edges: Vec<_> = included
        .iter()
        .flat_map(|id| index.outgoing(id).iter().copied())
        .filter(|edge| included.contains(&edge.target))
        .cloned()
        .collect();
    edges.sort_by_cached_key(edge_sort_key);
    // Only identical records are duplicates. Different callsite/occurrence properties stay separate.
    edges.dedup();
    let mut unresolved_calls: Vec<_> = index
        .graph()
        .unresolved_calls()
        .iter()
        .filter(|call| selection.function_ids.contains(&call.caller))
        .cloned()
        .collect();
    unresolved_calls.sort_by_cached_key(unresolved_sort_key);
    unresolved_calls.dedup();
    Ok(LocalSubgraph {
        seed_id: seed.seed_id.clone(),
        source_graph_version: index.graph().model_version().into(),
        config: config.clone(),
        selection,
        nodes,
        edges,
        unresolved_calls,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Callers,
    Callees,
}

/// The anchor has distance zero. Only resolved FUNCTION call edges are traversed.
/// Sorted neighbors and a FIFO queue guarantee minimum hop distances and reproducibility.
pub fn seed_centered_bfs(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
    direction: Direction,
    max_depth: usize,
) -> Result<BTreeMap<String, usize>, String> {
    validate_consolidated_seed(index, seed)?;
    Ok(function_distances(
        index,
        &seed.anchor_function_id,
        direction,
        max_depth,
    ))
}

fn function_distances(
    index: &GraphIndexes<'_>,
    anchor: &str,
    direction: Direction,
    max_depth: usize,
) -> BTreeMap<String, usize> {
    let mut distances = BTreeMap::from([(anchor.to_string(), 0)]);
    let mut queue = VecDeque::from([(anchor.to_string(), 0)]);
    while let Some((function, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let neighbors: Vec<_> = match direction {
            Direction::Callers => index.callers(&function).collect(),
            Direction::Callees => index.callees(&function).collect(),
        };
        for next in neighbors {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                distances.entry(next.to_string())
            {
                entry.insert(depth + 1);
                queue.push_back((next.to_string(), depth + 1));
            }
        }
    }
    distances
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::TypedGraph;
    use crate::seed_detection::detect_seeds;
    use crate::seed_limits::SeedDetectionConfig;
    use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules};
    use serde_json::{json, Value};

    #[test]
    fn unresolved_records_are_local_complete_and_do_not_create_targets() {
        let (graph, seed) = mixed_fixture();
        let mut value = serde_json::to_value(&graph).unwrap();
        let mut unrelated = value["unresolved_calls"][0].clone();
        unrelated["caller"] = json!("fn:00402000");
        value["unresolved_calls"]
            .as_array_mut()
            .unwrap()
            .push(unrelated);
        let graph = TypedGraph::from_value(&value).unwrap();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        assert_eq!(
            local.unresolved_calls,
            vec![graph.unresolved_calls()[0].clone()]
        );
        assert!(local.unresolved_calls[0].callee.is_none());
        assert_eq!(local.nodes.len(), 7);
        assert_eq!(local.edges.len(), 6);
    }

    #[test]
    fn unresolved_dedup_keeps_different_callsites_reasons_and_attributes() {
        let (graph, seed) = mixed_fixture();
        let mut value = serde_json::to_value(&graph).unwrap();
        let original = value["unresolved_calls"][0].clone();
        let mut other = original.clone();
        other["reason"] = json!("other_observed_reason");
        let mut site = original.clone();
        site["callsite"] = json!("00401091");
        let mut attrs = original.clone();
        attrs["occurrences"] = json!(2);
        value["unresolved_calls"]
            .as_array_mut()
            .unwrap()
            .extend([original, other, site, attrs]);
        let first = TypedGraph::from_value(&value).unwrap();
        let expected = extract_local_subgraph(
            &GraphIndexes::new(&first),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        assert_eq!(expected.unresolved_calls.len(), 4);
        value["unresolved_calls"].as_array_mut().unwrap().reverse();
        let second = TypedGraph::from_value(&value).unwrap();
        assert_eq!(
            expected,
            extract_local_subgraph(
                &GraphIndexes::new(&second),
                &seed,
                &LocalExtractionConfig::default()
            )
            .unwrap()
        );
    }

    #[test]
    fn explicit_dynamic_dispatch_is_preserved_without_inference_or_extra_edges() {
        let (graph, seed) = mixed_fixture();
        let mut value = serde_json::to_value(&graph).unwrap();
        let visibility = value["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|n| n["type"] == "VISIBILITY_INDICATOR")
            .unwrap();
        visibility["signals"] = json!(["indirect_call", "dynamic_dispatch"]);
        visibility["dynamic_dispatch_callsites"] = json!(["00401070"]);
        visibility["dynamic_dispatch_targets"] = json!(["fn:00402000", "api:virtualalloc"]);
        visibility["dynamic_dispatch_recognition"] =
            json!("computed_call_with_multiple_resolved_targets");
        let graph = TypedGraph::from_value(&value).unwrap();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        let node = local
            .nodes
            .iter()
            .find(|n| n.node_type == crate::graph::NodeType::VisibilityIndicator)
            .unwrap();
        assert_eq!(
            node.properties["dynamic_dispatch_targets"],
            json!(["fn:00402000", "api:virtualalloc"])
        );
        assert!(!local.selection.function_ids.contains("fn:00402000"));
        assert_eq!(local.edges.len(), 6);
    }

    #[test]
    fn ordinary_indirect_visibility_does_not_become_dynamic_dispatch() {
        let (graph, seed) = mixed_fixture();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        let node = local
            .nodes
            .iter()
            .find(|n| n.node_type == crate::graph::NodeType::VisibilityIndicator)
            .unwrap();
        assert_eq!(node.properties["signals"], json!(["indirect_call"]));
        assert_eq!(node.properties["dynamic_dispatch_callsites"], json!([]));
    }

    fn fixture(calls: &[(&str, &str)]) -> (TypedGraph, ConsolidatedSeed) {
        let mut nodes: Vec<Value> = ["a", "b", "c", "d", "e", "z"]
            .into_iter()
            .map(|id| json!({"id": format!("fn:{id}"), "type": "FUNCTION"}))
            .collect();
        nodes.push(
            json!({"id": "api:virtualalloc", "type": "API", "normalized_name": "VirtualAlloc"}),
        );
        let mut edges: Vec<Value> = calls.iter().map(|(source, target)| json!({"type": "calls_function", "source": format!("fn:{source}"), "target": format!("fn:{target}"), "callsites": ["00000001"]})).collect();
        edges.push(json!({"type": "calls_api", "source": "fn:a", "target": "api:virtualalloc", "callsites": ["00000002"]}));
        let value = json!({"model_version": "0.12.0", "metadata": {}, "nodes": nodes, "edges": edges, "unresolved_calls": []});
        let seed = detect_seeds(
            &value,
            &load_seed_rules(bundled_seed_rules_path()).unwrap(),
            &SeedDetectionConfig::default(),
        )
        .unwrap()
        .seeds
        .remove(0);
        (TypedGraph::from_value(&value).unwrap(), seed)
    }

    #[test]
    fn zero_depth_keeps_only_anchor() {
        let (graph, seed) = fixture(&[("a", "b"), ("c", "a")]);
        let index = GraphIndexes::new(&graph);
        for direction in [Direction::Callers, Direction::Callees] {
            assert_eq!(
                seed_centered_bfs(&index, &seed, direction, 0).unwrap(),
                BTreeMap::from([("fn:a".into(), 0)])
            );
        }
    }

    #[test]
    fn default_caller_depth_records_only_direct_callers_and_anchor() {
        let (graph, seed) = fixture(&[("b", "a"), ("c", "b"), ("a", "d")]);
        let config: LocalExtractionConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.caller_depth, 1);
        let selected = select_seed_functions(&GraphIndexes::new(&graph), &seed, &config).unwrap();
        assert_eq!(
            selected
                .caller_distances
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["fn:a".into(), "fn:b".into()])
        );
        assert_eq!(selected.caller_distances["fn:b"], 1);
    }

    #[test]
    fn caller_depth_zero_one_and_two_have_exact_boundaries() {
        let (graph, seed) = fixture(&[("b", "a"), ("c", "b"), ("d", "c"), ("b", "e")]);
        for depth in 0..=2 {
            let selection = select_seed_functions(
                &GraphIndexes::new(&graph),
                &seed,
                &LocalExtractionConfig {
                    caller_depth: depth,
                    callee_depth: 0,
                },
            )
            .unwrap();
            assert_eq!(selection.function_ids.len(), depth + 1);
            assert!(!selection.function_ids.contains("fn:e"));
            assert!(!selection.function_ids.contains("fn:d"));
        }
    }

    #[test]
    fn caller_config_round_trip_and_invalid_settings() {
        let config = LocalExtractionConfig {
            caller_depth: 3,
            callee_depth: 0,
        };
        assert_eq!(
            serde_json::from_value::<LocalExtractionConfig>(serde_json::to_value(&config).unwrap())
                .unwrap(),
            config
        );
        for value in [
            json!({"caller_depth": -1}),
            json!({"caller_depth": 1.5}),
            json!({"caller_depth": "1"}),
            json!({"priority": 1}),
        ] {
            assert!(serde_json::from_value::<LocalExtractionConfig>(value).is_err());
        }
    }

    #[test]
    fn caller_selection_is_deterministic_with_parallel_calls_and_cycle() {
        let (graph, seed) = fixture(&[("b", "a"), ("b", "a"), ("c", "b"), ("a", "c")]);
        let config = LocalExtractionConfig {
            caller_depth: usize::MAX,
            callee_depth: 0,
        };
        let expected = select_seed_functions(&GraphIndexes::new(&graph), &seed, &config).unwrap();
        assert_eq!(expected.function_ids.len(), 3);
        let mut value = serde_json::to_value(&graph).unwrap();
        value["edges"].as_array_mut().unwrap().reverse();
        let graph = TypedGraph::from_value(&value).unwrap();
        assert_eq!(
            expected,
            select_seed_functions(&GraphIndexes::new(&graph), &seed, &config).unwrap()
        );
    }

    #[test]
    fn bfs_uses_minimum_distance_across_diamond_and_longer_path() {
        let (graph, seed) = fixture(&[
            ("a", "b"),
            ("a", "c"),
            ("b", "d"),
            ("c", "d"),
            ("a", "e"),
            ("e", "b"),
        ]);
        let distances =
            seed_centered_bfs(&GraphIndexes::new(&graph), &seed, Direction::Callees, 2).unwrap();
        assert_eq!(
            distances,
            BTreeMap::from([
                ("fn:a".into(), 0),
                ("fn:b".into(), 1),
                ("fn:c".into(), 1),
                ("fn:d".into(), 2),
                ("fn:e".into(), 1)
            ])
        );
    }

    #[test]
    fn cycles_self_loops_and_duplicate_edges_terminate_without_duplicate_functions() {
        let (graph, seed) = fixture(&[("a", "a"), ("a", "b"), ("a", "b"), ("b", "c"), ("c", "a")]);
        let distances = seed_centered_bfs(
            &GraphIndexes::new(&graph),
            &seed,
            Direction::Callees,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(distances.len(), 3);
        assert_eq!(distances["fn:a"], 0);
        assert_eq!(distances["fn:c"], 2);
    }

    #[test]
    fn bfs_direction_and_depth_do_not_cross_api_nodes() {
        let (graph, seed) = fixture(&[("b", "a"), ("c", "b"), ("a", "d")]);
        let index = GraphIndexes::new(&graph);
        assert_eq!(
            seed_centered_bfs(&index, &seed, Direction::Callers, 1)
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["fn:a", "fn:b"]
        );
        assert_eq!(
            seed_centered_bfs(&index, &seed, Direction::Callees, 1)
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["fn:a", "fn:d"]
        );
    }

    #[test]
    fn bfs_is_identical_after_node_and_edge_permutations() {
        let (graph, seed) = fixture(&[("a", "c"), ("a", "b"), ("b", "d"), ("c", "d")]);
        let expected =
            seed_centered_bfs(&GraphIndexes::new(&graph), &seed, Direction::Callees, 3).unwrap();
        let mut value = serde_json::to_value(&graph).unwrap();
        value["nodes"].as_array_mut().unwrap().reverse();
        value["edges"].as_array_mut().unwrap().reverse();
        let graph = TypedGraph::from_value(&value).unwrap();
        assert_eq!(
            expected,
            seed_centered_bfs(&GraphIndexes::new(&graph), &seed, Direction::Callees, 3).unwrap()
        );
    }

    #[test]
    fn bfs_validates_seed_before_even_zero_depth_traversal() {
        let (graph, mut seed) = fixture(&[]);
        seed.evidence[0].callsite = Some("unobserved".into());
        assert!(
            seed_centered_bfs(&GraphIndexes::new(&graph), &seed, Direction::Callees, 0).is_err()
        );
    }

    #[test]
    fn default_callee_depth_is_two_hops() {
        let (graph, seed) = fixture(&[("b", "a"), ("a", "c"), ("c", "d"), ("d", "e")]);
        let config: LocalExtractionConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            config,
            LocalExtractionConfig {
                caller_depth: 1,
                callee_depth: 2
            }
        );
        let selected = select_seed_functions(&GraphIndexes::new(&graph), &seed, &config).unwrap();
        assert_eq!(
            selected.function_ids,
            BTreeSet::from(["fn:a".into(), "fn:b".into(), "fn:c".into(), "fn:d".into()])
        );
        assert_eq!(selected.callee_distances["fn:d"], 2);
        assert!(!selected.callee_distances.contains_key("fn:b"));
    }

    #[test]
    fn callee_depth_zero_one_two_and_three_have_exact_boundaries() {
        let (graph, seed) = fixture(&[("a", "b"), ("b", "c"), ("c", "d")]);
        for depth in 0..=3 {
            let selected = select_seed_functions(
                &GraphIndexes::new(&graph),
                &seed,
                &LocalExtractionConfig {
                    caller_depth: 0,
                    callee_depth: depth,
                },
            )
            .unwrap();
            assert_eq!(selected.function_ids.len(), depth + 1);
            assert!(selected.callee_distances.values().all(|d| *d <= depth));
        }
        for value in [
            json!({"callee_depth": -1}),
            json!({"callee_depth": 0.5}),
            json!({"callee_depth": null}),
        ] {
            assert!(serde_json::from_value::<LocalExtractionConfig>(value).is_err());
        }
    }

    #[test]
    fn caller_and_callee_limits_do_not_expand_siblings_or_cocallers() {
        let (graph, seed) = fixture(&[("b", "a"), ("b", "e"), ("a", "c"), ("d", "c"), ("c", "z")]);
        let selected = select_seed_functions(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig {
                caller_depth: 1,
                callee_depth: 1,
            },
        )
        .unwrap();
        assert_eq!(
            selected.function_ids,
            BTreeSet::from(["fn:a".into(), "fn:b".into(), "fn:c".into()])
        );
    }

    #[test]
    fn overlapping_caller_and_callee_paths_keep_one_function_with_both_distances() {
        let (graph, seed) = fixture(&[("a", "b"), ("b", "a"), ("b", "b")]);
        let selected = select_seed_functions(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        assert_eq!(selected.function_ids.len(), 2);
        assert_eq!(selected.caller_distances["fn:b"], 1);
        assert_eq!(selected.callee_distances["fn:b"], 1);
        assert_eq!(selected.caller_distances["fn:a"], 0);
        assert_eq!(selected.callee_distances["fn:a"], 0);
    }

    fn mixed_fixture() -> (TypedGraph, ConsolidatedSeed) {
        let value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
        let seed = detect_seeds(
            &value,
            &load_seed_rules(bundled_seed_rules_path()).unwrap(),
            &SeedDetectionConfig::default(),
        )
        .unwrap()
        .seeds
        .remove(0);
        (TypedGraph::from_value(&value).unwrap(), seed)
    }

    #[test]
    fn evidence_inclusion_keeps_all_six_types_even_at_depth_zero() {
        use crate::graph::{EdgeType, NodeType};
        let (graph, seed) = mixed_fixture();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig {
                caller_depth: 0,
                callee_depth: 0,
            },
        )
        .unwrap();
        assert_eq!(
            local.selection.function_ids,
            BTreeSet::from(["fn:00401000".into()])
        );
        assert_eq!(local.nodes.len(), 7);
        assert_eq!(local.edges.len(), 6);
        assert_eq!(
            local
                .nodes
                .iter()
                .map(|n| n.node_type)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                NodeType::Function,
                NodeType::Api,
                NodeType::String,
                NodeType::StringCategory,
                NodeType::Constant,
                NodeType::Section,
                NodeType::VisibilityIndicator
            ])
        );
        assert!(local
            .edges
            .iter()
            .any(|e| e.edge_type == EdgeType::HasStringCategory));
        for node in &local.nodes {
            assert!(graph.nodes().contains(node));
        }
        for edge in &local.edges {
            assert!(graph.edges().contains(edge));
        }
        assert!(local.nodes.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert_eq!(local.source_graph_version, "0.12.0");
        assert_eq!(local.seed_id, seed.seed_id);
    }

    #[test]
    fn caller_and_callee_evidence_includes_unconfigured_api_and_normal_section() {
        use crate::graph::EdgeType;
        let (graph, seed) = mixed_fixture();
        let mut value = serde_json::to_value(&graph).unwrap();
        value["nodes"].as_array_mut().unwrap().extend([
            json!({"id": "fn:00404000", "type": "FUNCTION"}),
            json!({"id": "api:getlasterror", "type": "API", "normalized_name": "GetLastError", "original_names": ["GetLastError"]}),
            json!({"id": "sec:normal", "type": "SECTION", "name": ".text", "suspicious": false, "permissions": "rx"})
        ]);
        value["edges"].as_array_mut().unwrap().extend([
            json!({"type": "calls_function", "source": "fn:00402000", "target": "fn:00401000", "callsites": ["00402021"]}),
            json!({"type": "calls_function", "source": "fn:00401000", "target": "fn:00404000", "callsites": ["00401099"]}),
            json!({"type": "calls_api", "source": "fn:00404000", "target": "api:getlasterror", "callsites": ["00404020"]}),
            json!({"type": "belongs_to_section", "source": "fn:00404000", "target": "sec:normal"})
        ]);
        let graph = TypedGraph::from_value(&value).unwrap();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        for id in ["api:writeprocessmemory", "api:getlasterror", "sec:normal"] {
            assert!(local.nodes.iter().any(|n| n.id == id));
        }
        assert_eq!(local.selection.function_ids.len(), 3);
        assert_eq!(
            local
                .edges
                .iter()
                .filter(|e| e.edge_type == EdgeType::CallsFunction)
                .count(),
            2
        );
    }

    #[test]
    fn shared_evidence_never_pulls_in_unselected_functions_or_their_edges() {
        let (graph, seed) = mixed_fixture();
        let mut value = serde_json::to_value(&graph).unwrap();
        value["edges"].as_array_mut().unwrap().extend([
            json!({"type": "references_string", "source": "fn:00402000", "target": "str:00403000", "reference_sites": ["00402040"]}),
            json!({"type": "calls_api", "source": "fn:00402000", "target": "api:virtualalloc", "callsites": ["00402050"]})
        ]);
        let graph = TypedGraph::from_value(&value).unwrap();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        assert!(!local.nodes.iter().any(|n| n.id == "fn:00402000"));
        assert!(local.edges.iter().all(|e| e.source != "fn:00402000"));
        for edge in &local.edges {
            assert!(local.nodes.iter().any(|n| n.id == edge.source));
            assert!(local.nodes.iter().any(|n| n.id == edge.target));
        }
    }

    #[test]
    fn evidence_and_edges_are_deterministic_and_keep_parallel_provenance() {
        let (graph, seed) = mixed_fixture();
        let mut value = serde_json::to_value(&graph).unwrap();
        let repeated = value["edges"][6].clone();
        value["edges"].as_array_mut().unwrap().push(repeated);
        value["edges"].as_array_mut().unwrap().push(json!({"type": "calls_api", "source": "fn:00401000", "target": "api:virtualalloc", "callsites": ["00401035"], "occurrences": 1}));
        let graph = TypedGraph::from_value(&value).unwrap();
        let expected = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        assert_eq!(expected.edges.len(), 7);
        assert!(expected
            .edges
            .iter()
            .any(|e| e.properties.get("callsites") == Some(&json!(["00401035"]))));
        value["nodes"].as_array_mut().unwrap().reverse();
        value["edges"].as_array_mut().unwrap().reverse();
        let graph = TypedGraph::from_value(&value).unwrap();
        assert_eq!(
            expected,
            extract_local_subgraph(
                &GraphIndexes::new(&graph),
                &seed,
                &LocalExtractionConfig::default()
            )
            .unwrap()
        );
    }

    #[test]
    fn all_trigger_node_provenance_is_present_in_extracted_context() {
        let (graph, seed) = mixed_fixture();
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        for evidence in &seed.evidence {
            if let Some(id) = &evidence.node_id {
                assert!(local.nodes.iter().any(|n| &n.id == id));
            }
        }
        let original = graph
            .nodes()
            .iter()
            .find(|n| n.id == "vis:call_visibility:fn:00401000")
            .unwrap();
        assert!(local.nodes.contains(original));
        let original = graph
            .nodes()
            .iter()
            .find(|n| n.id == "const:memory_protection:0x40")
            .unwrap();
        assert!(local.nodes.contains(original));
    }

    #[test]
    fn extraction_rejects_incoherent_seed_before_returning_partial_context() {
        let (graph, mut seed) = mixed_fixture();
        seed.evidence[0].value = "invented".into();
        assert!(extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default()
        )
        .is_err());
    }
}
