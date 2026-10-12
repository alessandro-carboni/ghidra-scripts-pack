//! Deterministic function traversal for local seed context. No ranking or scoring.
use crate::graph::{GraphEdge, GraphNode, NodeType, UnresolvedCall};
use crate::graph_indexes::GraphIndexes;
use crate::schema::ConsolidatedSeed;
use crate::seed_validation::validate_consolidated_seed;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalExtractionConfig {
    pub caller_depth: usize,
    pub callee_depth: usize,
    pub max_function_nodes: Option<usize>,
    pub max_evidence_nodes: Option<usize>,
    pub max_total_nodes: Option<usize>,
    pub max_edges: Option<usize>,
}

impl Default for LocalExtractionConfig {
    fn default() -> Self {
        Self {
            caller_depth: 1,
            callee_depth: 2,
            // Step 4.9: resource limits are opt-in.
            // None preserves the unlimited behavior from Steps 4.1-4.8.
            max_function_nodes: None,
            max_evidence_nodes: None,
            max_total_nodes: None,
            max_edges: None,
        }
    }
}

impl LocalExtractionConfig {
    pub fn validate(&self) -> Result<(), String> {
        // A Local Subgraph must always be able to contain its anchor FUNCTION.
        if self.max_function_nodes == Some(0) {
            return Err("max_function_nodes must be at least 1 when configured".to_string());
        }
        if self.max_total_nodes == Some(0) {
            return Err("max_total_nodes must be at least 1 when configured".to_string());
        }
        // max_evidence_nodes = 0 and max_edges = 0 are valid technical settings.
        Ok(())
    }

    fn effective_function_limit(&self) -> Option<usize> {
        [self.max_function_nodes, self.max_total_nodes]
            .into_iter()
            .flatten()
            .min()
    }

    fn effective_evidence_limit(&self, function_count: usize) -> Option<usize> {
        let remaining_total = self
            .max_total_nodes
            .map(|limit| limit.saturating_sub(function_count));

        [self.max_evidence_nodes, remaining_total]
            .into_iter()
            .flatten()
            .min()
    }

    fn configured_limit(&self, kind: LocalGraphLimitKind) -> Option<usize> {
        match kind {
            LocalGraphLimitKind::FunctionNodes => self.max_function_nodes,
            LocalGraphLimitKind::EvidenceNodes => self.max_evidence_nodes,
            LocalGraphLimitKind::TotalNodes => self.max_total_nodes,
            LocalGraphLimitKind::Edges => self.max_edges,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalGraphLimitKind {
    FunctionNodes,
    EvidenceNodes,
    TotalNodes,
    Edges,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachedLocalGraphLimit {
    pub kind: LocalGraphLimitKind,
    pub configured_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraversalDepth {
    pub caller_depth: usize,
    pub callee_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalGraphCounts {
    pub function_nodes: usize,
    pub evidence_nodes: usize,
    pub total_nodes: usize,
    pub edges: usize,
    pub unresolved_calls: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    ResourceLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTruncationMetadata {
    pub truncated: bool,
    #[serde(default)]
    pub limits_reached: Vec<ReachedLocalGraphLimit>,
    pub requested_depth: TraversalDepth,
    pub effective_depth: TraversalDepth,
    pub counts: LocalGraphCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<TruncationReason>,
}

impl LocalTruncationMetadata {
    pub fn validate(&self, config: &LocalExtractionConfig) -> Result<(), String> {
        if self.requested_depth.caller_depth != config.caller_depth
            || self.requested_depth.callee_depth != config.callee_depth
        {
            return Err("truncation requested_depth must match extraction config".to_string());
        }
        if self.effective_depth.caller_depth > self.requested_depth.caller_depth
            || self.effective_depth.callee_depth > self.requested_depth.callee_depth
        {
            return Err("effective depth cannot exceed requested depth".to_string());
        }
        if self.counts.total_nodes != self.counts.function_nodes + self.counts.evidence_nodes {
            return Err("total_nodes must equal function_nodes + evidence_nodes".to_string());
        }
        if self.truncated {
            if self.limits_reached.is_empty()
                || self.reason != Some(TruncationReason::ResourceLimit)
            {
                return Err(
                    "truncated local graph requires reached limits and resource_limit reason"
                        .to_string(),
                );
            }
        } else if !self.limits_reached.is_empty() || self.reason.is_some() {
            return Err(
                "complete local graph cannot declare reached limits or a truncation reason"
                    .to_string(),
            );
        }
        if self
            .limits_reached
            .windows(2)
            .any(|pair| pair[0].kind >= pair[1].kind)
        {
            return Err("limits_reached must be sorted and unique by kind".to_string());
        }
        for reached in &self.limits_reached {
            if config.configured_limit(reached.kind) != Some(reached.configured_limit) {
                return Err("reached limit does not match extraction config".to_string());
            }
        }
        Ok(())
    }
}

/// Deterministic function selection around one seed anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionSelection {
    pub anchor_function_id: String,
    pub function_ids: BTreeSet<String>,
    pub caller_distances: BTreeMap<String, usize>,
    pub callee_distances: BTreeMap<String, usize>,
}

#[derive(Debug)]
struct SelectionOutcome {
    selection: FunctionSelection,
    reached_limits: BTreeSet<LocalGraphLimitKind>,
}

pub fn select_seed_functions(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
    config: &LocalExtractionConfig,
) -> Result<FunctionSelection, String> {
    Ok(select_seed_functions_with_limits(index, seed, config)?.selection)
}

fn select_seed_functions_with_limits(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
    config: &LocalExtractionConfig,
) -> Result<SelectionOutcome, String> {
    config.validate()?;
    validate_consolidated_seed(index, seed)?;

    let function_limit = config.effective_function_limit();

    // Caller and callee traversals remain independent. Resource limiting does not
    // introduce caller->callee or callee->caller turns.
    let mut callers = function_distances(
        index,
        &seed.anchor_function_id,
        Direction::Callers,
        config.caller_depth,
        function_limit,
    );
    let mut callees = function_distances(
        index,
        &seed.anchor_function_id,
        Direction::Callees,
        config.callee_depth,
        function_limit,
    );

    let mut ordered_functions: Vec<String> = callers
        .distances
        .keys()
        .chain(callees.distances.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    ordered_functions.sort_by(|left, right| {
        let left_distance =
            combined_function_distance(left, &callers.distances, &callees.distances);
        let right_distance =
            combined_function_distance(right, &callers.distances, &callees.distances);
        left_distance
            .cmp(&right_distance)
            .then_with(|| left.cmp(right))
    });

    let union_exceeded_limit = function_limit.is_some_and(|limit| ordered_functions.len() > limit);
    if let Some(limit) = function_limit {
        ordered_functions.truncate(limit);
    }

    let function_ids: BTreeSet<String> = ordered_functions.into_iter().collect();
    callers.distances.retain(|id, _| function_ids.contains(id));
    callees.distances.retain(|id, _| function_ids.contains(id));

    let function_truncated = callers.limit_reached || callees.limit_reached || union_exceeded_limit;
    let mut reached_limits = BTreeSet::new();
    if function_truncated {
        if config.max_function_nodes == function_limit && config.max_function_nodes.is_some() {
            reached_limits.insert(LocalGraphLimitKind::FunctionNodes);
        }

        if config.max_total_nodes == function_limit && config.max_total_nodes.is_some() {
            reached_limits.insert(LocalGraphLimitKind::TotalNodes);
        }
    }

    Ok(SelectionOutcome {
        selection: FunctionSelection {
            anchor_function_id: seed.anchor_function_id.clone(),
            function_ids,
            caller_distances: callers.distances,
            callee_distances: callees.distances,
        },
        reached_limits,
    })
}

fn combined_function_distance(
    function_id: &str,
    caller_distances: &BTreeMap<String, usize>,
    callee_distances: &BTreeMap<String, usize>,
) -> usize {
    caller_distances
        .get(function_id)
        .into_iter()
        .chain(callee_distances.get(function_id))
        .copied()
        .min()
        .unwrap_or(usize::MAX)
}

/// Internal local context. Step 4.12 gives this data an explicit versioned export contract.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalSubgraph {
    pub seed_id: String,
    pub source_graph_version: String,
    pub config: LocalExtractionConfig,
    pub selection: FunctionSelection,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub unresolved_calls: Vec<UnresolvedCall>,
    pub truncation: LocalTruncationMetadata,
}

pub fn unresolved_sort_key(call: &UnresolvedCall) -> String {
    serde_json::to_string(call).expect("unresolved JSON attributes are serializable")
}

pub fn extract_local_subgraph(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
    config: &LocalExtractionConfig,
) -> Result<LocalSubgraph, String> {
    let selection_outcome = select_seed_functions_with_limits(index, seed, config)?;
    let selection = selection_outcome.selection;
    let mut reached_limits = selection_outcome.reached_limits;

    let evidence_limit = config
        .effective_evidence_limit(selection.function_ids.len())
        .unwrap_or(usize::MAX);

    let mut ordered_functions: Vec<String> = selection.function_ids.iter().cloned().collect();
    ordered_functions.sort_by(|left, right| {
        let left_distance = combined_function_distance(
            left,
            &selection.caller_distances,
            &selection.callee_distances,
        );
        let right_distance = combined_function_distance(
            right,
            &selection.caller_distances,
            &selection.callee_distances,
        );
        left_distance
            .cmp(&right_distance)
            .then_with(|| left.cmp(right))
    });

    let mut evidence_ids = BTreeSet::new();
    let mut evidence_limit_reached = false;

    'evidence_selection: for function in &ordered_functions {
        for evidence_id in index.evidence(function) {
            if evidence_ids.contains(evidence_id) {
                continue;
            }
            if evidence_ids.len() >= evidence_limit {
                evidence_limit_reached = true;
                break 'evidence_selection;
            }
            evidence_ids.insert(evidence_id.to_string());
        }
    }

    if evidence_limit_reached {
        let effective = config.effective_evidence_limit(selection.function_ids.len());
        if config.max_evidence_nodes == effective && config.max_evidence_nodes.is_some() {
            reached_limits.insert(LocalGraphLimitKind::EvidenceNodes);
        }
        let remaining_total = config
            .max_total_nodes
            .map(|limit| limit.saturating_sub(selection.function_ids.len()));
        if remaining_total == effective && config.max_total_nodes.is_some() {
            reached_limits.insert(LocalGraphLimitKind::TotalNodes);
        }
    }

    let mut included = selection.function_ids.clone();
    included.extend(evidence_ids);

    let nodes = included
        .iter()
        .map(|id| {
            index
                .node(id)
                .cloned()
                .ok_or_else(|| format!("indexed node '{id}' disappeared"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let edge_limit = config.max_edges.unwrap_or(usize::MAX);
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut edge_limit_reached = false;

    // `included` is ordered and every outgoing list is canonically sorted.
    'edge_sources: for source_id in &included {
        for edge in index.outgoing(source_id).iter().copied() {
            if !included.contains(&edge.target) {
                continue;
            }
            if edges.last().is_some_and(|previous| previous == edge) {
                continue;
            }
            if edges.len() >= edge_limit {
                edge_limit_reached = true;
                break 'edge_sources;
            }
            edges.push(edge.clone());
        }
    }
    if edge_limit_reached {
        reached_limits.insert(LocalGraphLimitKind::Edges);
    }

    // Step 4.8 records remain separate from the four node/edge resource limits.
    let mut unresolved_calls: Vec<_> = index
        .graph()
        .unresolved_calls()
        .iter()
        .filter(|call| selection.function_ids.contains(&call.caller))
        .cloned()
        .collect();
    unresolved_calls.sort_by_cached_key(unresolved_sort_key);
    unresolved_calls.dedup();

    let function_nodes = nodes
        .iter()
        .filter(|node| node.node_type == NodeType::Function)
        .count();
    let evidence_nodes = nodes.len().saturating_sub(function_nodes);
    let requested_depth = TraversalDepth {
        caller_depth: config.caller_depth,
        callee_depth: config.callee_depth,
    };
    let effective_depth = TraversalDepth {
        caller_depth: selection
            .caller_distances
            .values()
            .copied()
            .max()
            .unwrap_or(0),
        callee_depth: selection
            .callee_distances
            .values()
            .copied()
            .max()
            .unwrap_or(0),
    };

    let limits_reached: Vec<ReachedLocalGraphLimit> = reached_limits
        .into_iter()
        .map(|kind| ReachedLocalGraphLimit {
            kind,
            configured_limit: config
                .configured_limit(kind)
                .expect("reached limit must be configured"),
        })
        .collect();
    let truncated = !limits_reached.is_empty();
    let truncation = LocalTruncationMetadata {
        truncated,
        limits_reached,
        requested_depth,
        effective_depth,
        counts: LocalGraphCounts {
            function_nodes,
            evidence_nodes,
            total_nodes: nodes.len(),
            edges: edges.len(),
            unresolved_calls: unresolved_calls.len(),
        },
        reason: truncated.then_some(TruncationReason::ResourceLimit),
    };
    truncation.validate(config)?;

    Ok(LocalSubgraph {
        seed_id: seed.seed_id.clone(),
        source_graph_version: index.graph().model_version().into(),
        config: config.clone(),
        selection,
        nodes,
        edges,
        unresolved_calls,
        truncation,
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
    Ok(function_distances(index, &seed.anchor_function_id, direction, max_depth, None).distances)
}

#[derive(Debug)]
struct TraversalResult {
    distances: BTreeMap<String, usize>,
    limit_reached: bool,
}

fn function_distances(
    index: &GraphIndexes<'_>,
    anchor: &str,
    direction: Direction,
    max_depth: usize,
    max_nodes: Option<usize>,
) -> TraversalResult {
    let node_limit = max_nodes.unwrap_or(usize::MAX).max(1);
    let mut distances = BTreeMap::from([(anchor.to_string(), 0)]);
    let mut queue = VecDeque::from([(anchor.to_string(), 0)]);
    let mut limit_reached = false;

    while let Some((function, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        let neighbors: Vec<_> = match direction {
            Direction::Callers => index.callers(&function).collect(),
            Direction::Callees => index.callees(&function).collect(),
        };

        for next in neighbors {
            if distances.contains_key(next) {
                continue;
            }
            if distances.len() >= node_limit {
                limit_reached = true;
                continue;
            }
            distances.insert(next.to_string(), depth + 1);
            queue.push_back((next.to_string(), depth + 1));
        }
    }

    TraversalResult {
        distances,
        limit_reached,
    }
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
                    ..LocalExtractionConfig::default()
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
            ..LocalExtractionConfig::default()
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
            ..LocalExtractionConfig::default()
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

        assert_eq!(config, LocalExtractionConfig::default());

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
                    ..LocalExtractionConfig::default()
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
                ..LocalExtractionConfig::default()
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
                ..LocalExtractionConfig::default()
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

    #[test]
    fn local_graph_limits_default_to_unlimited_and_validate() {
        let config: LocalExtractionConfig = serde_json::from_str("{}").unwrap();

        assert_eq!(config.max_function_nodes, None);
        assert_eq!(config.max_evidence_nodes, None);
        assert_eq!(config.max_total_nodes, None);
        assert_eq!(config.max_edges, None);
        config.validate().unwrap();

        let configured: LocalExtractionConfig = serde_json::from_value(json!({
            "caller_depth": 1,
            "callee_depth": 2,
            "max_function_nodes": 4,
            "max_evidence_nodes": 10,
            "max_total_nodes": 12,
            "max_edges": 20
        }))
        .unwrap();

        configured.validate().unwrap();

        assert_eq!(configured.max_function_nodes, Some(4));
        assert_eq!(configured.max_evidence_nodes, Some(10));
        assert_eq!(configured.max_total_nodes, Some(12));
        assert_eq!(configured.max_edges, Some(20));

        assert_eq!(
            serde_json::from_value::<LocalExtractionConfig>(
                serde_json::to_value(&configured).unwrap()
            )
            .unwrap(),
            configured
        );
    }

    #[test]
    fn invalid_local_graph_limits_are_rejected() {
        for value in [
            json!({"max_function_nodes": -1}),
            json!({"max_total_nodes": -1}),
            json!({"max_evidence_nodes": 1.5}),
            json!({"max_edges": "10"}),
            json!({"minimum_priority": 1}),
        ] {
            assert!(serde_json::from_value::<LocalExtractionConfig>(value).is_err());
        }

        for value in [
            json!({"max_function_nodes": 0}),
            json!({"max_total_nodes": 0}),
        ] {
            let config: LocalExtractionConfig = serde_json::from_value(value).unwrap();
            assert!(config.validate().is_err());
        }

        let zero_evidence_and_edges: LocalExtractionConfig = serde_json::from_value(json!({
            "max_evidence_nodes": 0,
            "max_edges": 0
        }))
        .unwrap();

        zero_evidence_and_edges.validate().unwrap();
    }

    #[test]
    fn function_limit_keeps_anchor_and_nearest_functions_deterministically() {
        let (graph, seed) = fixture(&[("b", "a"), ("c", "a"), ("a", "d"), ("d", "e")]);

        let config = LocalExtractionConfig {
            caller_depth: 2,
            callee_depth: 2,
            max_function_nodes: Some(2),
            ..LocalExtractionConfig::default()
        };

        let first = select_seed_functions(&GraphIndexes::new(&graph), &seed, &config).unwrap();

        assert_eq!(
            first.function_ids,
            BTreeSet::from(["fn:a".into(), "fn:b".into()])
        );
        assert!(first.function_ids.contains("fn:a"));

        let mut value = serde_json::to_value(&graph).unwrap();
        value["nodes"].as_array_mut().unwrap().reverse();
        value["edges"].as_array_mut().unwrap().reverse();

        let permuted = TypedGraph::from_value(&value).unwrap();

        assert_eq!(
            first,
            select_seed_functions(&GraphIndexes::new(&permuted), &seed, &config).unwrap()
        );
    }

    #[test]
    fn evidence_and_total_node_limits_are_enforced() {
        let (graph, seed) = mixed_fixture();

        let evidence_limited = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig {
                caller_depth: 0,
                callee_depth: 0,
                max_evidence_nodes: Some(2),
                ..LocalExtractionConfig::default()
            },
        )
        .unwrap();

        assert_eq!(evidence_limited.selection.function_ids.len(), 1);
        assert_eq!(evidence_limited.nodes.len(), 3);

        let total_limited = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig {
                caller_depth: 0,
                callee_depth: 0,
                max_total_nodes: Some(2),
                ..LocalExtractionConfig::default()
            },
        )
        .unwrap();

        assert_eq!(total_limited.nodes.len(), 2);
        assert!(total_limited
            .nodes
            .iter()
            .any(|node| node.id == seed.anchor_function_id));
    }

    #[test]
    fn zero_evidence_and_edge_limits_keep_only_selected_functions() {
        let (graph, seed) = mixed_fixture();

        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig {
                caller_depth: 0,
                callee_depth: 0,
                max_evidence_nodes: Some(0),
                max_edges: Some(0),
                ..LocalExtractionConfig::default()
            },
        )
        .unwrap();

        assert_eq!(local.nodes.len(), 1);
        assert_eq!(local.nodes[0].id, seed.anchor_function_id);
        assert!(local.edges.is_empty());

        // Step 4.8 provenance remains separate and preserved.
        assert_eq!(local.unresolved_calls.len(), 1);
        assert!(local.unresolved_calls[0].callee.is_none());
    }

    #[test]
    fn edge_limit_is_deterministic_under_input_permutations() {
        let (graph, seed) = mixed_fixture();

        let config = LocalExtractionConfig {
            caller_depth: 0,
            callee_depth: 0,
            max_edges: Some(2),
            ..LocalExtractionConfig::default()
        };

        let expected = extract_local_subgraph(&GraphIndexes::new(&graph), &seed, &config).unwrap();

        assert_eq!(expected.edges.len(), 2);

        let mut value = serde_json::to_value(&graph).unwrap();
        value["nodes"].as_array_mut().unwrap().reverse();
        value["edges"].as_array_mut().unwrap().reverse();

        let permuted = TypedGraph::from_value(&value).unwrap();

        assert_eq!(
            expected,
            extract_local_subgraph(&GraphIndexes::new(&permuted), &seed, &config).unwrap()
        );
    }
}
