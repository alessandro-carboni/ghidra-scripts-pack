//! Immutable, deterministic adjacency indexes borrowing a validated graph.
use crate::graph::{EdgeType, GraphEdge, GraphNode, NodeType, TypedGraph};
use std::collections::{BTreeMap, BTreeSet};

pub fn edge_sort_key(edge: &GraphEdge) -> (String, EdgeType, String, String) {
    (
        edge.source.clone(),
        edge.edge_type,
        edge.target.clone(),
        serde_json::to_string(&edge.properties).expect("JSON properties are serializable"),
    )
}

pub struct GraphIndexes<'g> {
    graph: &'g TypedGraph,
    nodes: BTreeMap<&'g str, &'g GraphNode>,
    by_type: BTreeMap<NodeType, Vec<&'g str>>,
    outgoing: BTreeMap<&'g str, Vec<&'g GraphEdge>>,
    incoming: BTreeMap<&'g str, Vec<&'g GraphEdge>>,
    evidence: BTreeMap<&'g str, BTreeSet<&'g str>>,
    apis: BTreeMap<&'g str, BTreeSet<&'g str>>,
    callers: BTreeMap<&'g str, BTreeSet<&'g str>>,
    callees: BTreeMap<&'g str, BTreeSet<&'g str>>,
}

impl<'g> GraphIndexes<'g> {
    pub fn new(graph: &'g TypedGraph) -> Self {
        let mut result = Self {
            graph,
            nodes: BTreeMap::new(),
            by_type: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            evidence: BTreeMap::new(),
            apis: BTreeMap::new(),
            callers: BTreeMap::new(),
            callees: BTreeMap::new(),
        };
        for node in graph.nodes() {
            result.nodes.insert(&node.id, node);
            result
                .by_type
                .entry(node.node_type)
                .or_default()
                .push(&node.id);
        }
        for ids in result.by_type.values_mut() {
            ids.sort_unstable();
        }
        for edge in graph.edges() {
            result.outgoing.entry(&edge.source).or_default().push(edge);
            result.incoming.entry(&edge.target).or_default().push(edge);
            if edge.edge_type == EdgeType::CallsFunction {
                result
                    .callees
                    .entry(&edge.source)
                    .or_default()
                    .insert(&edge.target);
                result
                    .callers
                    .entry(&edge.target)
                    .or_default()
                    .insert(&edge.source);
            } else if edge.edge_type != EdgeType::HasStringCategory {
                result
                    .evidence
                    .entry(&edge.source)
                    .or_default()
                    .insert(&edge.target);
                if edge.edge_type == EdgeType::CallsApi {
                    result
                        .apis
                        .entry(&edge.source)
                        .or_default()
                        .insert(&edge.target);
                }
            }
        }
        for edges in result
            .outgoing
            .values_mut()
            .chain(result.incoming.values_mut())
        {
            edges.sort_by_cached_key(|edge| edge_sort_key(edge));
        }
        // Categories belong to a function only through its actually referenced strings.
        let mut categories = Vec::new();
        for (function, evidence) in &result.evidence {
            for id in evidence {
                if result.nodes[id].node_type == NodeType::String {
                    for edge in result.outgoing(id) {
                        if edge.edge_type == EdgeType::HasStringCategory {
                            categories.push((*function, edge.target.as_str()));
                        }
                    }
                }
            }
        }
        for (function, category) in categories {
            result
                .evidence
                .entry(function)
                .or_default()
                .insert(category);
        }
        result
    }

    pub fn graph(&self) -> &'g TypedGraph {
        self.graph
    }
    pub fn node(&self, id: &str) -> Option<&'g GraphNode> {
        self.nodes.get(id).copied()
    }
    pub fn nodes_of_type(&self, kind: NodeType) -> &[&'g str] {
        self.by_type.get(&kind).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn outgoing(&self, id: &str) -> &[&'g GraphEdge] {
        self.outgoing.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn incoming(&self, id: &str) -> &[&'g GraphEdge] {
        self.incoming.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn evidence(&self, function: &str) -> impl Iterator<Item = &'g str> + '_ {
        self.evidence
            .get(function)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }
    pub fn apis(&self, function: &str) -> impl Iterator<Item = &'g str> + '_ {
        self.apis
            .get(function)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }
    pub fn callers(&self, function: &str) -> impl Iterator<Item = &'g str> + '_ {
        self.callers
            .get(function)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }
    pub fn callees(&self, function: &str) -> impl Iterator<Item = &'g str> + '_ {
        self.callees
            .get(function)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> Value {
        let mut graph: Value =
            serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
        graph["edges"].as_array_mut().unwrap().extend([
            json!({"type": "calls_function", "source": "fn:00402000", "target": "fn:00401000", "callsites": ["00402050"]}),
            json!({"type": "calls_function", "source": "fn:00402000", "target": "fn:00401000", "callsites": ["00402060"]}),
            json!({"type": "calls_function", "source": "fn:00401000", "target": "fn:00401000", "callsites": ["00401001"]})
        ]);
        graph
    }

    #[test]
    fn indexes_resolve_nodes_types_and_missing_ids() {
        let graph = TypedGraph::from_value(&fixture()).unwrap();
        let index = GraphIndexes::new(&graph);
        assert_eq!(
            index.nodes_of_type(NodeType::Function),
            &["fn:00401000", "fn:00402000"]
        );
        assert_eq!(
            index.node("api:virtualalloc").unwrap().node_type,
            NodeType::Api
        );
        assert!(index.node("fn:missing").is_none());
        assert!(index.outgoing("fn:missing").is_empty());
        assert_eq!(index.evidence("fn:missing").count(), 0);
    }

    #[test]
    fn adjacency_preserves_parallel_call_provenance_but_neighbors_are_unique() {
        let graph = TypedGraph::from_value(&fixture()).unwrap();
        let index = GraphIndexes::new(&graph);
        assert_eq!(
            index.callees("fn:00402000").collect::<Vec<_>>(),
            vec!["fn:00401000"]
        );
        assert_eq!(
            index.callers("fn:00401000").collect::<Vec<_>>(),
            vec!["fn:00401000", "fn:00402000"]
        );
        assert_eq!(index.incoming("fn:00401000").len(), 3);
        assert_eq!(
            index
                .outgoing("fn:00402000")
                .iter()
                .filter(|e| e.edge_type == EdgeType::CallsFunction)
                .count(),
            2
        );
    }

    #[test]
    fn function_evidence_follows_string_categories_without_crossing_to_other_functions() {
        let graph = TypedGraph::from_value(&fixture()).unwrap();
        let index = GraphIndexes::new(&graph);
        let evidence = index.evidence("fn:00401000").collect::<Vec<_>>();
        assert_eq!(evidence.len(), 6);
        assert!(evidence.contains(&"strcat:powershell"));
        assert!(!evidence.contains(&"api:writeprocessmemory"));
        assert_eq!(
            index.apis("fn:00401000").collect::<Vec<_>>(),
            vec!["api:virtualalloc"]
        );
        assert_eq!(
            index.evidence("fn:00402000").collect::<Vec<_>>(),
            vec!["api:writeprocessmemory"]
        );
    }

    #[test]
    fn index_queries_are_independent_of_input_order() {
        let mut value = fixture();
        let first = TypedGraph::from_value(&value).unwrap();
        value["nodes"].as_array_mut().unwrap().reverse();
        value["edges"].as_array_mut().unwrap().reverse();
        let second = TypedGraph::from_value(&value).unwrap();
        let a = GraphIndexes::new(&first);
        let b = GraphIndexes::new(&second);
        for id in a.nodes.keys() {
            assert_eq!(a.outgoing(id), b.outgoing(id));
            assert_eq!(a.incoming(id), b.incoming(id));
            assert_eq!(
                a.evidence(id).collect::<Vec<_>>(),
                b.evidence(id).collect::<Vec<_>>()
            );
            assert_eq!(
                a.callers(id).collect::<Vec<_>>(),
                b.callers(id).collect::<Vec<_>>()
            );
        }
    }
}
