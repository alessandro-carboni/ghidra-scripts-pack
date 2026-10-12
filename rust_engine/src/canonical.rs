//! Canonicalization Baseline v0.1: scientific facts, separate from legacy scoring.
use crate::graph::{EdgeType, GraphEdge, GraphNode, NodeType, UnresolvedCall};
use crate::local_subgraph::LocalTruncationMetadata;
use crate::local_subgraph_schema::LocalSubgraphDocument;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const CANONICAL_SUBGRAPH_VERSION: &str = "0.1.0";
pub const CANONICALIZATION_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalNode {
    pub id: String,
    pub kind: NodeType,
    pub facts: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedObservation {
    pub id: String,
    pub caller: String,
    pub facts: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEdge {
    pub id: String,
    pub kind: EdgeType,
    pub source: String,
    pub target: String,
    pub facts: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCollection {
    Nodes,
    Edges,
    UnresolvedCalls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReference {
    pub collection: SourceCollection,
    pub index: usize,
    /// JSON pointers into source_document, including original sites and properties.
    pub property_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageDisposition {
    Represented { canonical_ids: Vec<String> },
    Excluded { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEntry {
    pub source: SourceReference,
    pub disposition: CoverageDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CoverageLedger {
    pub entries: Vec<CoverageEntry>,
    pub source_nodes: usize,
    pub source_edges: usize,
    pub source_unresolved_records: usize,
    pub represented: usize,
    pub excluded: usize,
}

fn source_reference(collection: SourceCollection, index: usize, value: Value) -> SourceReference {
    let name = match collection {
        SourceCollection::Nodes => "nodes",
        SourceCollection::Edges => "edges",
        SourceCollection::UnresolvedCalls => "unresolved_calls",
    };
    let property_paths = value
        .as_object()
        .unwrap()
        .keys()
        .map(|key| {
            format!(
                "/{name}/{index}/{}",
                key.replace('~', "~0").replace('/', "~1")
            )
        })
        .collect();
    SourceReference {
        collection,
        index,
        property_paths,
    }
}

fn edge_facts(edge: &GraphEdge) -> Value {
    let p = &edge.properties;
    let occurrences = p
        .get("occurrences")
        .or_else(|| p.get("reference_count"))
        .cloned()
        .or_else(|| {
            ["callsites", "reference_sites", "use_sites"]
                .iter()
                .find_map(|k| p.get(*k).and_then(Value::as_array).map(|a| json!(a.len())))
        })
        .unwrap_or(json!(1));
    let mut apis: Vec<String> = p
        .get("context_apis")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(normalize_api)
        .collect();
    apis.sort();
    apis.dedup();
    json!({"occurrences": occurrences, "direct": p.get("direct"), "indirect": p.get("indirect"), "context_apis": apis})
}

/// The graph contract preserves arbitrary raw properties. Validate the subset
/// interpreted here so malformed objects cannot enter the scientific payload.
fn validate_fact_properties(source: &LocalSubgraphDocument) -> Result<(), String> {
    let check = |p: &BTreeMap<String, Value>, keys: &[&str], valid: fn(&Value) -> bool| {
        for key in keys {
            if p.get(*key).is_some_and(|v| !valid(v)) {
                return Err(format!("invalid source property '{key}'"));
            }
        }
        Ok(())
    };
    let text = |v: &Value| v.as_str().is_some_and(|s| !s.trim().is_empty());
    let texts = |v: &Value| {
        v.as_array()
            .is_some_and(|a| a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty())))
    };
    for node in &source.nodes {
        let p = &node.properties;
        match node.node_type {
            NodeType::Api => check(p, &["name", "normalized_name"], text)?,
            NodeType::String => check(p, &["value"], Value::is_string)?,
            NodeType::StringCategory => check(p, &["category"], text)?,
            NodeType::Constant => {
                check(p, &["value"], |v| v.as_u64().is_some())?;
                check(p, &["symbolic_names"], texts)?;
                check(p, &["category"], text)?;
            }
            NodeType::Section => check(
                p,
                &["read", "write", "execute", "initialized"],
                Value::is_boolean,
            )?,
            NodeType::VisibilityIndicator => check(
                p,
                &[
                    "indirect_callsites",
                    "unresolved_indirect_callsites",
                    "dynamic_dispatch_callsites",
                ],
                texts,
            )?,
            NodeType::Function => (),
        }
    }
    for edge in &source.edges {
        let p = &edge.properties;
        check(p, &["direct", "indirect"], Value::is_boolean)?;
        check(p, &["occurrences", "reference_count"], |v| {
            v.as_u64().is_some_and(|n| n > 0)
        })?;
        check(
            p,
            &["context_apis", "callsites", "reference_sites", "use_sites"],
            texts,
        )?;
        for count in ["occurrences", "reference_count"]
            .iter()
            .filter_map(|k| p.get(*k).and_then(Value::as_u64))
        {
            if ["callsites", "reference_sites", "use_sites"]
                .iter()
                .filter_map(|k| p.get(*k).and_then(Value::as_array))
                .any(|a| count < a.len() as u64)
            {
                return Err("source occurrence count is smaller than its site list".into());
            }
        }
    }
    for call in &source.unresolved_calls {
        check(&call.properties, &["direct", "indirect"], Value::is_boolean)?;
        check(&call.properties, &["occurrences"], |v| {
            v.as_u64().is_some_and(|n| n > 0)
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FunctionRole {
    Anchor,
    Caller,
    Callee,
    Both,
}

/// Only surface aliases: A/W and Nt/Zw variants remain distinct.
pub fn normalize_api(raw: &str) -> String {
    let mut name = raw.trim().to_ascii_lowercase();
    if let Some((_, symbol)) = name.rsplit_once('!') {
        name = symbol.to_string();
    }
    if let Some((module, symbol)) = name.rsplit_once('.') {
        if module.ends_with(".dll") {
            name = symbol.to_string();
        }
    }
    if let Some(symbol) = name.strip_prefix("__imp_") {
        name = symbol.to_string();
    }
    if let Some((symbol, bytes)) = name.rsplit_once('@') {
        if !bytes.is_empty() && bytes.bytes().all(|b| b.is_ascii_digit()) && symbol.starts_with('_')
        {
            name = symbol[1..].to_string();
        }
    }
    name
}

fn evidence_facts(node: &GraphNode) -> Option<Value> {
    match node.node_type {
        NodeType::Api => {
            let raw = node
                .properties
                .get("name")
                .or_else(|| node.properties.get("normalized_name"))
                .and_then(Value::as_str)?;
            Some(json!({"canonical_value": normalize_api(raw)}))
        }
        NodeType::String => {
            let raw = node.properties.get("value")?.as_str()?;
            // Lossless text baseline: no case folding, whitespace trimming or behavior inference.
            Some(json!({"normalized": raw}))
        }
        NodeType::StringCategory => {
            Some(json!({"category": node.properties.get("category")?.as_str()?}))
        }
        NodeType::Constant => {
            let value = node.properties.get("value")?.clone();
            let category = node.properties.get("category").and_then(Value::as_str);
            let supported = match (category, value.as_u64()) {
                (Some("memory_protection"), Some(0x40)) => Some("PAGE_EXECUTE_READWRITE"),
                (Some("memory_protection"), Some(0x04)) => Some("PAGE_READWRITE"),
                _ => None,
            };
            let semantic = supported.filter(|name| {
                node.properties
                    .get("symbolic_names")
                    .and_then(Value::as_array)
                    .is_some_and(|names| names.iter().any(|n| n.as_str() == Some(name)))
            });
            Some(
                json!({"literal": value, "semantic": semantic.map(|name| json!({"category": category, "name": name}))}),
            )
        }
        NodeType::Section => {
            let flag = |key: &str| node.properties.get(key).and_then(Value::as_bool);
            let permissions = [flag("read"), flag("write"), flag("execute")];
            let role = match (flag("execute"), flag("initialized")) {
                (Some(true), _) => "executable",
                (Some(false), Some(true)) => "initialized_data",
                (Some(false), Some(false)) => "uninitialized_data",
                _ => "unknown",
            };
            Some(
                json!({"read": permissions[0], "write": permissions[1], "execute": permissions[2],
                "initialized": flag("initialized"), "role": role}),
            )
        }
        NodeType::VisibilityIndicator => {
            let count = |key: &str| {
                node.properties
                    .get(key)
                    .and_then(Value::as_array)
                    .map(Vec::len)
            };
            Some(json!({"indirect_calls": count("indirect_callsites"),
                "unresolved_indirect_calls": count("unresolved_indirect_callsites"),
                "explicit_dynamic_dispatch": count("dynamic_dispatch_callsites")}))
        }
        _ => None,
    }
}

fn function_facts(source: &LocalSubgraphDocument, id: &str) -> Value {
    let caller = source.function_selection.caller_distances.get(id);
    let callee = source.function_selection.callee_distances.get(id);
    let role = if id == source.anchor_function_id {
        FunctionRole::Anchor
    } else if caller.is_some() && callee.is_some() {
        FunctionRole::Both
    } else if caller.is_some() {
        FunctionRole::Caller
    } else {
        FunctionRole::Callee
    };
    json!({"role": role, "caller_distance": caller, "callee_distance": callee})
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSubgraph {
    pub schema_version: String,
    pub source_local_subgraph_schema_version: String,
    pub graph_version: String,
    /// Source metadata only; never part of scientific identity.
    pub seed_id: String,
    pub anchor_function_id: String,
    pub canonicalization_version: String,
    pub nodes: Vec<CanonicalNode>,
    /// Local handles mapped to original nodes; excluded from scientific identity.
    pub node_sources: BTreeMap<String, Vec<GraphNode>>,
    pub unresolved_calls: Vec<UnresolvedObservation>,
    pub unresolved_sources: BTreeMap<String, Vec<UnresolvedCall>>,
    pub local_graph_truncation: LocalTruncationMetadata,
    pub edges: Vec<CanonicalEdge>,
    pub edge_sources: BTreeMap<String, Vec<GraphEdge>>,
    pub provenance_map: BTreeMap<String, Vec<SourceReference>>,
    pub source_document: LocalSubgraphDocument,
    pub coverage_ledger: CoverageLedger,
    /// SHA-256 of scientific_value, never a similarity or maliciousness score.
    pub canonical_digest: String,
}

impl CanonicalSubgraph {
    pub fn from_source(source: &LocalSubgraphDocument) -> Result<Self, String> {
        let mut source = source.clone();
        for node in &mut source.nodes {
            normalize_properties(&mut node.properties);
        }
        for edge in &mut source.edges {
            normalize_properties(&mut edge.properties);
        }
        for call in &mut source.unresolved_calls {
            normalize_properties(&mut call.properties);
        }
        source.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        source
            .edges
            .sort_by_key(crate::graph_indexes::edge_sort_key);
        source
            .unresolved_calls
            .sort_by_key(crate::local_subgraph::unresolved_sort_key);
        source.truncation.limits_reached.sort_by_key(|v| v.kind);
        source.validate()?;
        validate_fact_properties(&source)?;
        crate::graph::TypedGraph::from_value(&json!({"model_version": source.graph_version,
            "nodes": source.nodes, "edges": source.edges, "unresolved_calls": source.unresolved_calls}))?;
        for id in &source.function_selection.function_ids {
            if id != &source.anchor_function_id {
                let caller = source.function_selection.caller_distances.get(id);
                let callee = source.function_selection.callee_distances.get(id);
                if (caller.is_none() && callee.is_none())
                    || caller == Some(&0)
                    || callee == Some(&0)
                {
                    return Err(
                        "non-anchor function needs a positive caller or callee distance".into(),
                    );
                }
            }
        }
        let source = &source;
        let mut nodes = Vec::new();
        let mut node_sources = BTreeMap::new();
        for node in source
            .nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Function)
        {
            let id = format!("F{}", nodes.len());
            nodes.push(CanonicalNode {
                id: id.clone(),
                kind: NodeType::Function,
                facts: function_facts(source, &node.id),
            });
            node_sources.insert(id, vec![node.clone()]);
        }
        for node in &source.nodes {
            if let Some(facts) = evidence_facts(node) {
                // Value facts can be shared. Functions, strings, sections and visibility
                // retain occurrence identity so their topology is never accidentally fused.
                if matches!(
                    node.node_type,
                    NodeType::Api | NodeType::Constant | NodeType::StringCategory
                ) {
                    if let Some(existing) = nodes
                        .iter()
                        .find(|n| n.kind == node.node_type && n.facts == facts)
                    {
                        node_sources
                            .get_mut(&existing.id)
                            .unwrap()
                            .push(node.clone());
                        continue;
                    }
                }
                let id = format!("N{}", nodes.len());
                nodes.push(CanonicalNode {
                    id: id.clone(),
                    kind: node.node_type,
                    facts,
                });
                node_sources.insert(id, vec![node.clone()]);
            }
        }
        let source_ids: BTreeMap<_, _> = node_sources
            .iter()
            .flat_map(|(id, ns)| ns.iter().map(move |n| (n.id.clone(), id.clone())))
            .collect();
        let mut edges = Vec::new();
        let mut edge_sources = BTreeMap::new();
        for edge in &source.edges {
            if let (Some(from), Some(to)) =
                (source_ids.get(&edge.source), source_ids.get(&edge.target))
            {
                let id = format!("E{}", edges.len());
                edges.push(CanonicalEdge {
                    id: id.clone(),
                    kind: edge.edge_type,
                    source: from.clone(),
                    target: to.clone(),
                    facts: edge_facts(edge),
                });
                edge_sources.insert(id, vec![edge.clone()]);
            }
        }
        let mut unresolved_calls = Vec::new();
        let mut unresolved_sources = BTreeMap::new();
        for call in &source.unresolved_calls {
            let id = format!("U{}", unresolved_calls.len());
            unresolved_calls.push(UnresolvedObservation {
                id: id.clone(), caller: source_ids[&call.caller].clone(),
                facts: json!({"unresolved": true, "direct": call.properties.get("direct"),
                    "indirect": call.properties.get("indirect"), "occurrences": call.properties.get("occurrences").unwrap_or(&json!(1))}),
            });
            unresolved_sources.insert(id, vec![call.clone()]);
        }
        let mut result = Self {
            schema_version: CANONICAL_SUBGRAPH_VERSION.into(),
            source_local_subgraph_schema_version: source.schema_version.clone(),
            graph_version: source.graph_version.clone(),
            seed_id: source.seed_id.clone(),
            anchor_function_id: source.anchor_function_id.clone(),
            canonicalization_version: CANONICALIZATION_VERSION.into(),
            nodes,
            node_sources,
            unresolved_calls,
            unresolved_sources,
            local_graph_truncation: source.truncation.clone(),
            edges,
            edge_sources,
            provenance_map: BTreeMap::new(),
            source_document: source.clone(),
            coverage_ledger: CoverageLedger::default(),
            canonical_digest: String::new(),
        };
        result.order()?;
        result.index_provenance();
        result.index_coverage();
        result.canonical_digest = sha256(result.scientific_value().to_string().as_bytes());
        Ok(result)
    }

    /// Rebuild from the validated source. This checks all IDs, endpoints, facts,
    /// provenance paths, coverage totals and ordering instead of trusting redundant metadata.
    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::from_source(&self.source_document)?;
        if self != &expected {
            return Err("canonical document differs from verified source-derived baseline (identity, facts, provenance, coverage or versions)".into());
        }
        Ok(())
    }

    pub fn from_json(data: &str) -> Result<Self, String> {
        let document: Self =
            serde_json::from_str(data).map_err(|e| format!("invalid canonical JSON: {e}"))?;
        document.validate()?;
        Ok(document)
    }

    pub fn to_json_pretty(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    fn index_coverage(&mut self) {
        let source = &self.source_document;
        let mut ledger = CoverageLedger {
            source_nodes: source.nodes.len(),
            source_edges: source.edges.len(),
            source_unresolved_records: source.unresolved_calls.len(),
            ..Default::default()
        };
        for (collection, values) in [
            (
                SourceCollection::Nodes,
                serde_json::to_value(&source.nodes).unwrap(),
            ),
            (
                SourceCollection::Edges,
                serde_json::to_value(&source.edges).unwrap(),
            ),
            (
                SourceCollection::UnresolvedCalls,
                serde_json::to_value(&source.unresolved_calls).unwrap(),
            ),
        ] {
            for (index, value) in values.as_array().unwrap().iter().enumerate() {
                let canonical_ids: Vec<_> = self
                    .provenance_map
                    .iter()
                    .filter(|(_, refs)| {
                        refs.iter()
                            .any(|r| r.collection == collection && r.index == index)
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                let disposition = if canonical_ids.is_empty() {
                    ledger.excluded += 1;
                    CoverageDisposition::Excluded {reason: match collection {
                        SourceCollection::Nodes => "missing_supported_value; raw node retained in source_document",
                        SourceCollection::Edges => "endpoint_excluded; raw edge retained in source_document",
                        SourceCollection::UnresolvedCalls => "unsupported_unresolved_record; raw record retained in source_document",
                    }.into()}
                } else {
                    ledger.represented += 1;
                    CoverageDisposition::Represented { canonical_ids }
                };
                ledger.entries.push(CoverageEntry {
                    source: source_reference(collection.clone(), index, value.clone()),
                    disposition,
                });
            }
        }
        self.coverage_ledger = ledger;
    }

    fn index_provenance(&mut self) {
        for (id, nodes) in &self.node_sources {
            self.provenance_map.insert(
                id.clone(),
                nodes
                    .iter()
                    .map(|node| {
                        let index = self
                            .source_document
                            .nodes
                            .iter()
                            .position(|n| n == node)
                            .unwrap();
                        source_reference(
                            SourceCollection::Nodes,
                            index,
                            serde_json::to_value(node).unwrap(),
                        )
                    })
                    .collect(),
            );
        }
        for (id, edges) in &self.edge_sources {
            self.provenance_map.insert(
                id.clone(),
                edges
                    .iter()
                    .map(|edge| {
                        let index = self
                            .source_document
                            .edges
                            .iter()
                            .position(|e| e == edge)
                            .unwrap();
                        source_reference(
                            SourceCollection::Edges,
                            index,
                            serde_json::to_value(edge).unwrap(),
                        )
                    })
                    .collect(),
            );
        }
        for (id, calls) in &self.unresolved_sources {
            self.provenance_map.insert(
                id.clone(),
                calls
                    .iter()
                    .map(|call| {
                        let index = self
                            .source_document
                            .unresolved_calls
                            .iter()
                            .position(|u| u == call)
                            .unwrap();
                        source_reference(
                            SourceCollection::UnresolvedCalls,
                            index,
                            serde_json::to_value(call).unwrap(),
                        )
                    })
                    .collect(),
            );
        }
    }

    /// Address-free payload. Source metadata and raw provenance intentionally live outside it.
    pub fn scientific_value(&self) -> Value {
        json!({"schema_version": self.schema_version,
            "canonicalization_version": self.canonicalization_version,
            "graph_version": self.graph_version,
            "source_local_subgraph_schema_version": self.source_local_subgraph_schema_version,
            "nodes": self.nodes, "edges": self.edges,
            "unresolved_calls": self.unresolved_calls, "local_graph_truncation": self.local_graph_truncation})
    }

    fn order(&mut self) -> Result<(), String> {
        let indices: BTreeMap<_, _> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.id.clone(), i))
            .collect();
        let keys: Vec<_> = self
            .nodes
            .iter()
            .map(|n| {
                let mut unresolved: Vec<_> = self
                    .unresolved_calls
                    .iter()
                    .filter(|u| u.caller == n.id)
                    .map(|u| u.facts.to_string())
                    .collect();
                unresolved.sort();
                json!([n.kind, n.facts, unresolved]).to_string()
            })
            .collect();
        let arcs: Vec<_> = self
            .edges
            .iter()
            .map(|e| {
                (
                    indices[&e.source],
                    indices[&e.target],
                    json!([e.kind, e.facts]).to_string(),
                )
            })
            .collect();
        let order = crate::canonical_order::canonical_order(&keys, &arcs)?;
        let mapping: BTreeMap<_, _> = order
            .iter()
            .enumerate()
            .map(|(new, old)| (self.nodes[*old].id.clone(), format!("N{new}")))
            .collect();
        let mut provenance = BTreeMap::new();
        self.nodes = order
            .iter()
            .map(|old| {
                let mut node = self.nodes[*old].clone();
                let id = mapping[&node.id].clone();
                provenance.insert(id.clone(), self.node_sources[&node.id].clone());
                node.id = id;
                node
            })
            .collect();
        self.node_sources = provenance;
        for edge in &mut self.edges {
            edge.source = mapping[&edge.source].clone();
            edge.target = mapping[&edge.target].clone();
        }
        self.edges.sort_by_key(|e| {
            json!([
                e.kind,
                e.source,
                e.target,
                e.facts,
                self.edge_sources[&e.id]
            ])
            .to_string()
        });
        let mut provenance = BTreeMap::new();
        for (i, edge) in self.edges.iter_mut().enumerate() {
            let id = format!("E{i}");
            provenance.insert(id.clone(), self.edge_sources[&edge.id].clone());
            edge.id = id;
        }
        self.edge_sources = provenance;
        for call in &mut self.unresolved_calls {
            call.caller = mapping[&call.caller].clone();
        }
        self.unresolved_calls.sort_by_key(|u| {
            json!([u.caller, u.facts, self.unresolved_sources[&u.id]]).to_string()
        });
        let mut provenance = BTreeMap::new();
        for (i, call) in self.unresolved_calls.iter_mut().enumerate() {
            let id = format!("U{i}");
            provenance.insert(id.clone(), self.unresolved_sources[&call.id].clone());
            call.id = id;
        }
        self.unresolved_sources = provenance;
        Ok(())
    }
}

/// Only contract-defined set-valued properties are sorted; unknown arrays keep their order.
fn normalize_properties(properties: &mut BTreeMap<String, Value>) {
    for key in [
        "callsites",
        "reference_sites",
        "use_sites",
        "original_names",
        "context_apis",
        "symbolic_names",
        "bit_lengths",
        "categories",
        "signals",
        "indirect_callsites",
        "unresolved_indirect_callsites",
        "dynamic_dispatch_callsites",
        "reasons",
    ] {
        if let Some(Value::Array(items)) = properties.get_mut(key) {
            items.sort_by_key(Value::to_string);
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::TypedGraph;
    use crate::graph_indexes::GraphIndexes;
    use crate::local_subgraph::{extract_local_subgraph, LocalExtractionConfig};
    use crate::seed_detection::detect_seeds;
    use crate::seed_limits::SeedDetectionConfig;
    use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules};

    pub fn source() -> LocalSubgraphDocument {
        let value =
            serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
        let graph = TypedGraph::from_value(&value).unwrap();
        let seed = detect_seeds(
            &value,
            &load_seed_rules(bundled_seed_rules_path()).unwrap(),
            &SeedDetectionConfig::default(),
        )
        .unwrap()
        .seeds
        .remove(0);
        LocalSubgraphDocument::from_local(
            &extract_local_subgraph(
                &GraphIndexes::new(&graph),
                &seed,
                &LocalExtractionConfig::default(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn connected_source() -> LocalSubgraphDocument {
        let mut s = source();
        let peer = "fn:00402000".to_string();
        s.nodes.push(GraphNode {
            id: peer.clone(),
            node_type: NodeType::Function,
            properties: BTreeMap::new(),
        });
        s.function_selection.function_ids.insert(peer.clone());
        s.function_selection
            .caller_distances
            .insert(peer.clone(), 1);
        s.function_selection
            .callee_distances
            .insert(peer.clone(), 1);
        for (from, to) in [
            (s.anchor_function_id.clone(), peer.clone()),
            (peer, s.anchor_function_id.clone()),
        ] {
            s.edges.push(GraphEdge {
                edge_type: EdgeType::CallsFunction,
                source: from,
                target: to,
                properties: BTreeMap::new(),
            });
        }
        s.truncation.counts.function_nodes += 1;
        s.truncation.counts.total_nodes += 1;
        s.truncation.counts.edges += 2;
        s
    }

    fn relocate(value: Value) -> Value {
        let rename = |s: String| {
            s.replace("004010", "00f010")
                .replace("004020", "001020")
                .replace("004030", "002030")
        };
        match value {
            Value::String(s) => Value::String(rename(s)),
            Value::Array(items) => Value::Array(items.into_iter().map(relocate).collect()),
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(k, v)| (rename(k), relocate(v)))
                    .collect(),
            ),
            other => other,
        }
    }

    #[test]
    fn step_5_15_relocation_invariance_and_provenance_integrity() {
        let source = connected_source();
        let baseline = CanonicalSubgraph::from_source(&source).unwrap();
        let relocated: LocalSubgraphDocument =
            serde_json::from_value(relocate(serde_json::to_value(&source).unwrap())).unwrap();
        let other = CanonicalSubgraph::from_source(&relocated).unwrap();
        assert_eq!(baseline.scientific_value(), other.scientific_value());
        assert_eq!(baseline.canonical_digest, other.canonical_digest);
        assert_ne!(baseline.anchor_function_id, other.anchor_function_id);
        assert_ne!(baseline.source_document, other.source_document);
        baseline.validate().unwrap();
        other.validate().unwrap();
        assert!(baseline.nodes.iter().any(|n| n.facts["role"] == "BOTH"));
        let science = baseline.scientific_value().to_string();
        for forbidden in ["004010", "004020", "score", "capability", "callsite"] {
            assert!(!science.contains(forbidden));
        }
        assert!(baseline
            .unresolved_calls
            .iter()
            .all(|u| u.facts.get("callee").is_none()));
        assert_eq!(baseline.coverage_ledger.excluded, 0);
    }

    #[test]
    fn step_5_15_all_seven_edge_types_and_semantic_sensitivity() {
        let mut source = connected_source();
        let baseline = CanonicalSubgraph::from_source(&source).unwrap();
        let kinds: std::collections::BTreeSet<_> = baseline.edges.iter().map(|e| e.kind).collect();
        assert_eq!(kinds.len(), 7);
        // Attach an API to the peer instead: evidence multiset unchanged, topology changed.
        source
            .edges
            .iter_mut()
            .find(|e| e.edge_type == EdgeType::CallsApi)
            .unwrap()
            .source = "fn:00402000".into();
        let changed = CanonicalSubgraph::from_source(&source).unwrap();
        assert_ne!(baseline.canonical_digest, changed.canonical_digest);
    }

    #[test]
    fn step_5_15_raw_extensions_are_preserved_without_entering_science() {
        let mut source = source();
        let baseline = CanonicalSubgraph::from_source(&source).unwrap();
        source.nodes[0].properties.insert(
            "future_extraction_property".into(),
            json!({"original": [3,1,2]}),
        );
        source.nodes[0]
            .properties
            .insert("legacy_score".into(), json!(100));
        let other = CanonicalSubgraph::from_source(&source).unwrap();
        assert_eq!(baseline.scientific_value(), other.scientific_value());
        assert_ne!(baseline.source_document, other.source_document);
        assert!(serde_json::to_string(&other.provenance_map)
            .unwrap()
            .contains("future_extraction_property"));
        other.validate().unwrap();
    }

    #[test]
    fn step_5_15_malformed_properties_cannot_smuggle_scientific_fields() {
        let mut s = source();
        s.nodes
            .iter_mut()
            .find(|n| n.node_type == NodeType::Constant)
            .unwrap()
            .properties
            .insert("value".into(), json!({"score": 42}));
        assert!(CanonicalSubgraph::from_source(&s).is_err());
        let mut s = source();
        s.edges[0]
            .properties
            .insert("direct".into(), json!({"address": "00401000"}));
        assert!(CanonicalSubgraph::from_source(&s).is_err());
        let mut s = source();
        s.edges[0].properties.insert("occurrences".into(), json!(0));
        assert!(CanonicalSubgraph::from_source(&s).is_err());
    }

    #[test]
    fn step_5_15_truncated_context_keeps_explicit_observability_and_coverage() {
        let baseline = source();
        let mut value = serde_json::to_value(&baseline).unwrap();
        value["extraction_config"]["max_edges"] = json!(0);
        value["edges"] = json!([]);
        value["truncation"]["truncated"] = json!(true);
        value["truncation"]["reason"] = json!("resource_limit");
        value["truncation"]["limits_reached"] = json!([{"kind":"edges", "configured_limit":0}]);
        value["truncation"]["counts"]["edges"] = json!(0);
        let source: LocalSubgraphDocument = serde_json::from_value(value).unwrap();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        c.validate().unwrap();
        assert!(c.local_graph_truncation.truncated);
        assert_eq!(
            c.coverage_ledger.represented,
            source.nodes.len() + source.unresolved_calls.len()
        );
        assert_eq!(c.coverage_ledger.excluded, 0);
        assert_ne!(
            c.canonical_digest,
            CanonicalSubgraph::from_source(&baseline)
                .unwrap()
                .canonical_digest
        );
    }

    #[test]
    fn step_5_14_digest_is_stable_and_sensitive_to_facts() {
        assert_eq!(
            sha256(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut source = source();
        let original = CanonicalSubgraph::from_source(&source).unwrap();
        source.nodes.reverse();
        source.edges.reverse();
        assert_eq!(
            original.canonical_digest,
            CanonicalSubgraph::from_source(&source)
                .unwrap()
                .canonical_digest
        );
        source
            .nodes
            .iter_mut()
            .find(|n| n.node_type == NodeType::String)
            .unwrap()
            .properties
            .insert("value".into(), json!("changed evidence"));
        assert_ne!(
            original.canonical_digest,
            CanonicalSubgraph::from_source(&source)
                .unwrap()
                .canonical_digest
        );
        let mut tampered = original;
        tampered.canonical_digest = "sha256:invalid".into();
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn step_5_13_rejects_tampering_and_invalid_source() {
        let c = CanonicalSubgraph::from_source(&source()).unwrap();
        c.validate().unwrap();
        assert_eq!(
            CanonicalSubgraph::from_json(&c.to_json_pretty().unwrap()).unwrap(),
            c
        );
        let mut broken = c.clone();
        broken.nodes[0].id = broken.nodes[1].id.clone();
        assert!(broken.validate().is_err());
        let mut broken = c.clone();
        broken.edges[0].target = "missing".into();
        assert!(broken.validate().is_err());
        let mut broken = c.clone();
        broken.nodes[0].facts["role"] = json!("ANCHOR");
        assert!(broken.validate().is_err());
        let mut broken = c.clone();
        broken.provenance_map.values_mut().next().unwrap()[0].index = usize::MAX;
        assert!(broken.validate().is_err());
        let mut broken = c.clone();
        broken.coverage_ledger.represented += 1;
        assert!(broken.validate().is_err());
        for forbidden in ["score", "capability", "address"] {
            let mut broken = c.clone();
            broken.nodes[0].facts[forbidden] = json!("injected");
            assert!(broken.validate().is_err());
        }
        let mut raw = source();
        raw.unresolved_calls[0].callee = Some(raw.anchor_function_id.clone());
        assert!(CanonicalSubgraph::from_source(&raw).is_err());
        let mut raw = source();
        raw.nodes.push(raw.nodes[0].clone());
        assert!(CanonicalSubgraph::from_source(&raw).is_err());
        let mut value = serde_json::to_value(&c).unwrap();
        value["score"] = json!(99);
        assert!(CanonicalSubgraph::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn step_5_12_every_source_element_is_accounted_for() {
        let mut source = source();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        let total = source.nodes.len() + source.edges.len() + source.unresolved_calls.len();
        assert_eq!(c.coverage_ledger.entries.len(), total);
        assert_eq!(c.coverage_ledger.represented, total);
        assert_eq!(c.coverage_ledger.excluded, 0);
        source
            .nodes
            .iter_mut()
            .find(|n| n.node_type == NodeType::Api)
            .unwrap()
            .properties
            .clear();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        assert_eq!(
            c.coverage_ledger.represented + c.coverage_ledger.excluded,
            total
        );
        assert_eq!(c.coverage_ledger.excluded, 2); // API node and its edge.
        assert!(c
            .coverage_ledger
            .entries
            .iter()
            .filter_map(|e| match &e.disposition {
                CoverageDisposition::Excluded { reason } => Some(reason),
                _ => None,
            })
            .all(|reason| !reason.is_empty()));
    }

    #[test]
    fn step_5_11_provenance_paths_resolve_to_original_properties() {
        let c = CanonicalSubgraph::from_source(&source()).unwrap();
        let raw = serde_json::to_value(&c.source_document).unwrap();
        assert_eq!(
            c.provenance_map.len(),
            c.nodes.len() + c.edges.len() + c.unresolved_calls.len()
        );
        for references in c.provenance_map.values() {
            assert!(!references.is_empty());
            for reference in references {
                for path in &reference.property_paths {
                    assert!(raw.pointer(path).is_some(), "missing {path}");
                }
            }
        }
        assert!(c
            .provenance_map
            .values()
            .flatten()
            .flat_map(|r| &r.property_paths)
            .any(|p| p.ends_with("/callsites")));
    }

    #[test]
    fn step_5_10_input_permutations_do_not_change_bytes() {
        let source = source();
        let expected = CanonicalSubgraph::from_source(&source).unwrap();
        let mut permuted = source.clone();
        permuted.nodes.reverse();
        permuted.edges.reverse();
        permuted.unresolved_calls.reverse();
        for edge in &mut permuted.edges {
            if let Some(Value::Array(sites)) = edge.properties.get_mut("callsites") {
                sites.reverse();
            }
        }
        let actual = CanonicalSubgraph::from_source(&permuted).unwrap();
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            serde_json::to_string(&actual).unwrap()
        );
        assert_eq!(expected.scientific_value(), actual.scientific_value());
    }

    #[test]
    fn step_5_9_shared_facts_keep_every_occurrence() {
        let mut source = source();
        let mut api = source
            .nodes
            .iter()
            .find(|n| n.node_type == NodeType::Api)
            .unwrap()
            .clone();
        api.id = "api:alias".into();
        api.properties
            .insert("normalized_name".into(), json!("KERNEL32.dll!VirtualAlloc"));
        source.nodes.push(api.clone());
        let mut edge = source
            .edges
            .iter()
            .find(|e| e.edge_type == EdgeType::CallsApi)
            .unwrap()
            .clone();
        edge.target = api.id;
        source.edges.push(edge);
        source.truncation.counts.evidence_nodes += 1;
        source.truncation.counts.total_nodes += 1;
        source.truncation.counts.edges += 1;
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        assert_eq!(
            c.nodes.iter().filter(|n| n.kind == NodeType::Api).count(),
            1
        );
        assert!(c.node_sources.values().any(|ns| ns.len() == 2));
        assert_eq!(
            c.edge_sources.values().map(Vec::len).sum::<usize>(),
            source.edges.len()
        );
        assert_eq!(
            c.node_sources.values().map(Vec::len).sum::<usize>(),
            source.nodes.len()
        );
    }

    #[test]
    fn step_5_8_edges_and_callsites_preserved() {
        let source = source();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        assert_eq!(c.edges.len(), source.edges.len());
        for edge in &c.edges {
            assert!(c.nodes.iter().any(|n| n.id == edge.source));
            assert!(c.nodes.iter().any(|n| n.id == edge.target));
            assert_eq!(edge.kind, c.edge_sources[&edge.id][0].edge_type);
        }
        let e = c
            .edges
            .iter()
            .find(|e| e.kind == EdgeType::CallsApi)
            .unwrap();
        assert_eq!(e.facts["occurrences"], 2);
        assert_eq!(
            c.edge_sources[&e.id][0].properties["callsites"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn step_5_7_observability_separated_without_targets() {
        let source = source();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        let v = c
            .nodes
            .iter()
            .find(|n| n.kind == NodeType::VisibilityIndicator)
            .unwrap();
        assert_eq!(v.facts["indirect_calls"], 2);
        assert_eq!(v.facts["unresolved_indirect_calls"], 1);
        assert_eq!(v.facts["explicit_dynamic_dispatch"], 0);
        assert_eq!(c.unresolved_calls.len(), source.unresolved_calls.len());
        assert!(!serde_json::to_string(&c.unresolved_calls)
            .unwrap()
            .contains("callee"));
        assert_eq!(c.local_graph_truncation, source.truncation);
    }

    #[test]
    fn step_5_6_section_facts_not_names() {
        let source = source();
        let mut node = source
            .nodes
            .iter()
            .find(|n| n.node_type == NodeType::Section)
            .unwrap()
            .clone();
        assert_eq!(evidence_facts(&node).unwrap()["role"], "unknown");
        node.properties.insert("execute".into(), json!(true));
        let facts = evidence_facts(&node).unwrap();
        assert_eq!(facts["role"], "executable");
        node.properties.insert("name".into(), json!("arbitrary"));
        assert_eq!(facts, evidence_facts(&node).unwrap());
        assert!(facts.get("suspicious").is_none());
    }

    #[test]
    fn step_5_5_constants_require_source_semantics() {
        let source = source();
        let mut node = source
            .nodes
            .iter()
            .find(|n| n.node_type == NodeType::Constant)
            .unwrap()
            .clone();
        assert_eq!(
            evidence_facts(&node).unwrap()["semantic"]["name"],
            "PAGE_EXECUTE_READWRITE"
        );
        node.properties.remove("symbolic_names");
        assert!(evidence_facts(&node).unwrap()["semantic"].is_null());
        node.properties.insert("value".into(), json!(12345));
        let fact = evidence_facts(&node).unwrap();
        assert_eq!(fact["literal"], 12345);
        assert!(fact["semantic"].is_null());
    }

    #[test]
    fn step_5_4_strings_keep_content_and_existing_category() {
        let c = CanonicalSubgraph::from_source(&source()).unwrap();
        let string = c.nodes.iter().find(|n| n.kind == NodeType::String).unwrap();
        assert_eq!(string.facts["normalized"], "powershell -NoProfile");
        assert_eq!(
            c.node_sources[&string.id][0].properties["value"],
            string.facts["normalized"]
        );
        assert!(c
            .nodes
            .iter()
            .any(|n| n.kind == NodeType::StringCategory && n.facts["category"] == "powershell"));
        let node = GraphNode {
            id: "str:test".into(),
            node_type: NodeType::String,
            properties: BTreeMap::from([("value".into(), json!(" A\r\n\u{0000}é "))]),
        };
        assert_eq!(
            evidence_facts(&node).unwrap()["normalized"],
            " A\r\n\u{0000}é "
        );
    }

    #[test]
    fn step_5_3_api_surface_only() {
        assert_eq!(
            normalize_api("KERNEL32.dll!__imp__VirtualAlloc@16"),
            "virtualalloc"
        );
        assert_eq!(normalize_api("KERNEL32.dll.VirtualAlloc"), "virtualalloc");
        assert_ne!(normalize_api("CreateFileA"), normalize_api("CreateFileW"));
        assert_ne!(normalize_api("NtOpenFile"), normalize_api("ZwOpenFile"));
        assert_eq!(normalize_api("_custom"), "_custom");
        let c = CanonicalSubgraph::from_source(&source()).unwrap();
        let api = c.nodes.iter().find(|n| n.kind == NodeType::Api).unwrap();
        assert!(c.node_sources[&api.id][0]
            .properties
            .contains_key("normalized_name"));
    }

    #[test]
    fn step_5_2_relative_roles() {
        let mut source = source();
        let anchor = source.anchor_function_id.clone();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        assert_eq!(
            c.nodes
                .iter()
                .filter(|n| n.facts["role"] == "ANCHOR")
                .count(),
            1
        );
        assert!(c.nodes.iter().all(|n| !n.id.contains(&anchor)));
        assert_eq!(function_facts(&source, &anchor)["caller_distance"], 0);
        source
            .function_selection
            .caller_distances
            .insert("peer".into(), 1);
        assert_eq!(function_facts(&source, "peer")["role"], "CALLER");
        source
            .function_selection
            .callee_distances
            .insert("peer".into(), 2);
        assert_eq!(function_facts(&source, "peer")["role"], "BOTH");
        source.function_selection.caller_distances.remove("peer");
        assert_eq!(function_facts(&source, "peer")["role"], "CALLEE");
    }

    #[test]
    fn step_5_1_versioned_contract() {
        let source = source();
        let canonical = CanonicalSubgraph::from_source(&source).unwrap();
        let json = serde_json::to_string(&canonical).unwrap();
        assert_eq!(
            serde_json::from_str::<CanonicalSubgraph>(&json).unwrap(),
            canonical
        );
        assert_eq!(canonical.schema_version, "0.1.0");
        assert_eq!(canonical.anchor_function_id, source.anchor_function_id);
        assert!(!json.contains("score"));
        assert!(!json.contains("capability"));
        println!(
            "CanonicalSubgraph v{}: round-trip OK",
            canonical.schema_version
        );
    }
}
