//! Validated Rust loader for the Python Typed Evidence Graph contract.
use crate::schema::Report;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub const TYPED_GRAPH_MODEL_VERSION: &str = "0.12.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeType {
    Function,
    Api,
    String,
    StringCategory,
    Constant,
    Section,
    VisibilityIndicator,
}

impl NodeType {
    fn prefix(self) -> &'static str {
        match self {
            Self::Function => "fn:",
            Self::Api => "api:",
            Self::String => "str:",
            Self::StringCategory => "strcat:",
            Self::Constant => "const:",
            Self::Section => "sec:",
            Self::VisibilityIndicator => "vis:",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    CallsFunction,
    CallsApi,
    ReferencesString,
    HasStringCategory,
    UsesConstant,
    BelongsToSection,
    ContainsIndirectCall,
}

impl EdgeType {
    fn endpoints(self) -> (NodeType, NodeType) {
        use NodeType::*;
        match self {
            Self::CallsFunction => (Function, Function),
            Self::CallsApi => (Function, Api),
            Self::ReferencesString => (Function, String),
            Self::HasStringCategory => (String, StringCategory),
            Self::UsesConstant => (Function, Constant),
            Self::BelongsToSection => (Function, Section),
            Self::ContainsIndirectCall => (Function, VisibilityIndicator),
        }
    }
}

/// Topology is typed; all exporter attributes are retained losslessly as properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    #[serde(flatten)]
    pub properties: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    #[serde(rename = "type")]
    pub edge_type: EdgeType,
    pub source: String,
    pub target: String,
    #[serde(flatten)]
    pub properties: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnresolvedCall {
    pub indicator: String,
    pub caller: String,
    pub callee: Option<String>,
    pub callsite: Option<String>,
    pub unresolved: bool,
    pub reason: String,
    #[serde(flatten)]
    pub properties: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct GraphDocument {
    model_version: String,
    #[serde(default)]
    metadata: BTreeMap<String, Value>,
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    unresolved_calls: Vec<UnresolvedCall>,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

/// Private storage prevents callers from invalidating a successfully loaded graph.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TypedGraph(GraphDocument);

impl<'de> Deserialize<'de> for TypedGraph {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let graph = Self(GraphDocument::deserialize(deserializer)?);
        graph.validate().map_err(serde::de::Error::custom)?;
        Ok(graph)
    }
}

impl TypedGraph {
    pub fn from_json(data: &str) -> Result<Self, String> {
        serde_json::from_str(data).map_err(|e| format!("invalid typed graph: {e}"))
    }
    pub fn from_value(value: &Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("invalid typed graph: {e}"))
    }
    pub fn from_report(report: &Report) -> Result<Self, String> {
        Self::from_value(
            report
                .typed_graph
                .as_ref()
                .ok_or("report.typed_graph is missing")?,
        )
    }
    /// Reads a standalone typed graph JSON, not a complete legacy report.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        Self::from_json(
            &std::fs::read_to_string(path)
                .map_err(|e| format!("read typed graph '{}': {e}", path.display()))?,
        )
    }
    pub fn model_version(&self) -> &str {
        &self.0.model_version
    }
    pub fn metadata(&self) -> &BTreeMap<String, Value> {
        &self.0.metadata
    }
    pub fn nodes(&self) -> &[GraphNode] {
        &self.0.nodes
    }
    pub fn edges(&self) -> &[GraphEdge] {
        &self.0.edges
    }
    pub fn unresolved_calls(&self) -> &[UnresolvedCall] {
        &self.0.unresolved_calls
    }

    fn validate(&self) -> Result<(), String> {
        if self.model_version() != TYPED_GRAPH_MODEL_VERSION {
            return Err(format!(
                "unsupported typed graph model_version '{}'; expected '{}'",
                self.model_version(),
                TYPED_GRAPH_MODEL_VERSION
            ));
        }
        let mut nodes = BTreeMap::new();
        for node in self.nodes() {
            let prefix = node.node_type.prefix();
            if node.id.trim() != node.id
                || !node.id.starts_with(prefix)
                || node.id.len() <= prefix.len()
            {
                return Err(format!(
                    "invalid {:?} node ID '{}'",
                    node.node_type, node.id
                ));
            }
            if nodes.insert(node.id.as_str(), node).is_some() {
                return Err(format!("duplicate graph node ID '{}'", node.id));
            }
        }
        for edge in self.edges() {
            let source = nodes
                .get(edge.source.as_str())
                .ok_or_else(|| format!("missing edge source '{}'", edge.source))?;
            let target = nodes
                .get(edge.target.as_str())
                .ok_or_else(|| format!("missing edge target '{}'", edge.target))?;
            if (source.node_type, target.node_type) != edge.edge_type.endpoints() {
                return Err(format!(
                    "invalid endpoints for {:?}: {} -> {}",
                    edge.edge_type, edge.source, edge.target
                ));
            }
            if edge.edge_type == EdgeType::ContainsIndirectCall
                && target.properties.get("function").and_then(Value::as_str)
                    != Some(edge.source.as_str())
            {
                return Err(format!(
                    "visibility indicator '{}' does not belong to '{}'",
                    edge.target, edge.source
                ));
            }
            for (alias, expected) in match edge.edge_type {
                EdgeType::CallsFunction => vec![("caller", &edge.source), ("callee", &edge.target)],
                EdgeType::CallsApi => vec![("caller", &edge.source), ("api", &edge.target)],
                EdgeType::ReferencesString => {
                    vec![("function", &edge.source), ("string", &edge.target)]
                }
                EdgeType::HasStringCategory => {
                    vec![("string", &edge.source), ("category", &edge.target)]
                }
                EdgeType::UsesConstant => {
                    vec![("function", &edge.source), ("constant", &edge.target)]
                }
                EdgeType::BelongsToSection => {
                    vec![("function", &edge.source), ("section", &edge.target)]
                }
                EdgeType::ContainsIndirectCall => {
                    vec![("function", &edge.source), ("indicator", &edge.target)]
                }
            } {
                if edge
                    .properties
                    .get(alias)
                    .is_some_and(|v| v.as_str() != Some(expected.as_str()))
                {
                    return Err(format!("inconsistent edge provenance alias '{alias}'"));
                }
            }
            if matches!(edge.edge_type, EdgeType::CallsFunction | EdgeType::CallsApi)
                && edge
                    .properties
                    .get("unresolved")
                    .is_some_and(|v| v != &Value::Bool(false))
            {
                return Err("resolved call edge must not declare unresolved=true".into());
            }
        }
        for call in self.unresolved_calls() {
            if nodes.get(call.caller.as_str()).map(|n| n.node_type) != Some(NodeType::Function) {
                return Err(format!(
                    "unresolved caller '{}' is not a FUNCTION",
                    call.caller
                ));
            }
            if call.indicator != "unresolved_call"
                || !call.unresolved
                || call.callee.is_some()
                || call.reason.trim().is_empty()
                || call.callsite.as_ref().is_some_and(|v| v.trim().is_empty())
            {
                return Err("invalid unresolved call provenance".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap()
    }

    #[test]
    fn loader_preserves_all_exporter_attributes_and_metadata() {
        let mut value = fixture();
        value["metadata"] = json!({"source": "Ghidra", "complete": true});
        value["nodes"][0]["symbol_name"] = json!("SampleFunction");
        value["edges"][0]["occurrences"] = json!(1);
        value["extension"] = json!({"kept": true});
        let graph = TypedGraph::from_json(&value.to_string()).unwrap();
        assert_eq!(graph.nodes().len(), 9);
        assert_eq!(graph.edges().len(), 7);
        assert_eq!(graph.unresolved_calls().len(), 1);
        assert_eq!(serde_json::to_value(graph).unwrap(), value);
    }

    #[test]
    fn loader_rejects_missing_and_incompatible_versions() {
        for version in [json!("0.11.0"), json!("0.13.0"), json!(null), json!(12)] {
            let mut value = fixture();
            value["model_version"] = version;
            assert!(TypedGraph::from_value(&value).is_err());
        }
        let mut value = fixture();
        value.as_object_mut().unwrap().remove("model_version");
        assert!(TypedGraph::from_value(&value).is_err());
    }

    #[test]
    fn loader_rejects_malformed_arrays_and_unknown_vocabulary() {
        for key in ["nodes", "edges", "unresolved_calls"] {
            let mut value = fixture();
            value[key] = json!({});
            assert!(TypedGraph::from_value(&value).is_err());
        }
        for key in ["nodes", "edges"] {
            let mut value = fixture();
            value[key][0]["type"] = json!("unknown");
            assert!(TypedGraph::from_value(&value).is_err());
        }
        assert!(TypedGraph::from_json("{").is_err());
    }

    #[test]
    fn loader_rejects_duplicate_ids_and_bad_endpoint_provenance() {
        let mut value = fixture();
        let duplicate = value["nodes"][0].clone();
        value["nodes"].as_array_mut().unwrap().push(duplicate);
        assert!(TypedGraph::from_value(&value)
            .unwrap_err()
            .contains("duplicate"));
        for target in ["api:missing", "fn:00401000"] {
            let mut value = fixture();
            value["edges"][0]["target"] = json!(target);
            assert!(TypedGraph::from_value(&value).is_err());
        }
        let mut value = fixture();
        value["edges"][0]["caller"] = json!("fn:wrong");
        assert!(TypedGraph::from_value(&value).is_err());
    }

    #[test]
    fn loader_rejects_fake_unresolved_targets_and_wrong_visibility_owner() {
        for (field, bad) in [
            ("callee", json!("fn:00402000")),
            ("unresolved", json!(false)),
            ("caller", json!("fn:missing")),
        ] {
            let mut value = fixture();
            value["unresolved_calls"][0][field] = bad;
            assert!(TypedGraph::from_value(&value).is_err());
        }
        let mut value = fixture();
        value["nodes"][8]["function"] = json!("fn:00402000");
        assert!(TypedGraph::from_value(&value).is_err());
    }

    #[test]
    fn empty_graph_and_report_adapter_are_supported_without_changing_legacy_report() {
        let value = json!({"model_version": "0.12.0", "metadata": {}, "nodes": [], "edges": [], "unresolved_calls": []});
        let report = Report {
            typed_graph: Some(value.clone()),
            ..Report::default()
        };
        assert!(TypedGraph::from_report(&report).unwrap().nodes().is_empty());
        assert_eq!(report.typed_graph, Some(value));
        assert!(TypedGraph::from_report(&Report::default()).is_err());
    }
}
