//! Versioned JSON contract for local seed subgraphs consumed by later stages and the GUI.
use crate::graph::{GraphEdge, GraphNode, NodeType, UnresolvedCall, TYPED_GRAPH_MODEL_VERSION};
use crate::graph_indexes::edge_sort_key;
use crate::local_subgraph::{
    unresolved_sort_key, FunctionSelection, LocalExtractionConfig, LocalSubgraph,
    LocalTruncationMetadata,
};
use crate::schema::build_consolidated_seed_id;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub const LOCAL_SUBGRAPH_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSubgraphDocument {
    pub schema_version: String,
    pub seed_id: String,
    pub anchor_function_id: String,
    pub graph_version: String,
    pub extraction_config: LocalExtractionConfig,
    pub function_selection: FunctionSelection,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub unresolved_calls: Vec<UnresolvedCall>,
    pub truncation: LocalTruncationMetadata,
}

impl LocalSubgraphDocument {
    pub fn from_local(local: &LocalSubgraph) -> Result<Self, String> {
        let document = Self {
            schema_version: LOCAL_SUBGRAPH_SCHEMA_VERSION.to_string(),
            seed_id: local.seed_id.clone(),
            anchor_function_id: local.selection.anchor_function_id.clone(),
            graph_version: local.source_graph_version.clone(),
            extraction_config: local.config.clone(),
            function_selection: local.selection.clone(),
            nodes: local.nodes.clone(),
            edges: local.edges.clone(),
            unresolved_calls: local.unresolved_calls.clone(),
            truncation: local.truncation.clone(),
        };
        document.validate()?;
        Ok(document)
    }

    pub fn from_json(data: &str) -> Result<Self, String> {
        let document: Self =
            serde_json::from_str(data).map_err(|e| format!("invalid local subgraph JSON: {e}"))?;
        document.validate()?;
        Ok(document)
    }

    pub fn to_json_pretty(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize local subgraph document: {e}"))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("read local subgraph '{}': {e}", path.display()))?;
        Self::from_json(&data)
    }

    pub fn write_pretty(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let data = self.to_json_pretty()?;
        std::fs::write(path, data)
            .map_err(|e| format!("write local subgraph '{}': {e}", path.display()))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LOCAL_SUBGRAPH_SCHEMA_VERSION {
            return Err(format!(
                "unsupported local subgraph schema_version '{}'; expected '{}'",
                self.schema_version, LOCAL_SUBGRAPH_SCHEMA_VERSION
            ));
        }
        if self.graph_version != TYPED_GRAPH_MODEL_VERSION {
            return Err(format!(
                "unsupported source graph version '{}'; expected '{}'",
                self.graph_version, TYPED_GRAPH_MODEL_VERSION
            ));
        }
        self.extraction_config.validate()?;
        self.truncation.validate(&self.extraction_config)?;

        if self.anchor_function_id != self.function_selection.anchor_function_id {
            return Err("anchor_function_id must match function_selection anchor".to_string());
        }
        let expected_seed_id = build_consolidated_seed_id(&self.anchor_function_id)?;
        if self.seed_id != expected_seed_id {
            return Err(format!(
                "local subgraph seed_id does not match anchor; expected '{expected_seed_id}'"
            ));
        }
        if !self
            .function_selection
            .function_ids
            .contains(&self.anchor_function_id)
        {
            return Err("function_selection must contain the anchor".to_string());
        }
        if self
            .function_selection
            .caller_distances
            .get(&self.anchor_function_id)
            != Some(&0)
            || self
                .function_selection
                .callee_distances
                .get(&self.anchor_function_id)
                != Some(&0)
        {
            return Err("anchor must have caller/callee distance zero".to_string());
        }
        if self
            .function_selection
            .caller_distances
            .iter()
            .any(|(id, depth)| {
                !self.function_selection.function_ids.contains(id)
                    || *depth > self.extraction_config.caller_depth
            })
            || self
                .function_selection
                .callee_distances
                .iter()
                .any(|(id, depth)| {
                    !self.function_selection.function_ids.contains(id)
                        || *depth > self.extraction_config.callee_depth
                })
        {
            return Err("function distances are inconsistent with selection/config".to_string());
        }

        if self.nodes.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err("local subgraph nodes must be sorted and unique by id".to_string());
        }
        let node_ids: BTreeSet<&str> = self.nodes.iter().map(|node| node.id.as_str()).collect();
        if node_ids.len() != self.nodes.len() {
            return Err("local subgraph contains duplicate node IDs".to_string());
        }
        for function_id in &self.function_selection.function_ids {
            let Some(node) = self.nodes.iter().find(|node| &node.id == function_id) else {
                return Err(format!(
                    "selected function '{function_id}' is missing from nodes"
                ));
            };
            if node.node_type != NodeType::Function {
                return Err(format!("selected node '{function_id}' is not a FUNCTION"));
            }
        }
        for node in self
            .nodes
            .iter()
            .filter(|node| node.node_type == NodeType::Function)
        {
            if !self.function_selection.function_ids.contains(&node.id) {
                return Err(format!(
                    "FUNCTION node '{}' is outside function_selection",
                    node.id
                ));
            }
        }

        for edge in &self.edges {
            if !node_ids.contains(edge.source.as_str()) || !node_ids.contains(edge.target.as_str())
            {
                return Err("local edge endpoint is missing from local nodes".to_string());
            }
        }
        if self
            .edges
            .windows(2)
            .any(|pair| edge_sort_key(&pair[0]) >= edge_sort_key(&pair[1]))
        {
            return Err("local edges must be canonically sorted and deduplicated".to_string());
        }

        if self
            .unresolved_calls
            .windows(2)
            .any(|pair| unresolved_sort_key(&pair[0]) >= unresolved_sort_key(&pair[1]))
        {
            return Err("unresolved calls must be canonically sorted and deduplicated".to_string());
        }
        for call in &self.unresolved_calls {
            if !self.function_selection.function_ids.contains(&call.caller) {
                return Err(
                    "unresolved call belongs to a function outside the local context".into(),
                );
            }
            if call.callee.is_some() || !call.unresolved {
                return Err("local unresolved call must not invent a resolved target".into());
            }
        }

        let function_nodes = self
            .nodes
            .iter()
            .filter(|node| node.node_type == NodeType::Function)
            .count();
        let evidence_nodes = self.nodes.len().saturating_sub(function_nodes);
        let counts = &self.truncation.counts;
        if counts.function_nodes != function_nodes
            || counts.evidence_nodes != evidence_nodes
            || counts.total_nodes != self.nodes.len()
            || counts.edges != self.edges.len()
            || counts.unresolved_calls != self.unresolved_calls.len()
        {
            return Err("truncation counts do not match local subgraph contents".to_string());
        }

        Ok(())
    }
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
    use serde_json::{json, Value};

    fn document(config: LocalExtractionConfig) -> LocalSubgraphDocument {
        let value: Value =
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
        let local = extract_local_subgraph(&GraphIndexes::new(&graph), &seed, &config).unwrap();
        LocalSubgraphDocument::from_local(&local).unwrap()
    }

    #[test]
    fn explicit_schema_contains_all_step_4_12_fields() {
        let document = document(LocalExtractionConfig::default());
        let value = serde_json::to_value(&document).unwrap();
        for field in [
            "schema_version",
            "seed_id",
            "anchor_function_id",
            "graph_version",
            "extraction_config",
            "nodes",
            "edges",
            "unresolved_calls",
            "truncation",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
        assert_eq!(
            value["schema_version"],
            json!(LOCAL_SUBGRAPH_SCHEMA_VERSION)
        );
    }

    #[test]
    fn schema_pretty_json_round_trip_is_stable() {
        let document = document(LocalExtractionConfig::default());
        let json = document.to_json_pretty().unwrap();
        let parsed = LocalSubgraphDocument::from_json(&json).unwrap();
        assert_eq!(parsed, document);
        assert_eq!(parsed.to_json_pretty().unwrap(), json);
    }

    #[test]
    fn schema_rejects_wrong_versions_and_inconsistent_counts() {
        let document = document(LocalExtractionConfig::default());
        let mut value = serde_json::to_value(&document).unwrap();
        value["schema_version"] = json!("9.9.9");
        assert!(LocalSubgraphDocument::from_json(&value.to_string()).is_err());

        let mut value = serde_json::to_value(&document).unwrap();
        value["truncation"]["counts"]["total_nodes"] = json!(999);
        assert!(LocalSubgraphDocument::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn schema_rejects_fake_edge_endpoint_and_fake_unresolved_target() {
        let document = document(LocalExtractionConfig::default());
        let mut value = serde_json::to_value(&document).unwrap();
        value["edges"][0]["target"] = json!("api:missing");
        assert!(LocalSubgraphDocument::from_json(&value.to_string()).is_err());

        let mut value = serde_json::to_value(&document).unwrap();
        value["unresolved_calls"][0]["callee"] = json!("fn:00402000");
        assert!(LocalSubgraphDocument::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn truncated_document_round_trips_with_explicit_metadata() {
        let document = document(LocalExtractionConfig {
            caller_depth: 0,
            callee_depth: 0,
            max_evidence_nodes: Some(1),
            max_edges: Some(0),
            ..LocalExtractionConfig::default()
        });
        assert!(document.truncation.truncated);
        assert!(!document.truncation.limits_reached.is_empty());
        LocalSubgraphDocument::from_json(&document.to_json_pretty().unwrap()).unwrap();
    }
    #[test]
    fn schema_can_be_written_and_loaded_as_gui_json_file() {
        let document = document(LocalExtractionConfig::default());
        let path = std::env::temp_dir().join(format!(
            "ghidra_local_subgraph_{}_{}.json",
            std::process::id(),
            document.seed_id.replace(':', "_")
        ));
        document.write_pretty(&path).unwrap();
        let loaded = LocalSubgraphDocument::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(loaded, document);
    }
}
