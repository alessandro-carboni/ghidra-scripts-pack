//! Opt-in hybrid graph: legacy graph plus per-function operation networks.
use crate::graph::{NodeType, TypedGraph};
use crate::graph_indexes::GraphIndexes;
use crate::local_subgraph::{extract_anchor_subgraph, LocalExtractionConfig};
use crate::local_subgraph_schema::LocalSubgraphDocument;
use crate::operational_schema::{ensure, is_hash, Evidence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|e| e.to_string())?)
    ))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphBundle {
    pub schema_version: String,
    pub typed_graph: TypedGraph,
    pub operational_evidence: Vec<Evidence>,
}
impl GraphBundle {
    pub fn validate(&self) -> Result<String, String> {
        ensure(
            self.schema_version == "osgf.typed-operational-graph/0.2.0",
            "unsupported operational graph",
        )?;
        let hash = self
            .typed_graph
            .metadata()
            .get("research_binary_sha256")
            .and_then(|v| v.as_str())
            .ok_or("typed graph requires observed research_binary_sha256")?;
        ensure(is_hash(hash), "invalid typed source hash")?;
        let functions: BTreeSet<_> = self
            .typed_graph
            .nodes()
            .iter()
            .filter(|n| n.node_type == NodeType::Function)
            .map(|n| n.id.as_str())
            .collect();
        let mut seen = BTreeSet::new();
        for doc in &self.operational_evidence {
            doc.validate()?;
            ensure(
                doc.source.sha256 == hash,
                "cross-binary attachment rejected",
            )?;
            ensure(
                functions.contains(doc.function.id.as_str()),
                "unknown operational function",
            )?;
            ensure(
                seen.insert(&doc.function.id),
                "duplicate function evidence; keep Raw/High in separate bundles",
            )?;
            if let Some(first) = self.operational_evidence.first() {
                ensure(
                    doc.environment == first.environment
                        && doc.representation == first.representation,
                    "mixed extraction domains",
                )?;
            }
        }
        Ok(hash.to_string())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfig {
    pub structural: LocalExtractionConfig,
    pub max_operational_functions: usize,
    pub max_operations: usize,
    pub max_dependencies: usize,
}
impl ContextConfig {
    fn validate(&self) -> Result<(), String> {
        self.structural.validate()?;
        ensure(
            self.max_operational_functions > 0
                && self.max_operations > 0
                && self.max_dependencies > 0,
            "operational budgets must be positive",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEvidence {
    pub schema_version: String,
    pub binary_sha256: String,
    pub source_graph_sha256: String,
    pub configuration: ContextConfig,
    pub structural: LocalSubgraphDocument,
    pub operational_evidence: Vec<Evidence>,
    pub coverage: BTreeMap<String, String>,
}
impl LocalEvidence {
    pub fn from_graph(
        graph: &GraphBundle,
        anchor: &str,
        config: ContextConfig,
    ) -> Result<Self, String> {
        let binary_sha256 = graph.validate()?;
        config.validate()?;
        let structural = LocalSubgraphDocument::from_local(&extract_anchor_subgraph(
            &GraphIndexes::new(&graph.typed_graph),
            anchor,
            &config.structural,
        )?)?;
        let mut result = Self {
            schema_version: "osgf.local-operational-subgraph/0.2.0".into(),
            binary_sha256,
            source_graph_sha256: digest(&graph.typed_graph)?,
            configuration: config,
            structural,
            operational_evidence: Vec::new(),
            coverage: BTreeMap::new(),
        };
        let mut functions: Vec<_> = result
            .structural
            .function_selection
            .function_ids
            .iter()
            .cloned()
            .collect();
        functions.sort_by_key(|id| (id != anchor, id.clone()));
        let mut ops_remaining = result.configuration.max_operations;
        let mut deps_remaining = result.configuration.max_dependencies;
        for function in functions {
            let Some(doc) = graph
                .operational_evidence
                .iter()
                .find(|d| d.function.id == function)
            else {
                result.coverage.insert(function, "missing".into());
                continue;
            };
            if result.operational_evidence.len() == result.configuration.max_operational_functions
                || ops_remaining == 0
            {
                result.coverage.insert(function, "budget_excluded".into());
                continue;
            }
            let mut doc = doc.clone();
            doc.operations
                .sort_by_key(|o| o.id[3..].parse::<usize>().unwrap());
            doc.dependencies.sort();
            let before = (doc.operations.len(), doc.dependencies.len());
            doc.operations.truncate(ops_remaining);
            let ids: BTreeSet<_> = doc.operations.iter().map(|o| o.id.clone()).collect();
            doc.dependencies
                .retain(|d| ids.contains(&d.from) && ids.contains(&d.to));
            doc.dependencies.truncate(deps_remaining);
            if before != (doc.operations.len(), doc.dependencies.len()) {
                doc.observability.truncated = true;
                doc.observability.state = "partial".into();
                doc.observability.reason = "local operational retention budget reached".into();
            }
            ops_remaining -= doc.operations.len();
            deps_remaining -= doc.dependencies.len();
            result.coverage.insert(function, "observed".into());
            result.operational_evidence.push(doc);
        }
        result
            .operational_evidence
            .sort_by(|a, b| a.function.id.cmp(&b.function.id));
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), String> {
        ensure(
            self.schema_version == "osgf.local-operational-subgraph/0.2.0",
            "unsupported operational local schema",
        )?;
        ensure(
            is_hash(&self.binary_sha256) && is_hash(&self.source_graph_sha256),
            "invalid local source identity",
        )?;
        self.configuration.validate()?;
        self.structural.validate()?;
        ensure(
            self.structural.extraction_config == self.configuration.structural,
            "structural configuration mismatch",
        )?;
        ensure(
            self.coverage.keys().cloned().collect::<BTreeSet<_>>()
                == self.structural.function_selection.function_ids,
            "incomplete function coverage",
        )?;
        let mut seen = BTreeSet::new();
        for doc in &self.operational_evidence {
            doc.validate()?;
            ensure(
                doc.source.sha256 == self.binary_sha256
                    && self.coverage.get(&doc.function.id).map(String::as_str) == Some("observed"),
                "invalid operational attachment",
            )?;
            ensure(
                seen.insert(doc.function.id.clone()),
                "duplicate function attachment",
            )?;
            if let Some(first) = self.operational_evidence.first() {
                ensure(
                    doc.environment == first.environment
                        && doc.representation == first.representation,
                    "mixed local extraction domains",
                )?;
            }
        }
        for (id, status) in &self.coverage {
            ensure(
                ["observed", "missing", "budget_excluded"].contains(&status.as_str()),
                "invalid coverage state",
            )?;
            ensure(
                (status == "observed") == seen.contains(id),
                "coverage/evidence mismatch",
            )?;
        }
        ensure(
            self.operational_evidence.len() <= self.configuration.max_operational_functions,
            "function budget exceeded",
        )?;
        // Checked subtraction avoids overflow in malformed untrusted collections.
        let mut ops = self.configuration.max_operations;
        let mut deps = self.configuration.max_dependencies;
        for doc in &self.operational_evidence {
            ops = ops
                .checked_sub(doc.operations.len())
                .ok_or("operation budget exceeded")?;
            deps = deps
                .checked_sub(doc.dependencies.len())
                .ok_or("dependency budget exceeded")?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    pub fn bundle() -> GraphBundle {
        let doc: Evidence = serde_json::from_str(include_str!(
            "../../tests/fixtures/pcode_evidence_v0_1/sum_array-high.json"
        ))
        .unwrap();
        let graph=TypedGraph::from_value(&json!({"model_version":"0.12.0","metadata":{"research_binary_sha256":doc.source.sha256},"nodes":[{"id":doc.function.id,"type":"FUNCTION","properties":{}}],"edges":[],"unresolved_calls":[]})).unwrap();
        GraphBundle {
            schema_version: "osgf.typed-operational-graph/0.2.0".into(),
            typed_graph: graph,
            operational_evidence: vec![doc],
        }
    }
    pub fn config() -> ContextConfig {
        ContextConfig {
            structural: LocalExtractionConfig {
                caller_depth: 0,
                callee_depth: 0,
                ..Default::default()
            },
            max_operational_functions: 4,
            max_operations: 1000,
            max_dependencies: 2000,
        }
    }
    #[test]
    fn source_binding_and_duplicates() {
        let mut g = bundle();
        g.validate().unwrap();
        g.operational_evidence[0].source.sha256 = "b".repeat(64);
        assert!(g.validate().is_err());
        let mut g = bundle();
        g.operational_evidence
            .push(g.operational_evidence[0].clone());
        assert!(g.validate().is_err());
    }
    #[test]
    fn anchor_and_budgets_keep_explicit_partial() {
        let g = bundle();
        let anchor = &g.operational_evidence[0].function.id;
        let full = LocalEvidence::from_graph(&g, anchor, config()).unwrap();
        assert_eq!(full.operational_evidence[0].observability.state, "complete");
        let mut c = config();
        c.max_operations = 2;
        let small = LocalEvidence::from_graph(&g, anchor, c).unwrap();
        assert_eq!(small.operational_evidence[0].operations.len(), 2);
        assert!(small.operational_evidence[0].observability.truncated);
        small.validate().unwrap();
    }
    #[test]
    fn absent_is_not_empty_observed() {
        let mut g = bundle();
        let anchor = g.operational_evidence[0].function.id.clone();
        g.operational_evidence.clear();
        let local = LocalEvidence::from_graph(&g, &anchor, config()).unwrap();
        assert_eq!(local.coverage[&anchor], "missing");
    }
}
