//! Validate seed provenance against the actual graph before extracting any context.
use crate::graph::{EdgeType, GraphNode, NodeType};
use crate::graph_indexes::GraphIndexes;
use crate::schema::{ConsolidatedSeed, SeedCandidate, SeedEvidence};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_seed_candidate(
    index: &GraphIndexes<'_>,
    seed: &SeedCandidate,
) -> Result<(), String> {
    seed.validate()?;
    validate_anchor(index, &seed.anchor_function_id)?;
    for evidence in &seed.evidence {
        validate_evidence(index, &seed.anchor_function_id, evidence)?;
    }
    Ok(())
}

pub fn validate_consolidated_seed(
    index: &GraphIndexes<'_>,
    seed: &ConsolidatedSeed,
) -> Result<(), String> {
    seed.validate()?;
    validate_anchor(index, &seed.anchor_function_id)?;
    for evidence in &seed.evidence {
        validate_evidence(index, &seed.anchor_function_id, evidence)?;
    }
    Ok(())
}

pub fn validate_anchor(index: &GraphIndexes<'_>, anchor: &str) -> Result<(), String> {
    if index.node(anchor).map(|n| n.node_type) != Some(NodeType::Function) {
        return Err(format!(
            "seed anchor '{anchor}' is not an existing FUNCTION node"
        ));
    }
    Ok(())
}

fn text<'a>(node: &'a GraphNode, field: &str) -> Result<&'a str, String> {
    node.properties
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("node '{}' requires '{field}'", node.id))
}

fn strings(properties: &BTreeMap<String, Value>, field: &str) -> Result<Vec<String>, String> {
    let Some(value) = properties.get(field) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("invalid value in {field}"))
        })
        .collect()
}

fn has_site(
    properties: &BTreeMap<String, Value>,
    field: &str,
    fallback: bool,
    site: Option<&str>,
) -> Result<bool, String> {
    let mut sites = strings(properties, field)?;
    if sites.is_empty() && fallback {
        if let Some(value) = properties.get("callsite").filter(|v| !v.is_null()) {
            sites.push(
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or("invalid callsite")?
                    .to_string(),
            );
        }
    }
    Ok(match site {
        Some(site) => sites.iter().any(|s| s == site),
        None => sites.is_empty(),
    })
}

fn validate_evidence(
    index: &GraphIndexes<'_>,
    anchor: &str,
    evidence: &SeedEvidence,
) -> Result<(), String> {
    if evidence.kind == "unresolved_call" {
        if evidence.node_id.is_some() || evidence.edge_type.is_some() {
            return Err("unresolved evidence must not invent a target node or edge".into());
        }
        return if index.graph().unresolved_calls().iter().any(|call| {
            call.caller == anchor
                && call.callsite.as_deref().map(str::trim) == evidence.callsite.as_deref()
                && call.reason.trim() == evidence.value
        }) {
            Ok(())
        } else {
            Err("unresolved evidence does not match an observed record for the anchor".into())
        };
    }
    let id = evidence
        .node_id
        .as_deref()
        .ok_or("node-backed seed evidence requires node_id")?;
    let node = index
        .node(id)
        .ok_or_else(|| format!("missing seed evidence node '{id}'"))?;
    let (kind, relation, relation_name, value) = match evidence.kind.as_str() {
        "api" => (
            NodeType::Api,
            EdgeType::CallsApi,
            "calls_api",
            text(node, "normalized_name")?.to_string(),
        ),
        "string" => (
            NodeType::String,
            EdgeType::ReferencesString,
            "references_string",
            text(node, "value")?.to_string(),
        ),
        "string_category" => (
            NodeType::StringCategory,
            EdgeType::HasStringCategory,
            "has_string_category",
            text(node, "category")?.to_string(),
        ),
        "constant" => {
            let names: BTreeSet<_> = strings(&node.properties, "symbolic_names")?
                .into_iter()
                .collect();
            let value = if names.is_empty() {
                text(node, "value_hex")?.to_string()
            } else {
                names.into_iter().collect::<Vec<_>>().join("|")
            };
            (
                NodeType::Constant,
                EdgeType::UsesConstant,
                "uses_constant",
                value,
            )
        }
        "section" => (
            NodeType::Section,
            EdgeType::BelongsToSection,
            "belongs_to_section",
            text(node, "name")?.to_string(),
        ),
        "visibility_signal" => {
            if !strings(&node.properties, "signals")?
                .iter()
                .any(|s| s == &evidence.value)
            {
                return Err("visibility signal is absent from node".into());
            }
            (
                NodeType::VisibilityIndicator,
                EdgeType::ContainsIndirectCall,
                "contains_indirect_call",
                evidence.value.clone(),
            )
        }
        _ => {
            return Err(format!(
                "unsupported seed evidence kind '{}'",
                evidence.kind
            ))
        }
    };
    if node.node_type != kind
        || evidence.edge_type.as_deref() != Some(relation_name)
        || evidence.value != value
    {
        return Err(format!(
            "inconsistent type, value or relation for evidence '{id}'"
        ));
    }
    if kind == NodeType::StringCategory {
        if evidence.callsite.is_some() {
            return Err("category edge does not carry a callsite".into());
        }
        let found = index
            .outgoing(anchor)
            .iter()
            .filter(|e| e.edge_type == EdgeType::ReferencesString)
            .any(|e| {
                index
                    .outgoing(&e.target)
                    .iter()
                    .any(|category| category.edge_type == relation && category.target == id)
            });
        return if found {
            Ok(())
        } else {
            Err("string category is not linked through a string referenced by the anchor".into())
        };
    }
    for edge in index
        .outgoing(anchor)
        .iter()
        .filter(|e| e.edge_type == relation && e.target == id)
    {
        let valid_site = match kind {
            NodeType::Api => has_site(
                &edge.properties,
                "callsites",
                true,
                evidence.callsite.as_deref(),
            )?,
            NodeType::String => has_site(
                &edge.properties,
                "reference_sites",
                false,
                evidence.callsite.as_deref(),
            )?,
            NodeType::Constant => has_site(
                &edge.properties,
                "use_sites",
                false,
                evidence.callsite.as_deref(),
            )?,
            NodeType::Section => evidence.callsite.is_none(),
            NodeType::VisibilityIndicator => {
                let field = match evidence.value.as_str() {
                    "indirect_call" => Some("indirect_callsites"),
                    "unresolved_call" => Some("unresolved_indirect_callsites"),
                    "dynamic_dispatch" => Some("dynamic_dispatch_callsites"),
                    _ => None,
                };
                match field {
                    Some(field) => {
                        has_site(&node.properties, field, false, evidence.callsite.as_deref())?
                    }
                    None => evidence.callsite.is_none(),
                }
            }
            _ => false,
        };
        if valid_site {
            return Ok(());
        }
    }
    Err(format!(
        "evidence '{id}' has no matching relation/callsite from anchor '{anchor}'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::TypedGraph;
    use crate::schema::build_seed_id;
    use crate::seed_detection::{detect_seed_candidates, detect_seeds};
    use crate::seed_limits::SeedDetectionConfig;
    use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules};

    fn fixture() -> (TypedGraph, Vec<SeedCandidate>) {
        let value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
        let candidates =
            detect_seed_candidates(&value, &load_seed_rules(bundled_seed_rules_path()).unwrap())
                .unwrap();
        (TypedGraph::from_value(&value).unwrap(), candidates)
    }

    #[test]
    fn all_detector_candidates_and_consolidated_seeds_match_the_graph() {
        let (graph, candidates) = fixture();
        let index = GraphIndexes::new(&graph);
        for candidate in candidates {
            validate_seed_candidate(&index, &candidate).unwrap();
        }
        let value = serde_json::to_value(&graph).unwrap();
        let result = detect_seeds(
            &value,
            &load_seed_rules(bundled_seed_rules_path()).unwrap(),
            &SeedDetectionConfig::default(),
        )
        .unwrap();
        for seed in result.seeds {
            validate_consolidated_seed(&index, &seed).unwrap();
        }
    }

    #[test]
    fn anchor_must_exist_and_be_a_function() {
        let (graph, _) = fixture();
        let index = GraphIndexes::new(&graph);
        assert!(validate_anchor(&index, "fn:missing").is_err());
        assert!(validate_anchor(&index, "api:virtualalloc").is_err());
    }

    #[test]
    fn existing_but_unrelated_anchor_does_not_validate() {
        let (graph, mut candidates) = fixture();
        let index = GraphIndexes::new(&graph);
        let seed = &mut candidates[0];
        seed.anchor_function_id = "fn:00402000".into();
        seed.seed_id = build_seed_id(&seed.anchor_function_id, &seed.trigger_id).unwrap();
        assert!(validate_seed_candidate(&index, seed).is_err());
    }

    #[test]
    fn node_value_relation_and_callsite_must_match_observed_evidence() {
        let (graph, candidates) = fixture();
        let index = GraphIndexes::new(&graph);
        for field in ["node", "value", "edge", "callsite", "missing_site"] {
            let mut seed = candidates[0].clone();
            let e = &mut seed.evidence[0];
            match field {
                "node" => e.node_id = Some("api:missing".into()),
                "value" => e.value = "InventedAPI".into(),
                "edge" => e.edge_type = Some("references_string".into()),
                "callsite" => e.callsite = Some("ffffffff".into()),
                _ => e.callsite = None,
            }
            assert!(validate_seed_candidate(&index, &seed).is_err(), "{field}");
        }
    }

    #[test]
    fn category_requires_an_actual_reference_path_from_the_anchor() {
        let (graph, candidates) = fixture();
        let seed = candidates
            .iter()
            .find(|s| s.trigger_id == "string_category.powershell")
            .unwrap();
        let mut value = serde_json::to_value(&graph).unwrap();
        value["edges"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["type"] != "references_string");
        let graph = TypedGraph::from_value(&value).unwrap();
        assert!(validate_seed_candidate(&GraphIndexes::new(&graph), seed).is_err());
    }

    #[test]
    fn unresolved_provenance_must_match_record_and_never_invents_node() {
        let (graph, candidates) = fixture();
        let index = GraphIndexes::new(&graph);
        let seed = candidates
            .iter()
            .find(|s| s.trigger_id == "unresolved_call.present")
            .unwrap();
        let mut wrong = seed.clone();
        wrong.evidence[0].value = "invented reason".into();
        assert!(validate_seed_candidate(&index, &wrong).is_err());
        wrong = seed.clone();
        wrong.evidence[0].node_id = Some("fn:00402000".into());
        assert!(validate_seed_candidate(&index, &wrong).is_err());
        wrong = seed.clone();
        wrong.evidence[0].callsite = Some("00409999".into());
        assert!(validate_seed_candidate(&index, &wrong).is_err());
    }
}
