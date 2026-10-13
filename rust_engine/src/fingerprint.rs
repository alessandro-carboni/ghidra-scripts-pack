//! OSGF Fingerprint Baseline v0.1: deterministic views, no scoring or classification.
use crate::canonical::{CanonicalEdge, CanonicalSubgraph};
use crate::fingerprint_motifs::{MotifBuffer, MotifTruncation};
use crate::fingerprint_provenance::{FeatureCoverage, SourceCoverageTotals};
use crate::graph::{EdgeType, NodeType};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OSGF_FINGERPRINT_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintConfig {
    pub max_topology_motifs: usize,
    pub max_interaction_motifs: usize,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            max_topology_motifs: 4096,
            max_interaction_motifs: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintFeature {
    pub id: String,
    pub descriptor: Value,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintView {
    RootedTopology,
    TypedEvidence,
    InteractionMotif,
    Observability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureOccurrence {
    pub canonical_elements: Vec<String>,
    pub multiplicity: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsgfFingerprint {
    pub schema_version: String,
    pub canonicalization_version: String,
    pub source_canonical_schema_version: String,
    pub source_canonical_digest: String,
    pub rooted_topology_view: Vec<FingerprintFeature>,
    pub typed_evidence_view: Vec<FingerprintFeature>,
    pub interaction_motif_view: Vec<FingerprintFeature>,
    pub observability_view: Vec<FingerprintFeature>,
    pub provenance_index: BTreeMap<String, Vec<FeatureOccurrence>>,
    pub config: FingerprintConfig,
    pub motif_truncation: BTreeMap<String, MotifTruncation>,
    pub canonical_coverage: BTreeMap<String, FeatureCoverage>,
    pub source_coverage_totals: SourceCoverageTotals,
    pub semantic_digest: String,
    pub fingerprint_digest: String,
}

impl OsgfFingerprint {
    pub fn from_canonical(canonical: &CanonicalSubgraph) -> Result<Self, String> {
        Self::with_config(canonical, FingerprintConfig::default())
    }

    pub fn with_config(
        canonical: &CanonicalSubgraph,
        config: FingerprintConfig,
    ) -> Result<Self, String> {
        let canonical = normalized_canonical(canonical)?;
        let canonical = &canonical;
        if config.max_topology_motifs > 100_000 || config.max_interaction_motifs > 100_000 {
            return Err("motif retention limits must be between 0 and 100000".into());
        }
        let mut fingerprint = Self {
            schema_version: OSGF_FINGERPRINT_VERSION.into(),
            canonicalization_version: canonical.canonicalization_version.clone(),
            source_canonical_schema_version: canonical.schema_version.clone(),
            source_canonical_digest: canonical.canonical_digest.clone(),
            rooted_topology_view: Vec::new(),
            typed_evidence_view: Vec::new(),
            interaction_motif_view: Vec::new(),
            observability_view: Vec::new(),
            provenance_index: BTreeMap::new(),
            config,
            motif_truncation: BTreeMap::new(),
            canonical_coverage: BTreeMap::new(),
            source_coverage_totals: SourceCoverageTotals::default(),
            semantic_digest: String::new(),
            fingerprint_digest: String::new(),
        };
        fingerprint.root_roles(canonical)?;
        fingerprint.function_relations(canonical)?;
        fingerprint.topology_motifs(canonical)?;
        fingerprint.typed_evidence(canonical)?;
        fingerprint.category_chains(canonical)?;
        fingerprint.interaction_motifs(canonical)?;
        fingerprint.observability(canonical)?;
        fingerprint.index_coverage(canonical);
        fingerprint.finalize();
        Ok(fingerprint)
    }

    fn finalize(&mut self) {
        for view in [
            &mut self.rooted_topology_view,
            &mut self.typed_evidence_view,
            &mut self.interaction_motif_view,
            &mut self.observability_view,
        ] {
            view.sort_by(|a, b| a.id.cmp(&b.id));
        }
        for occurrences in self.provenance_index.values_mut() {
            occurrences.sort_by_key(|o| serde_json::to_string(o).unwrap());
        }
        self.semantic_digest = digest(&self.semantic_value());
        let mut payload = serde_json::to_value(&self).unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .remove("fingerprint_digest");
        self.fingerprint_digest = digest(&payload);
    }

    pub fn to_json_pretty(&self, canonical: &CanonicalSubgraph) -> Result<String, String> {
        self.validate_against(canonical)?;
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    pub fn from_json(text: &str, canonical: &CanonicalSubgraph) -> Result<Self, String> {
        let fingerprint: Self =
            serde_json::from_str(text).map_err(|e| format!("invalid fingerprint JSON: {e}"))?;
        fingerprint.validate_against(canonical)?;
        Ok(fingerprint)
    }

    fn index_coverage(&mut self, c: &CanonicalSubgraph) {
        let ids = c
            .nodes
            .iter()
            .map(|n| n.id.as_str())
            .chain(c.edges.iter().map(|e| e.id.as_str()))
            .chain(c.unresolved_calls.iter().map(|u| u.id.as_str()))
            .chain(["@local_graph_truncation", "@coverage_ledger"]);
        for element in ids {
            let feature_ids: Vec<_> = self
                .provenance_index
                .iter()
                .filter(|(_, occurrences)| {
                    occurrences
                        .iter()
                        .any(|o| o.canonical_elements.iter().any(|id| id == element))
                })
                .map(|(id, _)| id.clone())
                .collect();
            let disposition = if feature_ids.is_empty() {
                FeatureCoverage::Excluded {
                    reason: "not_part_of_a_supported_feature; retained_in_canonical_source".into(),
                }
            } else {
                FeatureCoverage::Represented { feature_ids }
            };
            self.canonical_coverage.insert(element.into(), disposition);
        }
        self.source_coverage_totals = SourceCoverageTotals {
            nodes: c.coverage_ledger.source_nodes,
            edges: c.coverage_ledger.source_edges,
            unresolved_records: c.coverage_ledger.source_unresolved_records,
            represented: c.coverage_ledger.represented,
            excluded: c.coverage_ledger.excluded,
        };
    }

    /// Source identity, observability and provenance are outside semantic comparison.
    pub fn semantic_value(&self) -> Value {
        let sorted = |features: &[FingerprintFeature]| {
            let mut features = features.to_vec();
            features.sort_by(|a, b| a.id.cmp(&b.id));
            features
        };
        json!({"schema_version":self.schema_version, "canonicalization_version":self.canonicalization_version,
            "rooted_topology_view":sorted(&self.rooted_topology_view),
            "typed_evidence_view":sorted(&self.typed_evidence_view),
            "interaction_motif_view":sorted(&self.interaction_motif_view)})
    }

    fn observability(&mut self, c: &CanonicalSubgraph) -> Result<(), String> {
        let nodes: BTreeMap<_, _> = c.nodes.iter().map(|n| (&n.id, n)).collect();
        for node in c
            .nodes
            .iter()
            .filter(|n| n.kind == NodeType::VisibilityIndicator)
        {
            let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for edge in c
                .edges
                .iter()
                .filter(|e| e.kind == EdgeType::ContainsIndirectCall && e.target == node.id)
            {
                owners
                    .entry(edge.source.clone())
                    .or_default()
                    .push(edge.id.clone());
            }
            if owners.is_empty() {
                owners.insert(String::new(), Vec::new());
            }
            for (owner, edges) in owners {
                let function = nodes.get(&owner).map(|n| n.facts.clone());
                let mut support = edges;
                support.push(node.id.clone());
                if !owner.is_empty() {
                    support.push(owner);
                }
                for kind in [
                    "indirect_calls",
                    "unresolved_indirect_calls",
                    "explicit_dynamic_dispatch",
                ] {
                    self.add_feature(FingerprintView::Observability,
                        json!({"kind":kind, "function":function, "observed_count":node.facts[kind]}), 1, support.clone())?;
                }
            }
        }
        for call in &c.unresolved_calls {
            self.add_feature(
                FingerprintView::Observability,
                json!({"kind":"unresolved_call", "function":nodes[&call.caller].facts,
                    "direct":call.facts["direct"], "indirect":call.facts["indirect"]}),
                call.facts["occurrences"]
                    .as_u64()
                    .ok_or("invalid unresolved occurrence count")?,
                vec![call.caller.clone(), call.id.clone()],
            )?;
        }
        self.add_feature(FingerprintView::Observability,
            json!({"kind":"extraction_completeness", "local_graph":c.local_graph_truncation,
                "canonical_coverage":{"represented":c.coverage_ledger.represented, "excluded":c.coverage_ledger.excluded}}),
            1, vec!["@local_graph_truncation".into(), "@coverage_ledger".into()])?;
        Ok(())
    }

    fn finish_motifs(
        &mut self,
        view: FingerprintView,
        name: &str,
        buffer: MotifBuffer,
    ) -> Result<(), String> {
        let (metadata, candidates) = buffer.finish();
        for c in candidates {
            self.add_feature(view, c.descriptor, c.count, c.elements)?;
        }
        self.motif_truncation.insert(name.into(), metadata);
        Ok(())
    }

    fn view_mut(&mut self, view: FingerprintView) -> &mut Vec<FingerprintFeature> {
        match view {
            FingerprintView::RootedTopology => &mut self.rooted_topology_view,
            FingerprintView::TypedEvidence => &mut self.typed_evidence_view,
            FingerprintView::InteractionMotif => &mut self.interaction_motif_view,
            FingerprintView::Observability => &mut self.observability_view,
        }
    }

    fn add_feature(
        &mut self,
        view: FingerprintView,
        descriptor: Value,
        count: u64,
        mut elements: Vec<String>,
    ) -> Result<(), String> {
        if count == 0 {
            return Err("feature multiplicity must be positive".into());
        }
        let id = format!(
            "feature:{:x}",
            Sha256::digest(json!([view, descriptor]).to_string().as_bytes())
        );
        let features = self.view_mut(view);
        if let Some(feature) = features.iter_mut().find(|f| f.id == id) {
            feature.count = feature
                .count
                .checked_add(count)
                .ok_or("feature count overflow")?;
        } else {
            features.push(FingerprintFeature {
                id: id.clone(),
                descriptor,
                count,
            });
        }
        elements.sort();
        elements.dedup();
        self.provenance_index
            .entry(id)
            .or_default()
            .push(FeatureOccurrence {
                canonical_elements: elements,
                multiplicity: count,
            });
        Ok(())
    }

    fn root_roles(&mut self, canonical: &CanonicalSubgraph) -> Result<(), String> {
        for node in canonical
            .nodes
            .iter()
            .filter(|n| n.kind == NodeType::Function)
        {
            self.add_feature(
                FingerprintView::RootedTopology,
                json!({
                    "kind": "root_role",
                    "role": node.facts["role"]
                }),
                1,
                vec![node.id.clone()],
            )?;
            for direction in ["caller", "callee"] {
                if let Some(distance) = node.facts[format!("{direction}_distance")].as_u64() {
                    self.add_feature(FingerprintView::RootedTopology, json!({"kind":"distance_distribution", "direction":direction, "distance":distance}), 1, vec![node.id.clone()])?;
                }
            }
        }
        Ok(())
    }

    fn function_relations(&mut self, canonical: &CanonicalSubgraph) -> Result<(), String> {
        let nodes: BTreeMap<_, _> = canonical.nodes.iter().map(|n| (&n.id, n)).collect();
        for edge in canonical
            .edges
            .iter()
            .filter(|e| e.kind == EdgeType::CallsFunction)
        {
            self.add_feature(FingerprintView::RootedTopology,
                json!({"kind":"function_call", "source":nodes[&edge.source].facts, "target":nodes[&edge.target].facts}),
                edge.facts["occurrences"].as_u64().ok_or("invalid function-call multiplicity")?,
                vec![edge.source.clone(), edge.id.clone(), edge.target.clone()])?;
        }
        Ok(())
    }

    fn typed_evidence(&mut self, canonical: &CanonicalSubgraph) -> Result<(), String> {
        let nodes: BTreeMap<_, _> = canonical.nodes.iter().map(|n| (&n.id, n)).collect();
        for edge in canonical.edges.iter().filter(|e| is_evidence_edge(e.kind)) {
            let target = nodes[&edge.target];
            self.add_feature(
                FingerprintView::TypedEvidence,
                json!({"kind":"typed_evidence", "function":nodes[&edge.source].facts,
                    "relation":edge.kind, "evidence_type":target.kind, "evidence":target.facts}),
                edge.facts["occurrences"]
                    .as_u64()
                    .ok_or("invalid evidence occurrence count")?,
                vec![edge.source.clone(), edge.id.clone(), edge.target.clone()],
            )?;
        }
        Ok(())
    }

    fn category_chains(&mut self, c: &CanonicalSubgraph) -> Result<(), String> {
        let nodes: BTreeMap<_, _> = c.nodes.iter().map(|n| (&n.id, n)).collect();
        for reference in c
            .edges
            .iter()
            .filter(|e| e.kind == EdgeType::ReferencesString)
        {
            for category in c
                .edges
                .iter()
                .filter(|e| e.kind == EdgeType::HasStringCategory && e.source == reference.target)
            {
                self.add_feature(
                    FingerprintView::TypedEvidence,
                    json!({"kind":"category_chain", "function":nodes[&reference.source].facts,
                        "relations":["references_string", "has_string_category"],
                        "intermediate_type":"STRING", "category":nodes[&category.target].facts}),
                    1,
                    edge_support(reference, category),
                )?;
            }
        }
        Ok(())
    }

    fn interaction_motifs(&mut self, c: &CanonicalSubgraph) -> Result<(), String> {
        let mut candidates = MotifBuffer::new(self.config.max_interaction_motifs);
        let nodes: BTreeMap<_, _> = c.nodes.iter().map(|n| (&n.id, n)).collect();
        for _ in 0..c.edges.len().saturating_mul(
            c.edges
                .iter()
                .filter(|e| e.kind == EdgeType::CallsFunction)
                .count(),
        ) {
            candidates.check()?;
        }
        for call in c.edges.iter().filter(|e| e.kind == EdgeType::CallsFunction) {
            for evidence in c
                .edges
                .iter()
                .filter(|e| e.source == call.target && is_evidence_edge(e.kind))
            {
                candidates.add(
                    json!({
                        "kind": "call_evidence",
                        "caller": nodes[&call.source].facts,
                        "callee": nodes[&call.target].facts,
                        "recursive": call.source == call.target,
                        "relations": ["calls_function", evidence.kind],
                        "evidence_type": nodes[&evidence.target].kind,
                        "evidence": nodes[&evidence.target].facts
                    }),
                    1,
                    edge_support(call, evidence),
                )?;
                if evidence.kind == EdgeType::ReferencesString {
                    for _ in &c.edges {
                        candidates.check()?;
                    }
                    for category in c.edges.iter().filter(|e| {
                        e.kind == EdgeType::HasStringCategory && e.source == evidence.target
                    }) {
                        let count = 1;
                        let mut support = edge_support(call, evidence);
                        support.extend([category.id.clone(), category.target.clone()]);

                        candidates.add(
                            json!({
                                "kind": "call_category_chain",
                                "caller": nodes[&call.source].facts,
                                "callee": nodes[&call.target].facts,
                                "recursive": call.source == call.target,
                                "relations": [
                                    "calls_function",
                                    "references_string",
                                    "has_string_category"
                                ],
                                "category": nodes[&category.target].facts
                            }),
                            count,
                            support,
                        )?;
                    }
                }
            }
        }
        self.finish_motifs(FingerprintView::InteractionMotif, "interaction", candidates)
    }

    /// Exactly two distinct call edges, with the anchor at any path position.
    /// Forks are unordered pairs with two distinct branch functions.
    fn topology_motifs(&mut self, c: &CanonicalSubgraph) -> Result<(), String> {
        let mut candidates = MotifBuffer::new(self.config.max_topology_motifs);
        let nodes: BTreeMap<_, _> = c.nodes.iter().map(|n| (&n.id, n)).collect();
        let anchor = &c
            .nodes
            .iter()
            .find(|n| n.kind == NodeType::Function && n.facts["role"] == "ANCHOR")
            .ok_or("missing anchor")?
            .id;
        let calls: Vec<_> = c
            .edges
            .iter()
            .filter(|e| e.kind == EdgeType::CallsFunction)
            .collect();
        for (i, first) in calls.iter().enumerate() {
            for (j, second) in calls.iter().enumerate() {
                candidates.check()?;
                if i == j {
                    continue;
                }
                if first.target == second.source
                    && [&first.source, &first.target, &second.target].contains(&anchor)
                {
                    let path = [&first.source, &first.target, &second.target];
                    let pattern: Vec<_> = path
                        .iter()
                        .map(|id| path.iter().position(|p| p == id).unwrap())
                        .collect();
                    candidates.add(
                        json!({
                            "kind": "rooted_path",
                            "functions": path
                                .iter()
                                .map(|id| &nodes[*id].facts)
                                .collect::<Vec<_>>(),
                            "node_pattern": pattern
                        }),
                        1,
                        edge_support(first, second),
                    )?;
                }
                if i >= j {
                    continue;
                }
                let fork = if &first.source == anchor
                    && &second.source == anchor
                    && first.target != second.target
                {
                    Some(("out", &first.target, &second.target))
                } else if &first.target == anchor
                    && &second.target == anchor
                    && first.source != second.source
                {
                    Some(("in", &first.source, &second.source))
                } else {
                    None
                };
                if let Some((direction, a, b)) = fork {
                    let mut branches = vec![nodes[a].facts.clone(), nodes[b].facts.clone()];
                    branches.sort_by_key(Value::to_string);
                    candidates.add(
                        json!({
                            "kind": "rooted_fork",
                            "direction": direction,
                            "anchor": nodes[anchor].facts,
                            "branches": branches
                        }),
                        1,
                        edge_support(first, second),
                    )?;
                }
            }
        }
        self.finish_motifs(FingerprintView::RootedTopology, "topology", candidates)
    }
}

fn digest(value: &Value) -> String {
    format!("sha256:{:x}", Sha256::digest(value.to_string().as_bytes()))
}

/// Canonical arrays are unordered input collections. All other source/provenance
/// contracts must still match; rebuilding alone must never conceal tampering.
fn normalized_canonical(input: &CanonicalSubgraph) -> Result<CanonicalSubgraph, String> {
    let expected = CanonicalSubgraph::from_source(&input.source_document)?;
    let sort = |c: &mut CanonicalSubgraph| {
        c.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        c.edges.sort_by(|a, b| a.id.cmp(&b.id));
        c.unresolved_calls.sort_by(|a, b| a.id.cmp(&b.id));
    };
    let mut candidate = input.clone();
    let mut comparison = expected.clone();
    sort(&mut candidate);
    sort(&mut comparison);
    if candidate != comparison {
        return Err("canonical input does not match its verified source".into());
    }
    Ok(expected)
}

fn is_evidence_edge(kind: EdgeType) -> bool {
    matches!(
        kind,
        EdgeType::CallsApi
            | EdgeType::ReferencesString
            | EdgeType::UsesConstant
            | EdgeType::BelongsToSection
    )
}

fn edge_support(a: &CanonicalEdge, b: &CanonicalEdge) -> Vec<String> {
    vec![
        a.source.clone(),
        a.id.clone(),
        a.target.clone(),
        b.source.clone(),
        b.id.clone(),
        b.target.clone(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_subgraph_schema::LocalSubgraphDocument;

    fn canonical() -> CanonicalSubgraph {
        let local: LocalSubgraphDocument =
            serde_json::from_str(include_str!("../tests/fixtures/canonical_local_v0_1.json"))
                .unwrap();
        CanonicalSubgraph::from_source(&local).unwrap()
    }

    #[test]
    fn step_6_12_frozen_digests_and_sidecar_validation() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let golden: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/fingerprint_v0_1_digests.json"
        ))
        .unwrap();
        assert_eq!(f.semantic_digest, golden["semantic_digest"]);
        assert_eq!(f.fingerprint_digest, golden["fingerprint_digest"]);
        let mut sidecar = f.resolve_provenance(&c).unwrap();
        sidecar.validate_against(&f, &c).unwrap();
        sidecar.features.values_mut().next().unwrap()[0].multiplicity += 1;
        assert!(sidecar.validate_against(&f, &c).is_err());
    }

    #[test]
    fn step_6_12_observability_and_completeness_stay_separate_under_limits() {
        use crate::local_subgraph::{
            LocalGraphLimitKind, ReachedLocalGraphLimit, TruncationReason,
        };
        let c = canonical();
        let config = FingerprintConfig {
            max_topology_motifs: 1,
            max_interaction_motifs: 1,
        };
        let baseline = OsgfFingerprint::with_config(&c, config.clone()).unwrap();
        let mut source = c.source_document.clone();
        source
            .nodes
            .iter_mut()
            .find(|n| n.node_type == NodeType::VisibilityIndicator)
            .unwrap()
            .properties
            .insert("dynamic_dispatch_callsites".into(), json!(["004010aa"]));
        source.extraction_config.max_edges = Some(source.edges.len());
        source.truncation.truncated = true;
        source.truncation.reason = Some(TruncationReason::ResourceLimit);
        source.truncation.limits_reached = vec![ReachedLocalGraphLimit {
            kind: LocalGraphLimitKind::Edges,
            configured_limit: source.edges.len(),
        }];
        let changed =
            OsgfFingerprint::with_config(&CanonicalSubgraph::from_source(&source).unwrap(), config)
                .unwrap();
        assert_eq!(baseline.semantic_digest, changed.semantic_digest);
        assert_eq!(baseline.semantic_value(), changed.semantic_value());
        assert_ne!(baseline.fingerprint_digest, changed.fingerprint_digest);
    }

    #[test]
    fn step_6_12_evidence_attachment_changes_semantics() {
        let c = canonical();
        let baseline = OsgfFingerprint::from_canonical(&c).unwrap();
        let mut source = c.source_document.clone();
        let edge = source
            .edges
            .iter_mut()
            .find(|e| e.edge_type == EdgeType::CallsApi && e.source == "fn:00402000")
            .unwrap();
        edge.source = "fn:00401000".into();
        let changed =
            OsgfFingerprint::from_canonical(&CanonicalSubgraph::from_source(&source).unwrap())
                .unwrap();
        assert_ne!(baseline.semantic_digest, changed.semantic_digest);
        assert_ne!(
            baseline.interaction_motif_view,
            changed.interaction_motif_view
        );
    }

    #[test]
    fn step_6_11_serialization_and_digests_are_order_invariant() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let bytes = f.to_json_pretty(&c).unwrap();
        let mut permuted = c.clone();
        permuted.nodes.reverse();
        permuted.edges.reverse();
        permuted.unresolved_calls.reverse();
        let other = OsgfFingerprint::from_canonical(&permuted).unwrap();
        assert_eq!(bytes, other.to_json_pretty(&permuted).unwrap());
        assert_eq!(f, OsgfFingerprint::from_json(&bytes, &c).unwrap());
        let mut tampered = f.clone();
        tampered.semantic_digest = "sha256:fake".into();
        assert!(tampered.validate_against(&c).is_err());
        let mut tampered = f;
        tampered.rooted_topology_view[0].count += 1;
        assert!(tampered.validate_against(&c).is_err());
        permuted.nodes[0].facts["score"] = json!(99);
        assert!(OsgfFingerprint::from_canonical(&permuted).is_err());
    }

    #[test]
    fn step_6_11_relocation_preserves_complete_fingerprint_bytes() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let raw = serde_json::to_string(&c.source_document)
            .unwrap()
            .replace("004010", "00f010")
            .replace("004020", "001020")
            .replace("004030", "002030");
        let local = serde_json::from_str(&raw).unwrap();
        let relocated = CanonicalSubgraph::from_source(&local).unwrap();
        let other = OsgfFingerprint::from_canonical(&relocated).unwrap();
        assert_eq!(
            f.to_json_pretty(&c).unwrap(),
            other.to_json_pretty(&relocated).unwrap()
        );
        assert_ne!(
            f.resolve_provenance(&c).unwrap().source_document,
            other
                .resolve_provenance(&relocated)
                .unwrap()
                .source_document
        );
    }

    #[test]
    fn step_6_10_all_feature_provenance_resolves_to_source() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let resolved = f.resolve_provenance(&c).unwrap();
        let source = serde_json::to_value(&resolved.source_document).unwrap();
        assert_eq!(resolved.features.len(), f.provenance_index.len());
        for occurrences in resolved.features.values() {
            for occurrence in occurrences {
                for origin in &occurrence.origins {
                    assert!(
                        !origin.source_references.is_empty()
                            || !origin.source_metadata_paths.is_empty()
                    );
                    for path in origin
                        .source_references
                        .iter()
                        .flat_map(|r| &r.property_paths)
                        .chain(&origin.source_metadata_paths)
                    {
                        assert!(source.pointer(path).is_some(), "missing {path}");
                    }
                }
            }
        }
        assert_eq!(
            f.canonical_coverage.len(),
            c.nodes.len() + c.edges.len() + c.unresolved_calls.len() + 2
        );
        assert!(f
            .canonical_coverage
            .values()
            .all(|v| matches!(v, FeatureCoverage::Represented { .. })));
        let mut broken = f;
        broken.provenance_index.values_mut().next().unwrap()[0]
            .canonical_elements
            .push("fake".into());
        assert!(broken.resolve_provenance(&c).is_err());
    }

    #[test]
    fn step_6_10_orphan_evidence_is_explicitly_accounted_for() {
        let mut source = canonical().source_document;
        source.nodes.push(crate::graph::GraphNode {
            id: "api:orphan".into(),
            node_type: NodeType::Api,
            properties: BTreeMap::from([("name".into(), json!("OrphanApi"))]),
        });
        source.truncation.counts.total_nodes += 1;
        source.truncation.counts.evidence_nodes += 1;
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        assert_eq!(
            f.canonical_coverage
                .values()
                .filter(|v| matches!(v, FeatureCoverage::Excluded { .. }))
                .count(),
            1
        );
        f.resolve_provenance(&c).unwrap();
    }

    #[test]
    fn step_6_9_observability_does_not_change_semantic_views() {
        let c = canonical();
        let baseline = OsgfFingerprint::from_canonical(&c).unwrap();
        let mut source = c.source_document.clone();
        source
            .nodes
            .iter_mut()
            .find(|n| n.node_type == NodeType::VisibilityIndicator)
            .unwrap()
            .properties
            .insert("dynamic_dispatch_callsites".into(), json!(["004010aa"]));
        source.unresolved_calls[0]
            .properties
            .insert("occurrences".into(), json!(7));
        let changed =
            OsgfFingerprint::from_canonical(&CanonicalSubgraph::from_source(&source).unwrap())
                .unwrap();
        assert_eq!(baseline.semantic_value(), changed.semantic_value());
        assert_ne!(baseline.observability_view, changed.observability_view);
        assert_ne!(
            baseline.source_canonical_digest,
            changed.source_canonical_digest
        );
        assert!(changed
            .observability_view
            .iter()
            .any(|f| f.descriptor["kind"] == "explicit_dynamic_dispatch"
                && f.descriptor["observed_count"] == 1));
        assert!(changed
            .observability_view
            .iter()
            .any(|f| f.descriptor["kind"] == "unresolved_call" && f.count == 7));
        for feature in &changed.observability_view {
            assert!(feature.descriptor.get("callee").is_none());
            assert!(feature.descriptor.get("target").is_none());
        }
    }

    #[test]
    fn step_6_9_missing_visibility_is_unknown_not_zero() {
        let mut source = canonical().source_document;
        source
            .nodes
            .iter_mut()
            .find(|n| n.node_type == NodeType::VisibilityIndicator)
            .unwrap()
            .properties
            .remove("dynamic_dispatch_callsites");
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        assert!(f
            .observability_view
            .iter()
            .any(|f| f.descriptor["kind"] == "explicit_dynamic_dispatch"
                && f.descriptor["observed_count"].is_null()));
    }

    #[test]
    fn step_6_8_limits_are_explicit_and_do_not_rank() {
        let c = canonical();
        let f = OsgfFingerprint::with_config(
            &c,
            FingerprintConfig {
                max_topology_motifs: 0,
                max_interaction_motifs: 1,
            },
        )
        .unwrap();
        assert_eq!(f.motif_truncation["topology"].retained, 0);
        assert!(f.motif_truncation["topology"].truncated);
        assert_eq!(f.motif_truncation["interaction"].retained, 1);
        assert!(f.motif_truncation["interaction"].truncated);
        assert!(!f
            .rooted_topology_view
            .iter()
            .any(|f| f.descriptor["kind"] == "rooted_path"));
        assert!(f
            .rooted_topology_view
            .iter()
            .any(|f| f.descriptor["kind"] == "function_call"));
        assert_eq!(
            f,
            OsgfFingerprint::with_config(&c, f.config.clone()).unwrap()
        );
        assert!(OsgfFingerprint::with_config(
            &c,
            FingerprintConfig {
                max_topology_motifs: 100001,
                max_interaction_motifs: 1
            }
        )
        .is_err());
    }

    #[test]
    fn step_6_8_motif_counts_are_structural_not_edge_occurrence_products() {
        let c = canonical();
        let baseline = OsgfFingerprint::from_canonical(&c).unwrap();

        let mut source = c.source_document.clone();

        for edge in &mut source.edges {
            edge.properties.insert("occurrences".into(), json!(1000));
        }

        let changed_canonical = CanonicalSubgraph::from_source(&source).unwrap();
        let changed = OsgfFingerprint::from_canonical(&changed_canonical).unwrap();

        for feature in baseline.rooted_topology_view.iter().filter(|feature| {
            matches!(
                feature.descriptor["kind"].as_str(),
                Some("rooted_path") | Some("rooted_fork")
            )
        }) {
            let corresponding = changed
                .rooted_topology_view
                .iter()
                .find(|candidate| candidate.descriptor == feature.descriptor)
                .expect("missing corresponding topology motif");

            assert_eq!(corresponding.count, feature.count);
        }

        for feature in baseline
            .typed_evidence_view
            .iter()
            .filter(|feature| feature.descriptor["kind"] == "category_chain")
        {
            let corresponding = changed
                .typed_evidence_view
                .iter()
                .find(|candidate| candidate.descriptor == feature.descriptor)
                .expect("missing corresponding category-chain motif");

            assert_eq!(corresponding.count, feature.count);
        }

        for feature in &baseline.interaction_motif_view {
            let corresponding = changed
                .interaction_motif_view
                .iter()
                .find(|candidate| candidate.descriptor == feature.descriptor)
                .expect("missing corresponding interaction motif");

            assert_eq!(corresponding.count, feature.count);
        }
    }

    #[test]
    fn step_6_7_interaction_requires_connected_call_and_evidence() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let api = f
            .interaction_motif_view
            .iter()
            .find(|f| f.descriptor["evidence"]["canonical_value"] == "writeprocessmemory")
            .unwrap();
        assert_eq!(api.descriptor["caller"]["role"], "ANCHOR");
        assert_eq!(api.descriptor["callee"]["role"], "BOTH");
        assert_eq!(api.count, 1);
        assert_eq!(f.provenance_index[&api.id][0].canonical_elements.len(), 5);
        assert!(f
            .interaction_motif_view
            .iter()
            .any(|f| f.descriptor["kind"] == "call_category_chain"));
        let mut source = c.source_document.clone();
        source
            .edges
            .retain(|e| e.edge_type != EdgeType::CallsFunction);
        source.truncation.counts.edges = source.edges.len();
        let f = OsgfFingerprint::from_canonical(&CanonicalSubgraph::from_source(&source).unwrap())
            .unwrap();
        assert!(f.interaction_motif_view.is_empty());
    }

    #[test]
    fn step_6_6_category_chain_requires_both_explicit_edges() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let chains: Vec<_> = f
            .typed_evidence_view
            .iter()
            .filter(|f| f.descriptor["kind"] == "category_chain")
            .collect();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].descriptor["category"]["category"], "powershell");
        assert_eq!(chains[0].count, 1);
        assert_eq!(
            f.provenance_index[&chains[0].id][0]
                .canonical_elements
                .len(),
            5
        );
        let mut source = c.source_document.clone();
        source
            .edges
            .retain(|e| e.edge_type != EdgeType::HasStringCategory);
        source.truncation.counts.edges = source.edges.len();
        let f = OsgfFingerprint::from_canonical(&CanonicalSubgraph::from_source(&source).unwrap())
            .unwrap();
        assert!(!f
            .typed_evidence_view
            .iter()
            .any(|f| f.descriptor["kind"] == "category_chain"));
    }

    #[test]
    fn step_6_5_evidence_is_attached_to_roles_with_no_inference() {
        let f = OsgfFingerprint::from_canonical(&canonical()).unwrap();
        assert_eq!(
            f.typed_evidence_view
                .iter()
                .filter(|f| f.descriptor["kind"] == "typed_evidence")
                .count(),
            5
        );
        let relations: std::collections::BTreeSet<_> = f
            .typed_evidence_view
            .iter()
            .filter(|f| f.descriptor["kind"] == "typed_evidence")
            .map(|f| f.descriptor["relation"].as_str().unwrap())
            .collect();
        assert_eq!(
            relations,
            [
                "calls_api",
                "references_string",
                "uses_constant",
                "belongs_to_section"
            ]
            .into_iter()
            .collect()
        );
        let api = f
            .typed_evidence_view
            .iter()
            .find(|f| f.descriptor["evidence"]["canonical_value"] == "virtualalloc")
            .unwrap();
        assert_eq!(api.count, 2);
        assert_eq!(api.descriptor["function"]["role"], "ANCHOR");
        assert!(!serde_json::to_string(&f.typed_evidence_view)
            .unwrap()
            .contains("unresolved"));
    }

    #[test]
    fn step_6_4_rooted_motifs_preserve_cycle_shape() {
        let f = OsgfFingerprint::from_canonical(&canonical()).unwrap();
        let paths: Vec<_> = f
            .rooted_topology_view
            .iter()
            .filter(|f| f.descriptor["kind"] == "rooted_path")
            .collect();
        assert_eq!(paths.len(), 2);
        for path in paths {
            assert_eq!(path.descriptor["node_pattern"], json!([0, 1, 0]));
            assert_eq!(path.descriptor["functions"].as_array().unwrap().len(), 3);
            assert!(path.descriptor["functions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["role"] == "ANCHOR"));
        }
    }

    #[test]
    fn step_6_3_directed_relations_keep_occurrences_and_supports() {
        let c = canonical();
        let mut source = c.source_document.clone();
        source
            .edges
            .iter_mut()
            .find(|e| e.edge_type == EdgeType::CallsFunction)
            .unwrap()
            .properties
            .insert("occurrences".into(), json!(3));
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let relations: Vec<_> = f
            .rooted_topology_view
            .iter()
            .filter(|f| f.descriptor["kind"] == "function_call")
            .collect();
        assert_eq!(relations.len(), 2);
        assert_eq!(relations.iter().map(|f| f.count).sum::<u64>(), 4);
        assert_ne!(relations[0].descriptor, relations[1].descriptor);
        assert!(relations
            .iter()
            .all(|r| f.provenance_index[&r.id][0].canonical_elements.len() == 3));
        assert!(!serde_json::to_string(&relations)
            .unwrap()
            .contains("004010"));
    }

    #[test]
    fn step_6_2_roles_and_both_distance_distributions() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        let roles: Vec<_> = f
            .rooted_topology_view
            .iter()
            .filter(|f| f.descriptor["kind"] == "root_role")
            .collect();
        assert_eq!(roles.iter().map(|f| f.count).sum::<u64>(), 2);
        assert!(roles
            .iter()
            .any(|f| f.descriptor["role"] == "ANCHOR" && f.count == 1));

        assert!(roles.iter().any(|f| f.descriptor["role"] == "BOTH"));
        assert!(roles.iter().all(|f| f.descriptor.get("function").is_none()));
        assert!(roles
            .iter()
            .all(|f| f.descriptor.get("caller_distance").is_none()));
        assert!(roles
            .iter()
            .all(|f| f.descriptor.get("callee_distance").is_none()));
        for direction in ["caller", "callee"] {
            assert_eq!(
                f.rooted_topology_view
                    .iter()
                    .filter(|f| f.descriptor["direction"] == direction)
                    .map(|f| f.count)
                    .sum::<u64>(),
                2
            );
        }
    }

    #[test]
    fn step_6_1_contract_is_versioned_and_distinct() {
        let c = canonical();
        let f = OsgfFingerprint::from_canonical(&c).unwrap();
        assert_eq!(f.schema_version, "0.1.0");
        assert_eq!(f.source_canonical_digest, c.canonical_digest);
        let text = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<OsgfFingerprint>(&text).unwrap(), f);
        assert!(!text.contains("score"));
        assert!(!text.contains("capability"));
    }

    #[test]
    fn smoke_existing_canonical_document_when_available() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../reports/canonical-notepad-step5/seed_fn_140002100.json");
        if path.exists() {
            let c = CanonicalSubgraph::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
            OsgfFingerprint::from_canonical(&c).unwrap();
        }
    }
}
