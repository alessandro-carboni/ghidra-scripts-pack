//! OSGF Fingerprint Baseline v0.1: deterministic views, no scoring or classification.
use crate::canonical::{CanonicalEdge, CanonicalSubgraph};
use crate::fingerprint_motifs::{MotifBuffer, MotifTruncation};
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
}

impl OsgfFingerprint {
    pub fn from_canonical(canonical: &CanonicalSubgraph) -> Result<Self, String> {
        Self::with_config(canonical, FingerprintConfig::default())
    }

    pub fn with_config(
        canonical: &CanonicalSubgraph,
        config: FingerprintConfig,
    ) -> Result<Self, String> {
        canonical.validate()?;
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
        };
        fingerprint.root_roles(canonical)?;
        fingerprint.function_relations(canonical)?;
        fingerprint.topology_motifs(canonical)?;
        fingerprint.typed_evidence(canonical)?;
        fingerprint.category_chains(canonical)?;
        fingerprint.interaction_motifs(canonical)?;
        Ok(fingerprint)
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
