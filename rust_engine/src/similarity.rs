//! Versioned, source-validated similarity; no classification or manual weights.
use crate::canonical::{CanonicalSubgraph, CANONICALIZATION_VERSION, CANONICAL_SUBGRAPH_VERSION};
use crate::fingerprint::{FingerprintFeature, OsgfFingerprint, OSGF_FINGERPRINT_VERSION};
use crate::fingerprint_provenance::{FingerprintProvenance, ResolvedOccurrence};
use crate::similarity_observability::{self, ObservabilityComparison, ObservabilityState};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OSGF_SIMILARITY_VERSION: &str = "0.1.0";

fn multiset_similarity(
    query: &[FingerprintFeature],
    reference: &[FingerprintFeature],
) -> Option<f64> {
    let q = feature_map(query);
    let r = feature_map(reference);
    // u128 safely accumulates u64 counts across any addressable vector.
    let mut intersection = 0u128;
    let mut union = 0u128;
    for (key, feature) in &q {
        let other = r.get(key).map_or(0, |f| f.count);
        intersection += u128::from(feature.count.min(other));
        union += u128::from(feature.count.max(other));
    }
    for (key, feature) in &r {
        if !q.contains_key(key) {
            union += u128::from(feature.count);
        }
    }
    (union != 0).then(|| intersection as f64 / union as f64)
}

fn metrics(query: &[FingerprintFeature], reference: &[FingerprintFeature]) -> ViewSimilarity {
    let set = set_similarity(query, reference);
    ViewSimilarity {
        comparable: set.is_some(),
        set_similarity: set,
        multiset_similarity: multiset_similarity(query, reference),
        comparison_complete: true,
        ..ViewSimilarity::default()
    }
}

fn feature_map(
    features: &[FingerprintFeature],
) -> std::collections::BTreeMap<String, &FingerprintFeature> {
    features
        .iter()
        .map(|f| (serde_json::to_string(&f.descriptor).unwrap(), f))
        .collect()
}

fn set_similarity(query: &[FingerprintFeature], reference: &[FingerprintFeature]) -> Option<f64> {
    let q = feature_map(query);
    let r = feature_map(reference);
    let intersection = q.keys().filter(|k| r.contains_key(*k)).count();
    let union = q.len() + r.len() - intersection;
    (union != 0).then(|| intersection as f64 / union as f64)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputIdentity {
    pub id: String,
    pub fingerprint_version: String,
    pub canonicalization_version: String,
    pub canonical_schema_version: String,
    pub provenance: FingerprintProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchedFeature {
    pub descriptor: Value,
    pub query_count: u64,
    pub reference_count: u64,
    pub matched_count: u64,
    pub query_provenance: Vec<ResolvedOccurrence>,
    pub reference_provenance: Vec<ResolvedOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissingFeature {
    pub descriptor: Value,
    pub count: u64,
    pub provenance: Vec<ResolvedOccurrence>,
    pub qualification: MissingQualification,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingQualification {
    ObservedAbsent,
    ObservedAbsentWithIncompleteObservability,
}

impl MissingFeature {
    fn new(
        feature: &FingerprintFeature,
        provenance: &FingerprintProvenance,
        absent_side_incomplete: bool,
    ) -> Self {
        Self {
            descriptor: feature.descriptor.clone(),
            count: feature.count,
            provenance: provenance.features[&feature.id].clone(),
            qualification: if absent_side_incomplete {
                MissingQualification::ObservedAbsentWithIncompleteObservability
            } else {
                MissingQualification::ObservedAbsent
            },
            warnings: if absent_side_incomplete {
                vec!["Absence may reflect incomplete observability on the absent side; no unresolved target or feature correspondence is inferred.".into()]
            } else {
                vec![]
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ViewSimilarity {
    pub comparable: bool,
    pub set_similarity: Option<f64>,
    pub multiset_similarity: Option<f64>,
    pub comparison_complete: bool,
    pub matched: Vec<MatchedFeature>,
    /// Present in reference, absent in query (not a shared-feature count deficit).
    pub missing_from_query: Vec<MissingFeature>,
    /// Present in query, absent in reference.
    pub missing_from_reference: Vec<MissingFeature>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimilarityResult {
    pub schema_version: String,
    pub query: InputIdentity,
    pub reference: InputIdentity,
    pub rooted_topology: Option<ViewSimilarity>,
    pub typed_evidence: Option<ViewSimilarity>,
    pub interaction_motif: Option<ViewSimilarity>,
    pub observability: Option<ObservabilityComparison>,
    pub observability_warnings: Vec<String>,
    pub aggregate_set_similarity: Option<f64>,
    pub aggregate_multiset_similarity: Option<f64>,
    pub aggregate_requested: bool,
    pub aggregate_components: Vec<String>,
}

impl SimilarityResult {
    fn compute_aggregate(&mut self) {
        self.aggregate_requested = true;
        self.aggregate_components.clear();
        let mut set_sum = 0.0;
        let mut multiset_sum = 0.0;
        for (name, view) in [
            ("rooted_topology", &self.rooted_topology),
            ("typed_evidence", &self.typed_evidence),
            ("interaction_motif", &self.interaction_motif),
        ] {
            if let Some(view) = view.as_ref().filter(|v| v.comparable) {
                if let (Some(set), Some(multiset)) = (view.set_similarity, view.multiset_similarity)
                {
                    self.aggregate_components.push(name.into());
                    set_sum += set;
                    multiset_sum += multiset;
                }
            }
        }
        let n = self.aggregate_components.len();
        self.aggregate_set_similarity = (n > 0).then(|| set_sum / n as f64);
        self.aggregate_multiset_similarity = (n > 0).then(|| multiset_sum / n as f64);
    }
}

/// Private verified inputs prevent comparisons against forged counts or provenance.
pub struct SimilarityComparison<'a> {
    query: &'a OsgfFingerprint,
    reference: &'a OsgfFingerprint,
    result: SimilarityResult,
}

impl<'a> SimilarityComparison<'a> {
    pub fn observability(&self) -> ObservabilityComparison {
        similarity_observability::compare(
            ObservabilityState::from_fingerprint(
                self.query,
                self.result
                    .query
                    .provenance
                    .source_document
                    .truncation
                    .clone(),
            ),
            ObservabilityState::from_fingerprint(
                self.reference,
                self.result
                    .reference
                    .provenance
                    .source_document
                    .truncation
                    .clone(),
            ),
        )
    }

    pub fn finish(self) -> SimilarityResult {
        self.finish_with_aggregate(false)
    }

    pub fn finish_with_aggregate(mut self, aggregate: bool) -> SimilarityResult {
        self.result.rooted_topology = Some(self.rooted_topology());
        self.result.typed_evidence = Some(self.typed_evidence());
        self.result.interaction_motif = Some(self.interaction_motif());
        let obs = self.observability();
        self.result.observability_warnings = obs.warnings.clone();
        self.result.observability = Some(obs);
        if aggregate {
            self.result.compute_aggregate();
        }
        self.result
    }
    pub fn interaction_motif(&self) -> ViewSimilarity {
        self.compare_view(
            &self.query.interaction_motif_view,
            &self.reference.interaction_motif_view,
            Some("interaction"),
        )
    }
    pub fn typed_evidence(&self) -> ViewSimilarity {
        self.compare_view(
            &self.query.typed_evidence_view,
            &self.reference.typed_evidence_view,
            None,
        )
    }
    pub fn rooted_topology(&self) -> ViewSimilarity {
        self.compare_view(
            &self.query.rooted_topology_view,
            &self.reference.rooted_topology_view,
            Some("topology"),
        )
    }

    fn compare_view(
        &self,
        query: &[FingerprintFeature],
        reference: &[FingerprintFeature],
        motif_family: Option<&str>,
    ) -> ViewSimilarity {
        let mut view = metrics(query, reference);
        let q = feature_map(query);
        let r = feature_map(reference);
        let qp = &self.result.query.provenance;
        let rp = &self.result.reference.provenance;
        let observability = self.observability();
        for (key, feature) in &q {
            if let Some(other) = r.get(key) {
                view.matched.push(matched(feature, other, qp, rp));
            } else {
                view.missing_from_reference.push(MissingFeature::new(
                    feature,
                    qp,
                    observability.reference_possibly_incomplete,
                ));
            }
        }
        for (key, feature) in &r {
            if !q.contains_key(key) {
                view.missing_from_query.push(MissingFeature::new(
                    feature,
                    rp,
                    observability.query_possibly_incomplete,
                ));
            }
        }
        if let Some(family) = motif_family {
            for (side, fp) in [("query", self.query), ("reference", self.reference)] {
                if fp.motif_truncation.get(family).is_some_and(|t| t.truncated) {
                    view.comparison_complete = false;
                    view.warnings.push(format!(
                        "{side}: {family} motifs truncated; similarity uses retained features"
                    ));
                }
            }
        }
        view
    }

    pub fn new(
        query_id: &str,
        query: &'a OsgfFingerprint,
        query_source: &CanonicalSubgraph,
        reference_id: &str,
        reference: &'a OsgfFingerprint,
        reference_source: &CanonicalSubgraph,
    ) -> Result<Self, String> {
        for fp in [query, reference] {
            if fp.schema_version != OSGF_FINGERPRINT_VERSION
                || fp.canonicalization_version != CANONICALIZATION_VERSION
                || fp.source_canonical_schema_version != CANONICAL_SUBGRAPH_VERSION
            {
                return Err("incompatible scientific versions: comparison unavailable".into());
            }
        }
        let identity = |id: &str,
                        fp: &OsgfFingerprint,
                        source: &CanonicalSubgraph|
         -> Result<InputIdentity, String> {
            Ok(InputIdentity {
                id: id.into(),
                fingerprint_version: fp.schema_version.clone(),
                canonicalization_version: fp.canonicalization_version.clone(),
                canonical_schema_version: fp.source_canonical_schema_version.clone(),
                provenance: fp.resolve_provenance(source)?,
            })
        };
        Ok(Self {
            query,
            reference,
            result: SimilarityResult {
                schema_version: OSGF_SIMILARITY_VERSION.into(),
                query: identity(query_id, query, query_source)?,
                reference: identity(reference_id, reference, reference_source)?,
                rooted_topology: None,
                typed_evidence: None,
                interaction_motif: None,
                observability: None,
                observability_warnings: vec![],
                aggregate_set_similarity: None,
                aggregate_multiset_similarity: None,
                aggregate_requested: false,
                aggregate_components: vec![],
            },
        })
    }
}

fn matched(
    q: &FingerprintFeature,
    r: &FingerprintFeature,
    qp: &FingerprintProvenance,
    rp: &FingerprintProvenance,
) -> MatchedFeature {
    MatchedFeature {
        descriptor: q.descriptor.clone(),
        query_count: q.count,
        reference_count: r.count,
        matched_count: q.count.min(r.count),
        query_provenance: qp.features[&q.id].clone(),
        reference_provenance: rp.features[&r.id].clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_is_optional_unweighted_and_excludes_unavailable_views() {
        let (c, fp) = fixture();
        let plain = SimilarityComparison::new("q", &fp, &c, "r", &fp, &c)
            .unwrap()
            .finish();
        assert!(!plain.aggregate_requested);
        assert!(plain.aggregate_components.is_empty());
        let mut result = SimilarityComparison::new("q", &fp, &c, "r", &fp, &c)
            .unwrap()
            .finish_with_aggregate(true);
        assert_eq!(result.aggregate_set_similarity, Some(1.0));
        assert_eq!(result.aggregate_components.len(), 3);
        assert!(result.observability.as_ref().unwrap().possibly_incomplete);
        result.rooted_topology = Some(metrics(&features(&[("A", 5)]), &features(&[("A", 1)])));
        result.typed_evidence = Some(metrics(&features(&[("A", 1)]), &features(&[("B", 1)])));
        result.interaction_motif = Some(metrics(&[], &[]));
        result.compute_aggregate();
        assert_eq!(result.aggregate_set_similarity, Some(0.5));
        assert_eq!(result.aggregate_multiset_similarity, Some(0.1));
        assert_eq!(
            result.aggregate_components,
            vec!["rooted_topology", "typed_evidence"]
        );
        result.rooted_topology = Some(metrics(&[], &[]));
        result.typed_evidence = Some(metrics(&[], &[]));
        result.compute_aggregate();
        assert!(result.aggregate_set_similarity.is_none());
        assert!(result.aggregate_multiset_similarity.is_none());
        assert!(result.aggregate_components.is_empty());
    }
    #[test]
    fn missing_qualification_uses_absent_side_and_never_invents_matches() {
        let (c, q) = fixture();
        let (rc, r) = altered_fixture(|raw| {
            raw["unresolved_calls"] = serde_json::json!([]);
            raw["truncation"]["counts"]["unresolved_calls"] = serde_json::json!(0);
            for node in raw["nodes"].as_array_mut().unwrap() {
                if node["type"] == "VISIBILITY_INDICATOR" {
                    node["unresolved_indirect_callsites"] = serde_json::json!([]);
                }
            }
            for edge in raw["edges"].as_array_mut().unwrap() {
                if edge["target"] == "api:virtualalloc" {
                    edge["source"] = serde_json::json!("fn:00402000");
                }
            }
        });
        let view = SimilarityComparison::new("q", &q, &c, "r", &r, &rc)
            .unwrap()
            .typed_evidence();
        assert_eq!(view.missing_from_query.len(), 1);
        assert_eq!(view.missing_from_reference.len(), 1);
        assert_eq!(
            view.missing_from_query[0].qualification,
            MissingQualification::ObservedAbsentWithIncompleteObservability
        );
        assert_eq!(
            view.missing_from_reference[0].qualification,
            MissingQualification::ObservedAbsent
        );
        assert_eq!(view.missing_from_query[0].warnings.len(), 1);
        assert!(view.missing_from_reference[0].warnings.is_empty());
        assert_eq!(view.matched.len() + 1, q.typed_evidence_view.len());
        assert!(r
            .typed_evidence_view
            .iter()
            .any(|f| f.descriptor == view.missing_from_query[0].descriptor));
        let reverse = SimilarityComparison::new("r", &r, &rc, "q", &q, &c)
            .unwrap()
            .typed_evidence();
        assert_eq!(view.missing_from_query, reverse.missing_from_reference);
        assert_eq!(view.missing_from_reference, reverse.missing_from_query);
        assert_eq!(view.set_similarity, reverse.set_similarity);
    }
    #[test]
    fn observability_is_separate_and_indirect_does_not_mean_unresolved() {
        let (c, q) = fixture();
        let (rc, r) = altered_fixture(|raw| {
            raw["unresolved_calls"] = serde_json::json!([]);
            raw["truncation"]["counts"]["unresolved_calls"] = serde_json::json!(0);
            for node in raw["nodes"].as_array_mut().unwrap() {
                if node["type"] == "VISIBILITY_INDICATOR" {
                    node["unresolved_indirect_callsites"] = serde_json::json!([]);
                }
            }
        });
        let result = SimilarityComparison::new("degraded", &q, &c, "resolved", &r, &rc)
            .unwrap()
            .finish();
        for view in [
            &result.rooted_topology,
            &result.typed_evidence,
            &result.interaction_motif,
        ] {
            let view = view.as_ref().unwrap();
            assert_eq!(view.set_similarity, Some(1.0));
            assert_eq!(view.multiset_similarity, Some(1.0));
        }
        let obs = result.observability.unwrap();
        assert!(obs.query_possibly_incomplete);
        assert!(!obs.reference_possibly_incomplete);
        assert!(!obs.reference.indirect_calls.is_empty());
        assert!(obs
            .differences
            .iter()
            .any(|d| d.field == "unresolved_calls"));
        assert!(obs
            .differences
            .iter()
            .any(|d| d.field == "unresolved_indirect_calls"));
        assert!(result.aggregate_set_similarity.is_none());
    }
    #[test]
    fn observability_reports_unknown_depth_truncation_and_dispatch_differences() {
        let (c, fp) = fixture();
        let cmp = SimilarityComparison::new("q", &fp, &c, "r", &fp, &c).unwrap();
        let initial = cmp.observability();
        assert!(initial.differences.is_empty());
        let mut altered = initial.reference.clone();
        altered.local_graph.truncated = true;
        altered.local_graph.effective_depth.callee_depth = 0;
        altered
            .motif_truncation
            .get_mut("interaction")
            .unwrap()
            .truncated = true;
        altered.explicit_dynamic_dispatch[0].descriptor["observed_count"] = serde_json::json!(3);
        altered.indirect_calls[0].descriptor["observed_count"] = Value::Null;
        let comparison = similarity_observability::compare(initial.query, altered);
        for field in [
            "local_graph",
            "motif_truncation",
            "explicit_dynamic_dispatch",
            "indirect_calls",
        ] {
            assert!(comparison.differences.iter().any(|d| d.field == field));
        }
        assert!(comparison
            .warnings
            .iter()
            .any(|w| w.contains("observation unavailable")));
        assert!(comparison
            .warnings
            .iter()
            .any(|w| w.contains("local graph truncated")));
        assert!(comparison
            .warnings
            .iter()
            .any(|w| w.contains("interaction motifs truncated")));
    }
    #[test]
    fn interaction_counts_are_structural_and_truncation_is_explicit() {
        let (c, q) = fixture();
        let (rc, r) = altered_fixture(|raw| {
            for edge in raw["edges"].as_array_mut().unwrap() {
                if edge["type"] == "calls_function" || edge["type"] == "calls_api" {
                    edge["callsites"] = serde_json::json!(["00401020", "00401030", "00401060"]);
                }
            }
        });
        let cmp = SimilarityComparison::new("q", &q, &c, "r", &r, &rc).unwrap();
        let view = cmp.interaction_motif();
        assert_eq!(view.set_similarity, Some(1.0));
        assert_eq!(view.multiset_similarity, Some(1.0));
        assert!(view
            .matched
            .iter()
            .all(|m| m.query_count == m.reference_count));
        assert!(cmp.typed_evidence().multiset_similarity.unwrap() < 1.0);
        let mut config = q.config.clone();
        config.max_interaction_motifs = 1;
        let limited = OsgfFingerprint::with_config(&c, config).unwrap();
        let partial = SimilarityComparison::new("q", &limited, &c, "r", &q, &c)
            .unwrap()
            .interaction_motif();
        assert!(!partial.comparison_complete);
        assert!(!partial.warnings.is_empty());
        assert!(partial.comparable);
        assert!(!partial.matched.is_empty());
        assert!(!partial.missing_from_query.is_empty());
        assert!(partial.missing_from_reference.is_empty());
        let both = SimilarityComparison::new("q", &limited, &c, "r", &limited, &c)
            .unwrap()
            .interaction_motif();
        assert_eq!(both.set_similarity, Some(1.0));
        assert!(!both.comparison_complete);
        assert_eq!(both.warnings.len(), 2);
    }
    fn altered_fixture(edit: impl FnOnce(&mut Value)) -> (CanonicalSubgraph, OsgfFingerprint) {
        let mut raw: Value =
            serde_json::from_str(include_str!("../tests/fixtures/canonical_local_v0_1.json"))
                .unwrap();
        edit(&mut raw);
        let c = CanonicalSubgraph::from_source(&serde_json::from_value(raw).unwrap()).unwrap();
        let fp = OsgfFingerprint::from_canonical(&c).unwrap();
        (c, fp)
    }
    #[test]
    fn typed_evidence_requires_identical_function_position() {
        let (c, q) = fixture();
        let (rc, r) = altered_fixture(|raw| {
            for edge in raw["edges"].as_array_mut().unwrap() {
                if edge["target"] == "api:virtualalloc" {
                    edge["source"] = serde_json::json!("fn:00402000");
                }
            }
        });
        let cmp = SimilarityComparison::new("q", &q, &c, "r", &r, &rc).unwrap();
        let view = cmp.typed_evidence();
        assert_eq!(view.missing_from_query.len(), 1);
        assert_eq!(view.missing_from_reference.len(), 1);
        assert_ne!(
            view.missing_from_query[0].descriptor,
            view.missing_from_reference[0].descriptor
        );
        assert_eq!(
            view.missing_from_query[0].descriptor["evidence"],
            view.missing_from_reference[0].descriptor["evidence"]
        );
        assert!(view
            .matched
            .iter()
            .any(|m| m.descriptor["kind"] == "category_chain"));
        assert_eq!(cmp.rooted_topology().set_similarity, Some(1.0));
        assert!(view.set_similarity.unwrap() < 1.0);
        let identical = SimilarityComparison::new("q", &q, &c, "r", &q, &c)
            .unwrap()
            .typed_evidence();
        assert_eq!(identical.set_similarity, Some(1.0));
        assert_eq!(identical.multiset_similarity, Some(1.0));
        assert_eq!(identical.matched.len(), q.typed_evidence_view.len());
    }
    #[test]
    fn topology_matches_only_topology_and_preserves_missing_direction() {
        let (c, fp) = fixture();
        let mut config = fp.config.clone();
        config.max_topology_motifs = 0;
        let truncated = OsgfFingerprint::with_config(&c, config).unwrap();
        let cmp = SimilarityComparison::new("q", &truncated, &c, "r", &fp, &c).unwrap();
        let view = cmp.rooted_topology();
        assert!(!view.comparison_complete);
        assert!(!view.missing_from_query.is_empty());
        assert!(view.missing_from_reference.is_empty());
        assert!(view.missing_from_query.iter().all(
            |f| f.descriptor["kind"] == "rooted_path" || f.descriptor["kind"] == "rooted_fork"
        ));
        assert!(view
            .matched
            .iter()
            .all(|f| !f.query_provenance.is_empty() && !f.reference_provenance.is_empty()));
        let reverse = SimilarityComparison::new("r", &fp, &c, "q", &truncated, &c)
            .unwrap()
            .rooted_topology();
        assert_eq!(view.missing_from_query, reverse.missing_from_reference);
        assert_eq!(view.set_similarity, reverse.set_similarity);
        let identical = SimilarityComparison::new("q", &fp, &c, "r", &fp, &c)
            .unwrap()
            .rooted_topology();
        assert_eq!(identical.set_similarity, Some(1.0));
        assert_eq!(identical.multiset_similarity, Some(1.0));
        assert_eq!(identical.matched.len(), fp.rooted_topology_view.len());
    }
    #[test]
    fn multiset_uses_original_counts_and_retains_both_metrics() {
        let q = features(&[("A", 5), ("B", 1)]);
        let r = features(&[("A", 1), ("B", 20)]);
        let m = metrics(&q, &r);
        assert!(m.comparable);
        assert_eq!(m.set_similarity, Some(1.0));
        assert_eq!(m.multiset_similarity, Some(2.0 / 25.0));
        assert_eq!(multiset_similarity(&r, &q), m.multiset_similarity);
        assert!(!metrics(&[], &[]).comparable);
        assert_eq!(metrics(&[], &[]).multiset_similarity, None);
        assert_eq!(multiset_similarity(&q, &[]), Some(0.0));
        assert_eq!(multiset_similarity(&[], &q), Some(0.0));
        assert_eq!(
            multiset_similarity(&q, &features(&[("B", 2), ("C", 3)])),
            Some(1.0 / 10.0)
        );
        let large = features(&[("A", u64::MAX), ("B", u64::MAX)]);
        assert_eq!(multiset_similarity(&large, &large), Some(1.0));
    }
    fn features(values: &[(&str, u64)]) -> Vec<FingerprintFeature> {
        values
            .iter()
            .map(|(s, count)| FingerprintFeature {
                id: s.to_string(),
                descriptor: serde_json::json!({"kind":s}),
                count: *count,
            })
            .collect()
    }
    #[test]
    fn set_jaccard_ignores_counts_and_handles_empty_and_partial_overlap() {
        let q = features(&[("A", 5), ("B", 1)]);
        let r = features(&[("A", 1), ("B", 20)]);
        assert_eq!(set_similarity(&q, &r), Some(1.0));
        assert_eq!(set_similarity(&[], &[]), None);
        assert_eq!(set_similarity(&q, &[]), Some(0.0));
        assert_eq!(set_similarity(&[], &r), Some(0.0));
        assert_eq!(
            set_similarity(&q, &features(&[("B", 2), ("C", 3)])),
            Some(1.0 / 3.0)
        );
        assert_eq!(set_similarity(&q, &features(&[("C", 1)])), Some(0.0));
    }
    fn fixture() -> (CanonicalSubgraph, OsgfFingerprint) {
        let source =
            serde_json::from_str(include_str!("../tests/fixtures/canonical_local_v0_1.json"))
                .unwrap();
        let c = CanonicalSubgraph::from_source(&source).unwrap();
        let fp = OsgfFingerprint::from_canonical(&c).unwrap();
        (c, fp)
    }
    #[test]
    fn contract_preserves_identity_versions_and_two_sided_provenance() {
        let (c, fp) = fixture();
        let cmp = SimilarityComparison::new("query", &fp, &c, "reference", &fp, &c).unwrap();
        let q = &fp.typed_evidence_view[0];
        let mut r = q.clone();
        r.count += 5;
        let m = matched(
            q,
            &r,
            &cmp.result.query.provenance,
            &cmp.result.reference.provenance,
        );
        assert_eq!(m.matched_count, q.count);
        assert!(!m.query_provenance.is_empty());
        assert_eq!(m.query_provenance, m.reference_provenance);
        let json = serde_json::to_string(&cmp.result).unwrap();
        assert_eq!(
            serde_json::from_str::<SimilarityResult>(&json).unwrap(),
            cmp.result
        );
        assert_eq!(cmp.result.query.id, "query");
    }
    #[test]
    fn incompatible_versions_and_tampered_counts_are_errors() {
        let (c, fp) = fixture();
        for field in 0..3 {
            let mut bad = fp.clone();
            match field {
                0 => bad.schema_version = "2".into(),
                1 => bad.canonicalization_version = "2".into(),
                _ => bad.source_canonical_schema_version = "2".into(),
            }
            assert!(SimilarityComparison::new("q", &bad, &c, "r", &bad, &c).is_err());
        }
        let mut bad = fp.clone();
        bad.typed_evidence_view[0].count += 1;
        assert!(SimilarityComparison::new("q", &bad, &c, "r", &fp, &c).is_err());
    }
}
