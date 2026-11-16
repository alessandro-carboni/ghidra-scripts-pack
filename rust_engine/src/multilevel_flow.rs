//! Independent producer-context depths; explicit fixed aggregates, never equivalence decisions.
use crate::operational_context::digest;
use crate::operational_features::{Feature, OperationalFingerprint};
use crate::operational_schema::ensure;
use crate::value_flow::ValueFingerprint;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const VERSION: &str = "osgf.multilevel-flow-fingerprint/0.1.0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Level {
    pub producer_depth: usize,
    pub features: Vec<Feature>,
    pub paths_truncated: bool,
    pub semantic_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultilevelFingerprint {
    pub schema_version: String,
    pub source: OperationalFingerprint,
    pub levels: BTreeMap<String, Level>,
    pub contracted_copies: BTreeMap<String, String>,
    pub copy_barriers: BTreeMap<String, String>,
    pub semantic_digest: String,
}

impl MultilevelFingerprint {
    pub fn from_source(source: &OperationalFingerprint) -> Result<Self, String> {
        let mut levels = BTreeMap::new();
        let mut contracted_copies = BTreeMap::new();
        let mut copy_barriers = BTreeMap::new();
        for depth in 0..=2 {
            let view = ValueFingerprint::at_depth(source, depth)?;
            contracted_copies = view.contracted_copies;
            copy_barriers = view.copy_barriers;
            // Same feature families and topology at every depth: isolate producer context.
            let science: Vec<_> = view
                .features
                .iter()
                .map(|f| json!({"descriptor":f.descriptor,"count":f.count}))
                .collect();
            let semantic_digest = digest(
                &json!({"schema":VERSION,"producer_depth":depth,"copy_hops":64,
                "max_two_edge_paths":source.configuration.max_two_edge_paths,"features":science}),
            )?;
            levels.insert(
                format!("depth_{depth}"),
                Level {
                    producer_depth: depth,
                    features: view.features,
                    paths_truncated: view.paths_truncated,
                    semantic_digest,
                },
            );
        }
        let digests: BTreeMap<_, _> = levels
            .iter()
            .map(|(k, v)| (k, &v.semantic_digest))
            .collect();
        let semantic_digest = digest(&json!({"schema":VERSION,"levels":digests}))?;
        Ok(Self {
            schema_version: VERSION.into(),
            source: source.clone(),
            levels,
            contracted_copies,
            copy_barriers,
            semantic_digest,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        ensure(
            *self == Self::from_source(&self.source)?,
            "multilevel fingerprint differs from verified source",
        )
    }
}

fn score(q: &Level, r: &Level, family: Option<&str>, usable: bool) -> Value {
    let counts = |v: &Level| {
        v.features
            .iter()
            .filter(|f| family.is_none_or(|name| f.descriptor["family"] == name))
            .map(|f| (f.descriptor.to_string(), f.count))
            .collect()
    };
    let qcounts: BTreeMap<String, u64> = counts(q);
    let rcounts = counts(r);
    let (set, multiset, matched) = if usable {
        crate::operational_similarity::jaccard(&qcounts, &rcounts)
    } else {
        (None, None, 0)
    };
    json!({"set_similarity":set,"multiset_similarity":multiset,"matched_distinct_features":matched,
        "query_features":qcounts.len(),"reference_features":rcounts.len()})
}

fn aggregate(views: &[&Value]) -> Value {
    let mean = |field: &str| -> Option<f64> {
        views
            .iter()
            .map(|v| v[field].as_f64())
            .collect::<Option<Vec<_>>>()
            .map(|values| values.iter().sum::<f64>() / values.len() as f64)
    };
    json!({"set_similarity":mean("set_similarity"),"multiset_similarity":mean("multiset_similarity"),
        "comparison_complete":views.iter().all(|v| v["comparison_complete"] == true),
        "policy":"Equal weights, all specified views required; missing views are never silently dropped"})
}

pub fn compare(q: &MultilevelFingerprint, r: &MultilevelFingerprint) -> Result<Value, String> {
    q.validate()?;
    r.validate()?;
    // The original comparison also enforces source/configuration compatibility.
    let baseline = crate::operational_similarity::compare(&q.source, &r.source)?;
    let usable = |f: &MultilevelFingerprint| {
        f.source
            .source_canonical
            .source_document
            .operational_evidence
            .iter()
            .any(|d| matches!(d.observability.state.as_str(), "complete" | "partial"))
    };
    let usable = usable(q) && usable(r);
    let mut levels = BTreeMap::new();
    for (key, query) in &q.levels {
        let reference = &r.levels[key];
        let mut result = score(query, reference, None, usable);
        let families: BTreeMap<_, _> = ["operation", "dependency", "two_edge_path"]
            .into_iter()
            .map(|family| (family, score(query, reference, Some(family), usable)))
            .collect();
        result["families"] = json!(families);
        result["producer_depth"] = json!(query.producer_depth);
        result["paths_truncated"] = json!(query.paths_truncated || reference.paths_truncated);
        result["comparison_complete"] = json!(
            baseline["operational"]["comparison_complete"] == true
                && !query.paths_truncated
                && !reference.paths_truncated
        );
        levels.insert(key.clone(), result);
    }
    let mean01 = aggregate(&[&levels["depth_0"], &levels["depth_1"]]);
    let mean012 = aggregate(&[&levels["depth_0"], &levels["depth_1"], &levels["depth_2"]]);
    let exact_mean = aggregate(&[&baseline["operational"], &mean012]);
    Ok(
        json!({"schema_version":"osgf.multilevel-flow-similarity/0.1.0",
        "query_semantic_digest":q.semantic_digest,"reference_semantic_digest":r.semantic_digest,
        "baseline":baseline,"levels":levels,
        "aggregates":{"mean_01":mean01,"mean_012":mean012,"exact_mean_012":exact_mean},
        "query_contracted_copies":q.contracted_copies,"reference_contracted_copies":r.contracted_copies,
        "query_copy_barriers":q.copy_barriers,"reference_copy_barriers":r.copy_barriers,
        "decision":null,
        "policy":"Opt-in High SSA producer-depth ablation; identical feature families and structural context at each depth; observability inherited from baseline; scores are not equivalence proofs"}),
    )
}
