//! Four-view comparison. Support is descriptive, never an equivalence probability.
use crate::operational_features::OperationalFingerprint;
use crate::operational_schema::ensure;
use crate::similarity::SimilarityComparison;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub fn jaccard(
    q: &BTreeMap<String, u64>,
    r: &BTreeMap<String, u64>,
) -> (Option<f64>, Option<f64>, usize) {
    let keys: BTreeSet<_> = q.keys().chain(r.keys()).collect();
    if keys.is_empty() {
        return (None, None, 0);
    }
    let mut matched = 0;
    let mut intersection = 0u128;
    let mut union = 0u128;
    for key in &keys {
        let a = *q.get(*key).unwrap_or(&0);
        let b = *r.get(*key).unwrap_or(&0);
        if a > 0 && b > 0 {
            matched += 1;
        }
        intersection += a.min(b) as u128;
        union += a.max(b) as u128;
    }
    (
        Some(matched as f64 / keys.len() as f64),
        Some(intersection as f64 / union as f64),
        matched,
    )
}
fn support(f: &OperationalFingerprint) -> Value {
    let local = &f.source_canonical.source_document;
    let unavailable = local
        .coverage
        .values()
        .filter(|v| v.as_str() != "observed")
        .count();
    let partial = local
        .operational_evidence
        .iter()
        .filter(|d| d.observability.state != "complete" || d.observability.truncated)
        .count();
    let unsupported = local
        .operational_evidence
        .iter()
        .flat_map(|d| &d.operations)
        .filter(|o| o.semantics.family == "unsupported")
        .count();
    json!({"distinct_features":f.operational_view.len(),"feature_occurrences":f.operational_view.iter().map(|v|v.count).sum::<u64>(),"selected_functions":local.coverage.len(),"missing_or_budget_excluded_functions":unavailable,"partial_or_unavailable_functions":partial,"unsupported_operations":unsupported,"unresolved_inputs":local.operational_evidence.iter().map(|d|d.observability.unresolved_inputs).sum::<usize>(),"paths_truncated":f.paths_truncated,"comparison_complete":unavailable==0&&partial==0&&unsupported==0&&!f.paths_truncated,"status":if f.operational_view.is_empty(){"INSUFFICIENT_EVIDENCE"}else{"OBSERVED_EVIDENCE"},"interpretation":"Counts and coverage are not confidence or probability of equivalence"})
}
pub fn compare(q: &OperationalFingerprint, r: &OperationalFingerprint) -> Result<Value, String> {
    q.validate()?;
    r.validate()?;
    ensure(
        q.configuration == r.configuration,
        "incompatible operational feature configuration",
    )?;
    let domain = |f: &OperationalFingerprint| {
        f.source_canonical
            .source_document
            .operational_evidence
            .first()
            .map(|d| json!({"representation":d.representation,"environment":d.environment}))
    };
    let qdomain = domain(q);
    let rdomain = domain(r);
    if qdomain.is_some() && rdomain.is_some() {
        ensure(qdomain == rdomain, "incompatible P-code extraction domains")?;
    }
    let structural = SimilarityComparison::new(
        "query",
        &q.structural,
        &q.source_canonical.structural,
        "reference",
        &r.structural,
        &r.source_canonical.structural,
    )?
    .finish_with_aggregate(true);
    let counts = |f: &OperationalFingerprint| {
        f.operational_view
            .iter()
            .map(|v| (v.descriptor.to_string(), v.count))
            .collect::<BTreeMap<_, _>>()
    };
    let qc = counts(q);
    let rc = counts(r);
    let usable = |f: &OperationalFingerprint| {
        f.source_canonical
            .source_document
            .operational_evidence
            .iter()
            .any(|d| ["complete", "partial"].contains(&d.observability.state.as_str()))
    };
    let available = qdomain.is_some() && rdomain.is_some() && usable(q) && usable(r);
    let (set, multiset, matched) = if available {
        jaccard(&qc, &rc)
    } else {
        (None, None, 0)
    };
    let qs = support(q);
    let rs = support(r);
    let complete = qs["comparison_complete"] == true && rs["comparison_complete"] == true;
    let missing = |a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>| -> Vec<Value> {
        a.iter().filter_map(|(key,count)|{let other=*b.get(key).unwrap_or(&0);(*count>other).then(||json!({"descriptor":serde_json::from_str::<Value>(key).unwrap(),"count":count-other,"qualification":if complete{"not_observed"}else{"not_observed_in_incomplete_evidence"}}))}).collect()
    };
    let mut sets = Vec::new();
    let mut multisets = Vec::new();
    let mut components = Vec::new();
    for (name, view) in [
        ("rooted_topology", &structural.rooted_topology),
        ("typed_evidence", &structural.typed_evidence),
        ("interaction_motif", &structural.interaction_motif),
    ] {
        if let Some(view) = view {
            if let (Some(a), Some(b)) = (view.set_similarity, view.multiset_similarity) {
                sets.push(a);
                multisets.push(b);
                components.push(name);
            }
        }
    }
    if let (Some(a), Some(b)) = (set, multiset) {
        sets.push(a);
        multisets.push(b);
        components.push("operational");
    }
    let mean = |v: &Vec<f64>| {
        if v.is_empty() {
            None
        } else {
            Some(v.iter().sum::<f64>() / v.len() as f64)
        }
    };
    Ok(
        json!({"schema_version":"0.2.0","query_semantic_digest":q.semantic_digest,"reference_semantic_digest":r.semantic_digest,"structural_v0_1":structural,"operational":{"comparable":set.is_some(),"set_similarity":set,"multiset_similarity":multiset,"matched_distinct_features":matched,"missing_from_query":if available{missing(&rc,&qc)}else{vec![]},"missing_from_reference":if available{missing(&qc,&rc)}else{vec![]},"comparison_complete":complete,"query_support":qs,"reference_support":rs,"source_support":"Resolve feature occurrences via each supplied fingerprint's source_canonical.provenance"},"aggregate":{"rule":"arithmetic mean over comparable views; no learned weights","set_similarity":mean(&sets),"multiset_similarity":mean(&multisets),"components":components},"decision":null,"decision_policy":"No classifier or equivalence decision introduced; insufficient evidence is descriptive only"}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_one_empty() {
        assert_eq!(jaccard(&BTreeMap::new(), &BTreeMap::new()), (None, None, 0));
        let a = BTreeMap::from([("x".into(), 1)]);
        assert_eq!(jaccard(&a, &BTreeMap::new()), (Some(0.0), Some(0.0), 0));
    }
    #[test]
    fn exact_set_and_count_math() {
        let a = BTreeMap::from([("a".into(), 3), ("b".into(), 2)]);
        let b = BTreeMap::from([("a".into(), 1), ("c".into(), 4)]);
        assert_eq!(jaccard(&a, &b), (Some(1.0 / 3.0), Some(1.0 / 9.0), 1));
        let big = BTreeMap::from([("a".into(), u64::MAX), ("b".into(), u64::MAX)]);
        assert_eq!(jaccard(&big, &big), (Some(1.0), Some(1.0), 2));
    }
}
