//! Collapse equivalent observations without losing distinct provenance.
use crate::schema::{SeedCandidate, SeedEvidence, SeedTriggerFamily};
use crate::seed_ordering::order_seed_candidates;
use std::collections::BTreeMap;

/// Structured identity avoids delimiter collisions and distinguishes None from Some.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceKey {
    kind: String,
    value: String,
    node_id: Option<String>,
    edge_type: Option<String>,
    callsite: Option<String>,
}

pub fn evidence_key(evidence: &SeedEvidence) -> EvidenceKey {
    EvidenceKey {
        kind: evidence.kind.clone(),
        value: evidence.value.clone(),
        node_id: evidence.node_id.clone(),
        edge_type: evidence.edge_type.clone(),
        callsite: evidence.callsite.clone(),
    }
}

struct CandidateGroup {
    seed: SeedCandidate,
    evidence: BTreeMap<EvidenceKey, SeedEvidence>,
}

/// Same anchor/trigger/reason: union all distinct evidence records. Different reasons
/// remain separate candidate variants so consolidation can retain all explanations.
/// Contradictory families for one trigger identity are rejected, never silently chosen.
pub fn deduplicate_seed_candidates(
    candidates: &[SeedCandidate],
) -> Result<Vec<SeedCandidate>, String> {
    let mut families: BTreeMap<(&str, &str), SeedTriggerFamily> = BTreeMap::new();
    let mut groups: BTreeMap<(&str, &str, &str), CandidateGroup> = BTreeMap::new();
    for candidate in candidates {
        candidate.validate()?;
        let identity = (
            candidate.anchor_function_id.as_str(),
            candidate.trigger_id.as_str(),
        );
        if families
            .insert(identity, candidate.family)
            .is_some_and(|previous| previous != candidate.family)
        {
            return Err(format!(
                "conflicting families for seed {}",
                candidate.seed_id
            ));
        }
        let group = groups
            .entry((identity.0, identity.1, candidate.reason.as_str()))
            .or_insert_with(|| {
                let mut seed = candidate.clone();
                seed.evidence.clear();
                CandidateGroup {
                    seed,
                    evidence: BTreeMap::new(),
                }
            });
        for item in &candidate.evidence {
            group
                .evidence
                .entry(evidence_key(item))
                .or_insert_with(|| item.clone());
        }
        debug_assert_eq!(group.seed.seed_id, candidate.seed_id);
    }
    let mut result: Vec<_> = groups
        .into_values()
        .map(|mut group| {
            group.seed.evidence = group.evidence.into_values().collect();
            group.seed
        })
        .collect();
    order_seed_candidates(&mut result);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::build_seed_id;
    use crate::seed_consolidation::consolidate_seed_candidates;

    fn candidate(anchor: &str, trigger: &str, site: Option<&str>) -> SeedCandidate {
        SeedCandidate {
            seed_id: build_seed_id(anchor, trigger).unwrap(),
            anchor_function_id: anchor.into(),
            trigger_id: trigger.into(),
            family: SeedTriggerFamily::MemoryManagement,
            reason: "Observed API".into(),
            evidence: vec![SeedEvidence {
                kind: "api".into(),
                value: "VirtualAlloc".into(),
                node_id: Some("api:virtualalloc".into()),
                edge_type: Some("calls_api".into()),
                callsite: site.map(str::to_string),
            }],
        }
    }

    #[test]
    fn duplicate_candidates_merge_all_distinct_callsites() {
        let first = candidate("fn:A", "api.virtualalloc", Some("10"));
        let second = candidate("fn:A", "api.virtualalloc", Some("20"));
        let result = deduplicate_seed_candidates(&[first.clone(), second, first]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0]
                .evidence
                .iter()
                .map(|e| e.callsite.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("10"), Some("20")]
        );
    }

    #[test]
    fn distinct_provenance_and_explanations_survive() {
        let first = candidate("fn:A", "api.virtualalloc", Some("10"));
        let mut other_node = first.clone();
        other_node.evidence[0].node_id = Some("api:other".into());
        let mut other_edge = first.clone();
        other_edge.evidence[0].edge_type = Some("observed_api".into());
        let unknown_site = candidate("fn:A", "api.virtualalloc", None);
        let mut reason = first.clone();
        reason.reason = "Another observation".into();
        let result =
            deduplicate_seed_candidates(&[first, other_node, other_edge, unknown_site, reason])
                .unwrap();
        assert_eq!(result.len(), 2);
        let consolidated = consolidate_seed_candidates(&result).unwrap();
        assert_eq!(consolidated[0].evidence.len(), 4);
        assert_eq!(consolidated[0].reasons.len(), 2);
    }

    #[test]
    fn different_anchors_and_triggers_are_not_merged() {
        let result = deduplicate_seed_candidates(&[
            candidate("fn:A", "api.a", None),
            candidate("fn:B", "api.a", None),
            candidate("fn:A", "api.b", None),
        ])
        .unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn structured_identity_prevents_delimiter_collisions() {
        let mut first = candidate("fn:A", "api.a", None);
        first.evidence[0].kind = "a\u{1f}b".into();
        first.evidence[0].value = "c".into();
        let mut second = first.clone();
        second.evidence[0].kind = "a".into();
        second.evidence[0].value = "b\u{1f}c".into();
        assert_ne!(
            evidence_key(&first.evidence[0]),
            evidence_key(&second.evidence[0])
        );
        assert_eq!(
            consolidate_seed_candidates(&[first, second]).unwrap()[0]
                .evidence
                .len(),
            2
        );
    }

    #[test]
    fn deduplication_is_idempotent_and_permutation_invariant() {
        let first = candidate("fn:A", "api.a", Some("20"));
        let second = candidate("fn:A", "api.a", Some("10"));
        let forward =
            deduplicate_seed_candidates(&[first.clone(), second.clone(), first.clone()]).unwrap();
        let reverse = deduplicate_seed_candidates(&[second, first]).unwrap();
        assert_eq!(
            serde_json::to_string(&forward).unwrap(),
            serde_json::to_string(&reverse).unwrap()
        );
        assert_eq!(deduplicate_seed_candidates(&forward).unwrap(), forward);
    }

    #[test]
    fn invalid_candidates_and_conflicting_families_are_rejected() {
        let first = candidate("fn:A", "api.a", None);
        let mut invalid = first.clone();
        invalid.seed_id = "wrong".into();
        assert!(deduplicate_seed_candidates(&[invalid]).is_err());
        let mut conflicting = first.clone();
        conflicting.family = SeedTriggerFamily::Networking;
        assert!(deduplicate_seed_candidates(&[first, conflicting])
            .unwrap_err()
            .contains("conflicting families"));
    }
}
