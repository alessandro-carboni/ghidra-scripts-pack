//! Canonical presentation order, never a ranking of maliciousness.
//! IDs and callsites are compared lexicographically as supplied by the typed graph.
//! Missing optional provenance sorts before present provenance; no address rewriting.
use crate::schema::{ConsolidatedSeed, SeedCandidate, SeedEvidence};
use std::cmp::Ordering;

pub fn compare_evidence(left: &SeedEvidence, right: &SeedEvidence) -> Ordering {
    left.callsite
        .cmp(&right.callsite)
        .then_with(|| left.node_id.cmp(&right.node_id))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.value.cmp(&right.value))
        .then_with(|| left.edge_type.cmp(&right.edge_type))
}

fn compare_evidence_lists(left: &[SeedEvidence], right: &[SeedEvidence]) -> Ordering {
    left.iter()
        .zip(right)
        .map(|(a, b)| compare_evidence(a, b))
        .find(|order| *order != Ordering::Equal)
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

/// Sorts without dropping duplicates or changing provenance.
pub fn order_seed_candidates(seeds: &mut [SeedCandidate]) {
    for seed in seeds.iter_mut() {
        seed.evidence.sort_by(compare_evidence);
    }
    seeds.sort_by(|left, right| {
        left.anchor_function_id
            .cmp(&right.anchor_function_id)
            .then_with(|| left.trigger_id.cmp(&right.trigger_id))
            .then_with(|| compare_evidence_lists(&left.evidence, &right.evidence))
            // Complete ties deterministically even for externally supplied candidates.
            .then_with(|| left.reason.cmp(&right.reason))
            .then_with(|| left.family.cmp(&right.family))
            .then_with(|| left.seed_id.cmp(&right.seed_id))
    });
}

pub fn order_consolidated_seeds(seeds: &mut [ConsolidatedSeed]) {
    for seed in seeds.iter_mut() {
        seed.evidence.sort_by(compare_evidence);
    }
    seeds.sort_by(|left, right| {
        left.anchor_function_id
            .cmp(&right.anchor_function_id)
            .then_with(|| left.trigger_ids.cmp(&right.trigger_ids))
            .then_with(|| compare_evidence_lists(&left.evidence, &right.evidence))
            .then_with(|| left.source_candidate_ids.cmp(&right.source_candidate_ids))
            .then_with(|| left.reasons.cmp(&right.reasons))
            .then_with(|| left.families.cmp(&right.families))
            .then_with(|| left.seed_id.cmp(&right.seed_id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{build_seed_id, SeedTriggerFamily};

    fn evidence(site: Option<&str>, node: &str) -> SeedEvidence {
        SeedEvidence {
            kind: "api".into(),
            value: "Observed".into(),
            node_id: Some(node.into()),
            edge_type: Some("calls_api".into()),
            callsite: site.map(str::to_string),
        }
    }

    fn candidate(anchor: &str, trigger: &str, evidence: Vec<SeedEvidence>) -> SeedCandidate {
        SeedCandidate {
            seed_id: build_seed_id(anchor, trigger).unwrap(),
            anchor_function_id: anchor.into(),
            trigger_id: trigger.into(),
            evidence,
            reason: "Observed".into(),
            family: SeedTriggerFamily::MemoryManagement,
        }
    }

    #[test]
    fn anchor_then_trigger_then_callsite_determine_order() {
        let mut seeds = vec![
            candidate("fn:B", "api.a", vec![evidence(Some("01"), "api:a")]),
            candidate("fn:A", "api.z", vec![evidence(Some("01"), "api:z")]),
            candidate("fn:A", "api.a", vec![evidence(Some("20"), "api:a")]),
            candidate("fn:A", "api.a", vec![evidence(Some("10"), "api:z")]),
        ];
        order_seed_candidates(&mut seeds);
        assert_eq!(
            seeds
                .iter()
                .map(|s| (
                    s.anchor_function_id.as_str(),
                    s.trigger_id.as_str(),
                    s.evidence[0].callsite.as_deref()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("fn:A", "api.a", Some("10")),
                ("fn:A", "api.a", Some("20")),
                ("fn:A", "api.z", Some("01")),
                ("fn:B", "api.a", Some("01"))
            ]
        );
    }

    #[test]
    fn evidence_order_preserves_missing_sites_and_distinct_provenance() {
        let items = vec![
            evidence(Some("20"), "api:a"),
            evidence(Some("10"), "api:z"),
            evidence(Some("10"), "api:a"),
            evidence(None, "api:z"),
        ];
        let mut seeds = vec![candidate("fn:A", "api.a", items)];
        order_seed_candidates(&mut seeds);
        assert_eq!(
            seeds[0].evidence,
            vec![
                evidence(None, "api:z"),
                evidence(Some("10"), "api:a"),
                evidence(Some("10"), "api:z"),
                evidence(Some("20"), "api:a")
            ]
        );
    }

    #[test]
    fn permutations_produce_identical_json_and_ordering_is_idempotent() {
        let original = vec![
            candidate(
                "fn:B",
                "api.a",
                vec![evidence(Some("20"), "api:a"), evidence(Some("10"), "api:z")],
            ),
            candidate("fn:A", "api.z", vec![evidence(None, "api:z")]),
        ];
        let mut expected = original.clone();
        order_seed_candidates(&mut expected);
        let mut reversed = original;
        reversed.reverse();
        for candidate in &mut reversed {
            candidate.evidence.reverse();
        }
        order_seed_candidates(&mut reversed);
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            serde_json::to_string(&reversed).unwrap()
        );
        order_seed_candidates(&mut reversed);
        assert_eq!(expected, reversed);
    }

    #[test]
    fn ordering_does_not_deduplicate_or_change_ids() {
        let seed = candidate("fn:A", "api.a", vec![evidence(None, "api:a"); 2]);
        let mut seeds = vec![seed.clone(), seed.clone()];
        order_seed_candidates(&mut seeds);
        assert_eq!(seeds, vec![seed.clone(), seed]);
    }
}
