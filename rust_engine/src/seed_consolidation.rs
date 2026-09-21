use crate::schema::{build_consolidated_seed_id, ConsolidatedSeed, SeedCandidate, SeedEvidence};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
struct ConsolidationAccumulator {
    trigger_ids: BTreeSet<String>,
    source_candidate_ids: BTreeSet<String>,
    evidence_by_key: BTreeMap<String, SeedEvidence>,
    reasons: BTreeSet<String>,
}

/// Consolidates atomic trigger-level `SeedCandidate`s into one deterministic seed per anchor.
///
/// No ranking, weighting or maliciousness scoring is performed. The operation only groups
/// observed evidence that already points to the same function anchor.
pub fn consolidate_seed_candidates(
    candidates: &[SeedCandidate],
) -> Result<Vec<ConsolidatedSeed>, String> {
    let mut by_anchor: BTreeMap<String, ConsolidationAccumulator> = BTreeMap::new();

    for candidate in candidates {
        candidate.validate()?;

        let accumulator = by_anchor
            .entry(candidate.anchor_function_id.clone())
            .or_default();

        accumulator.trigger_ids.insert(candidate.trigger_id.clone());
        accumulator
            .source_candidate_ids
            .insert(candidate.seed_id.clone());
        accumulator.reasons.insert(candidate.reason.clone());

        for evidence in &candidate.evidence {
            accumulator
                .evidence_by_key
                .entry(evidence_key(evidence))
                .or_insert_with(|| evidence.clone());
        }
    }

    let mut consolidated = Vec::with_capacity(by_anchor.len());

    for (anchor_function_id, accumulator) in by_anchor {
        let seed = ConsolidatedSeed {
            seed_id: build_consolidated_seed_id(&anchor_function_id)?,
            anchor_function_id,
            trigger_ids: accumulator.trigger_ids.into_iter().collect(),
            source_candidate_ids: accumulator.source_candidate_ids.into_iter().collect(),
            evidence: accumulator.evidence_by_key.into_values().collect(),
            reasons: accumulator.reasons.into_iter().collect(),
        };

        seed.validate()?;
        consolidated.push(seed);
    }

    Ok(consolidated)
}

fn evidence_key(evidence: &SeedEvidence) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        evidence.kind,
        evidence.value,
        evidence.node_id.as_deref().unwrap_or(""),
        evidence.edge_type.as_deref().unwrap_or(""),
        evidence.callsite.as_deref().unwrap_or("")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::build_seed_id;

    fn candidate(
        anchor: &str,
        trigger: &str,
        reason: &str,
        evidence: Vec<SeedEvidence>,
    ) -> SeedCandidate {
        SeedCandidate {
            seed_id: build_seed_id(anchor, trigger).expect("test seed id should be valid"),
            anchor_function_id: anchor.to_string(),
            trigger_id: trigger.to_string(),
            evidence,
            reason: reason.to_string(),
        }
    }

    fn evidence(
        kind: &str,
        value: &str,
        node_id: &str,
        edge_type: &str,
        callsite: Option<&str>,
    ) -> SeedEvidence {
        SeedEvidence {
            kind: kind.to_string(),
            value: value.to_string(),
            node_id: Some(node_id.to_string()),
            edge_type: Some(edge_type.to_string()),
            callsite: callsite.map(str::to_string),
        }
    }

    #[test]
    fn multiple_triggers_on_same_anchor_become_one_consolidated_seed() {
        let candidates = vec![
            candidate(
                "fn:140001000",
                "api.virtualallocex",
                "Function calls API VirtualAllocEx",
                vec![evidence(
                    "api",
                    "VirtualAllocEx",
                    "api:virtualallocex",
                    "calls_api",
                    Some("140001050"),
                )],
            ),
            candidate(
                "fn:140001000",
                "constant_category.memory_protection",
                "Function uses constant evidence from category memory_protection",
                vec![evidence(
                    "constant",
                    "PAGE_EXECUTE_READWRITE",
                    "const:memory_protection:0x40",
                    "uses_constant",
                    Some("140001040"),
                )],
            ),
            candidate(
                "fn:140001000",
                "api.writeprocessmemory",
                "Function calls API WriteProcessMemory",
                vec![evidence(
                    "api",
                    "WriteProcessMemory",
                    "api:writeprocessmemory",
                    "calls_api",
                    Some("140001090"),
                )],
            ),
        ];

        let seeds = consolidate_seed_candidates(&candidates).expect("consolidation should succeed");

        assert_eq!(seeds.len(), 1);
        let seed = &seeds[0];
        assert_eq!(seed.seed_id, "seed:fn:140001000");
        assert_eq!(seed.anchor_function_id, "fn:140001000");
        assert_eq!(
            seed.trigger_ids,
            vec![
                "api.virtualallocex".to_string(),
                "api.writeprocessmemory".to_string(),
                "constant_category.memory_protection".to_string(),
            ]
        );
        assert_eq!(seed.evidence.len(), 3);
        assert_eq!(seed.reasons.len(), 3);
    }

    #[test]
    fn candidates_from_different_anchors_remain_separate() {
        let candidates = vec![
            candidate(
                "fn:140001000",
                "api.virtualalloc",
                "Function calls API VirtualAlloc",
                vec![evidence(
                    "api",
                    "VirtualAlloc",
                    "api:virtualalloc",
                    "calls_api",
                    Some("140001010"),
                )],
            ),
            candidate(
                "fn:140002000",
                "api.virtualalloc",
                "Function calls API VirtualAlloc",
                vec![evidence(
                    "api",
                    "VirtualAlloc",
                    "api:virtualalloc",
                    "calls_api",
                    Some("140002010"),
                )],
            ),
        ];

        let seeds = consolidate_seed_candidates(&candidates).expect("consolidation should succeed");

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].anchor_function_id, "fn:140001000");
        assert_eq!(seeds[1].anchor_function_id, "fn:140002000");
    }

    #[test]
    fn duplicate_candidates_and_evidence_are_deduplicated() {
        let repeated = candidate(
            "fn:140001000",
            "api.virtualalloc",
            "Function calls API VirtualAlloc",
            vec![evidence(
                "api",
                "VirtualAlloc",
                "api:virtualalloc",
                "calls_api",
                Some("140001010"),
            )],
        );

        let seeds = consolidate_seed_candidates(&[repeated.clone(), repeated])
            .expect("consolidation should succeed");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].trigger_ids.len(), 1);
        assert_eq!(seeds[0].source_candidate_ids.len(), 1);
        assert_eq!(seeds[0].evidence.len(), 1);
        assert_eq!(seeds[0].reasons.len(), 1);
    }

    #[test]
    fn consolidation_is_deterministic_across_candidate_order() {
        let first = candidate(
            "fn:140001000",
            "api.getprocaddress",
            "Function calls API GetProcAddress",
            vec![evidence(
                "api",
                "GetProcAddress",
                "api:getprocaddress",
                "calls_api",
                Some("140001030"),
            )],
        );
        let second = candidate(
            "fn:140001000",
            "string_category.url",
            "Function references string categorized as url",
            vec![evidence(
                "string_category",
                "url",
                "strcat:url",
                "has_string_category",
                None,
            )],
        );

        let forward = consolidate_seed_candidates(&[first.clone(), second.clone()])
            .expect("forward consolidation should succeed");
        let reverse = consolidate_seed_candidates(&[second, first])
            .expect("reverse consolidation should succeed");

        assert_eq!(forward, reverse);
    }

    #[test]
    fn singleton_candidate_still_becomes_valid_consolidated_seed() {
        let candidates = vec![candidate(
            "fn:140001000",
            "visibility_signal.indirect_call",
            "Function contains visibility signal indirect_call",
            vec![evidence(
                "visibility_signal",
                "indirect_call",
                "vis:call_visibility:fn:140001000",
                "contains_indirect_call",
                Some("140001020"),
            )],
        )];

        let seeds = consolidate_seed_candidates(&candidates).expect("consolidation should succeed");

        assert_eq!(seeds.len(), 1);
        seeds[0]
            .validate()
            .expect("singleton consolidated seed should validate");
    }

    #[test]
    fn empty_candidate_set_produces_empty_seed_set() {
        let seeds = consolidate_seed_candidates(&[]).expect("empty consolidation should be valid");

        assert!(seeds.is_empty());
    }

    #[test]
    fn invalid_atomic_candidate_is_rejected_before_consolidation() {
        let mut invalid = candidate(
            "fn:140001000",
            "api.virtualalloc",
            "Function calls API VirtualAlloc",
            vec![evidence(
                "api",
                "VirtualAlloc",
                "api:virtualalloc",
                "calls_api",
                Some("140001010"),
            )],
        );
        invalid.seed_id = "seed:fn:WRONG:api.virtualalloc".to_string();

        assert!(consolidate_seed_candidates(&[invalid]).is_err());
    }

    #[test]
    fn consolidated_seed_serialization_contains_no_scoring_fields() {
        let seeds = consolidate_seed_candidates(&[candidate(
            "fn:140001000",
            "api.virtualalloc",
            "Function calls API VirtualAlloc",
            vec![evidence(
                "api",
                "VirtualAlloc",
                "api:virtualalloc",
                "calls_api",
                Some("140001010"),
            )],
        )])
        .expect("consolidation should succeed");

        let serialized =
            serde_json::to_value(&seeds[0]).expect("consolidated seed should serialize");

        for forbidden_field in [
            "score",
            "priority",
            "confidence",
            "risk_level",
            "legacy_metadata",
            "function_score",
        ] {
            assert!(
                serialized.get(forbidden_field).is_none(),
                "consolidated seed must not expose scoring field: {forbidden_field}"
            );
        }
    }
}
