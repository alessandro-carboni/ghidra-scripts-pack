//! Deterministic, score-free grouping for seeds that describe closely related local contexts.
use crate::local_subgraph::LocalSubgraph;
use crate::schema::{ConsolidatedSeed, SeedEvidence, SeedTriggerFamily};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelatedSeedReason {
    ContainedLocalContextWithCorrelatedEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedSeedGroup {
    pub group_id: String,
    pub seed_ids: Vec<String>,
    pub anchor_function_ids: Vec<String>,
    pub reasons: Vec<RelatedSeedReason>,
}

impl RelatedSeedGroup {
    pub fn validate(&self) -> Result<(), String> {
        if self.seed_ids.len() < 2 {
            return Err("related seed group requires at least two seeds".to_string());
        }
        if self.seed_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("related seed group seed_ids must be sorted and unique".to_string());
        }
        if self.anchor_function_ids.is_empty()
            || self
                .anchor_function_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("related seed group anchors must be sorted and unique".to_string());
        }
        if self.reasons.is_empty() || self.reasons.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("related seed group reasons must be sorted and unique".to_string());
        }
        let expected = format!("related-seed-group:{}", self.seed_ids[0]);
        if self.group_id != expected {
            return Err(format!(
                "invalid related seed group id; expected '{expected}'"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SeedContext<'a> {
    seed: &'a ConsolidatedSeed,
    local: &'a LocalSubgraph,
}

/// Conservative Step 4.11 baseline.
///
/// Same-anchor trigger candidates have already been consolidated into one
/// `ConsolidatedSeed` by Step 3.6, so valid Step 4 inputs cannot contain two
/// distinct consolidated seeds with the same anchor.
///
/// Across different anchors, two seeds are grouped only when one selected FUNCTION
/// context fully contains the other *and* their evidence is descriptively correlated.
/// Full containment intentionally avoids a hand-tuned overlap percentage or score.
pub fn group_related_seeds(
    seeds: &[ConsolidatedSeed],
    subgraphs: &[LocalSubgraph],
) -> Result<Vec<RelatedSeedGroup>, String> {
    if seeds.len() != subgraphs.len() {
        return Err("seed/subgraph collections must have the same length".to_string());
    }

    let mut seed_by_id = BTreeMap::new();
    let mut seen_anchors = BTreeSet::new();
    for seed in seeds {
        seed.validate()?;
        if seed_by_id.insert(seed.seed_id.as_str(), seed).is_some() {
            return Err("duplicate seed_id in related-seed grouping input".to_string());
        }
        if !seen_anchors.insert(seed.anchor_function_id.as_str()) {
            return Err(
                "multiple consolidated seeds with the same anchor must be consolidated upstream"
                    .to_string(),
            );
        }
    }

    let mut local_by_id = BTreeMap::new();
    for local in subgraphs {
        if local_by_id.insert(local.seed_id.as_str(), local).is_some() {
            return Err("duplicate local subgraph seed_id in grouping input".to_string());
        }
    }

    let mut contexts = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let local = local_by_id
            .get(seed.seed_id.as_str())
            .copied()
            .ok_or_else(|| format!("missing local subgraph for seed '{}'", seed.seed_id))?;
        if local.selection.anchor_function_id != seed.anchor_function_id {
            return Err(format!(
                "local subgraph anchor does not match seed '{}'",
                seed.seed_id
            ));
        }
        contexts.push(SeedContext { seed, local });
    }
    contexts.sort_by(|left, right| left.seed.seed_id.cmp(&right.seed.seed_id));

    let mut adjacency: BTreeMap<String, BTreeSet<String>> = contexts
        .iter()
        .map(|ctx| (ctx.seed.seed_id.clone(), BTreeSet::new()))
        .collect();
    let mut pair_reasons: BTreeMap<(String, String), BTreeSet<RelatedSeedReason>> = BTreeMap::new();

    for i in 0..contexts.len() {
        for j in (i + 1)..contexts.len() {
            let left = &contexts[i];
            let right = &contexts[j];
            let reasons = relation_reasons(left, right);
            if reasons.is_empty() {
                continue;
            }
            let a = left.seed.seed_id.clone();
            let b = right.seed.seed_id.clone();
            adjacency.get_mut(&a).expect("known seed").insert(b.clone());
            adjacency.get_mut(&b).expect("known seed").insert(a.clone());
            pair_reasons.insert((a, b), reasons);
        }
    }

    let mut visited = BTreeSet::new();
    let mut groups = Vec::new();

    for seed_id in adjacency.keys() {
        if visited.contains(seed_id) {
            continue;
        }
        let mut queue = VecDeque::from([seed_id.clone()]);
        let mut component = BTreeSet::new();
        visited.insert(seed_id.clone());

        while let Some(current) = queue.pop_front() {
            component.insert(current.clone());
            for next in adjacency.get(&current).into_iter().flat_map(|v| v.iter()) {
                if visited.insert(next.clone()) {
                    queue.push_back(next.clone());
                }
            }
        }

        if component.len() < 2 {
            continue;
        }

        let seed_ids: Vec<String> = component.iter().cloned().collect();
        let anchor_function_ids: Vec<String> = seed_ids
            .iter()
            .map(|id| {
                seed_by_id
                    .get(id.as_str())
                    .expect("component seed is known")
                    .anchor_function_id
                    .clone()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let mut reasons = BTreeSet::new();
        for (pair, pair_values) in &pair_reasons {
            if component.contains(&pair.0) && component.contains(&pair.1) {
                reasons.extend(pair_values.iter().copied());
            }
        }

        let group = RelatedSeedGroup {
            group_id: format!("related-seed-group:{}", seed_ids[0]),
            seed_ids,
            anchor_function_ids,
            reasons: reasons.into_iter().collect(),
        };
        group.validate()?;
        groups.push(group);
    }

    groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    Ok(groups)
}

fn relation_reasons(
    left: &SeedContext<'_>,
    right: &SeedContext<'_>,
) -> BTreeSet<RelatedSeedReason> {
    let mut reasons = BTreeSet::new();
    if contexts_are_nested(left.local, right.local)
        && seed_evidence_is_correlated(left.seed, right.seed)
    {
        reasons.insert(RelatedSeedReason::ContainedLocalContextWithCorrelatedEvidence);
    }
    reasons
}

fn contexts_are_nested(left: &LocalSubgraph, right: &LocalSubgraph) -> bool {
    let a = &left.selection.function_ids;
    let b = &right.selection.function_ids;
    !a.is_empty() && !b.is_empty() && (a.is_subset(b) || b.is_subset(a))
}

fn seed_evidence_is_correlated(left: &ConsolidatedSeed, right: &ConsolidatedSeed) -> bool {
    let left_families: BTreeSet<SeedTriggerFamily> = left.families.iter().copied().collect();
    if right
        .families
        .iter()
        .any(|family| left_families.contains(family))
    {
        return true;
    }

    let left_triggers: BTreeSet<&str> = left.trigger_ids.iter().map(String::as_str).collect();
    if right
        .trigger_ids
        .iter()
        .any(|trigger| left_triggers.contains(trigger.as_str()))
    {
        return true;
    }

    let left_evidence: BTreeSet<_> = left.evidence.iter().map(evidence_semantic_key).collect();
    right
        .evidence
        .iter()
        .map(evidence_semantic_key)
        .any(|key| left_evidence.contains(&key))
}

fn evidence_semantic_key(evidence: &SeedEvidence) -> (&str, &str, Option<&str>, Option<&str>) {
    (
        evidence.kind.as_str(),
        evidence.value.as_str(),
        evidence.node_id.as_deref(),
        evidence.edge_type.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::TypedGraph;
    use crate::graph_indexes::GraphIndexes;
    use crate::local_subgraph::{extract_local_subgraph, LocalExtractionConfig};
    use crate::schema::{SeedEvidence, SeedTriggerFamily};
    use crate::seed_detection::detect_seeds;
    use crate::seed_limits::SeedDetectionConfig;
    use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules};
    use serde_json::Value;

    fn fixture() -> (ConsolidatedSeed, LocalSubgraph) {
        let value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
        let graph = TypedGraph::from_value(&value).unwrap();
        let seed = detect_seeds(
            &value,
            &load_seed_rules(bundled_seed_rules_path()).unwrap(),
            &SeedDetectionConfig::default(),
        )
        .unwrap()
        .seeds
        .remove(0);
        let local = extract_local_subgraph(
            &GraphIndexes::new(&graph),
            &seed,
            &LocalExtractionConfig::default(),
        )
        .unwrap();
        (seed, local)
    }

    fn second_seed(first: &ConsolidatedSeed, correlated: bool) -> ConsolidatedSeed {
        let mut seed = first.clone();
        seed.anchor_function_id = "fn:00402000".into();
        seed.seed_id = "seed:fn:00402000".into();
        seed.trigger_ids = vec!["api.writeprocessmemory".into()];
        seed.source_candidate_ids = vec!["seed:fn:00402000:api.writeprocessmemory".into()];
        seed.reasons = vec!["observed WriteProcessMemory call".into()];
        if correlated {
            seed.families = first.families.clone();
            seed.evidence = first.evidence.clone();
        } else {
            seed.families = vec![SeedTriggerFamily::ProcessMemoryAccess];
            seed.evidence = vec![SeedEvidence {
                kind: "api".into(),
                value: "WriteProcessMemory".into(),
                node_id: Some("api:writeprocessmemory".into()),
                edge_type: Some("calls_api".into()),
                callsite: Some("00402020".into()),
            }];
        }
        seed.validate().unwrap();
        seed
    }

    fn nested_local(first: &LocalSubgraph, second: &ConsolidatedSeed) -> LocalSubgraph {
        let mut local = first.clone();
        local.seed_id = second.seed_id.clone();
        local.selection.anchor_function_id = second.anchor_function_id.clone();
        local
            .selection
            .function_ids
            .insert(second.anchor_function_id.clone());
        local
            .selection
            .caller_distances
            .insert(second.anchor_function_id.clone(), 0);
        local
            .selection
            .callee_distances
            .insert(second.anchor_function_id.clone(), 0);
        local
    }

    #[test]
    fn same_anchor_is_already_consolidated_upstream() {
        let (seed, local) = fixture();
        assert!(group_related_seeds(&[seed.clone(), seed], &[local.clone(), local]).is_err());
    }

    #[test]
    fn nested_context_with_correlated_evidence_is_grouped() {
        let (first, first_local) = fixture();
        let second = second_seed(&first, true);
        let second_local = nested_local(&first_local, &second);
        let groups = group_related_seeds(
            &[first.clone(), second.clone()],
            &[first_local, second_local],
        )
        .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].seed_ids, vec![first.seed_id, second.seed_id]);
        assert_eq!(
            groups[0].reasons,
            vec![RelatedSeedReason::ContainedLocalContextWithCorrelatedEvidence]
        );
    }

    #[test]
    fn nested_context_without_correlated_evidence_is_not_grouped() {
        let (first, first_local) = fixture();
        let second = second_seed(&first, false);
        let second_local = nested_local(&first_local, &second);
        let groups = group_related_seeds(&[first, second], &[first_local, second_local]).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn grouping_is_permutation_invariant() {
        let (first, first_local) = fixture();
        let second = second_seed(&first, true);
        let second_local = nested_local(&first_local, &second);
        let a = group_related_seeds(
            &[first.clone(), second.clone()],
            &[first_local.clone(), second_local.clone()],
        )
        .unwrap();
        let b = group_related_seeds(&[second, first], &[second_local, first_local]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mismatched_seed_and_subgraph_is_rejected() {
        let (seed, mut local) = fixture();
        local.seed_id = "seed:fn:missing".into();
        assert!(group_related_seeds(&[seed], &[local]).is_err());
    }

    #[test]
    fn grouping_contract_contains_no_score_fields() {
        let group = RelatedSeedGroup {
            group_id: "related-seed-group:seed:fn:a".into(),
            seed_ids: vec!["seed:fn:a".into(), "seed:fn:b".into()],
            anchor_function_ids: vec!["fn:a".into(), "fn:b".into()],
            reasons: vec![RelatedSeedReason::ContainedLocalContextWithCorrelatedEvidence],
        };
        group.validate().unwrap();
        let text = serde_json::to_string(&group).unwrap();
        for forbidden in ["score", "priority", "confidence", "malicious"] {
            assert!(!text.contains(forbidden));
        }
    }
}
