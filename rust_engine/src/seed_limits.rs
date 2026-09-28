//! Technical output limits applied after complete detection, deduplication and ordering.
//! These limits bound downstream seed work, not the initial typed-graph scan or its memory.
use crate::schema::{ConsolidatedSeed, SeedCandidate, SEED_MODEL_VERSION};
use crate::seed_consolidation::consolidate_seed_candidates;
use crate::seed_ordering::compare_evidence;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedDetectionConfig {
    /// None means unlimited; Some(0) returns no seeds but reports the detected total.
    #[serde(default)]
    pub max_seeds: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedTruncationReason {
    MaxSeeds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedDetectionResult {
    pub model_version: String,
    pub config: SeedDetectionConfig,
    pub seeds: Vec<ConsolidatedSeed>,
    /// Number of unique function anchors after consolidation, before limiting.
    pub total_detected: usize,
    pub returned: usize,
    pub truncated: bool,
    pub truncation_reason: Option<SeedTruncationReason>,
}

impl SeedDetectionResult {
    pub fn validate(&self) -> Result<(), String> {
        if self.model_version != SEED_MODEL_VERSION {
            return Err("unsupported seed detection model_version".into());
        }
        let expected_returned = self
            .config
            .max_seeds
            .unwrap_or(self.total_detected)
            .min(self.total_detected);
        if self.returned != self.seeds.len() || self.returned != expected_returned {
            return Err("seed detection returned count is inconsistent with seeds, total_detected or config".into());
        }
        let expected_truncated = self.returned < self.total_detected;
        let expected_reason = expected_truncated.then_some(SeedTruncationReason::MaxSeeds);
        if self.truncated != expected_truncated || self.truncation_reason != expected_reason {
            return Err("seed detection truncation metadata is inconsistent".into());
        }
        if self
            .seeds
            .windows(2)
            .any(|pair| pair[0].anchor_function_id >= pair[1].anchor_function_id)
        {
            return Err("seed detection anchors must be sorted and unique".into());
        }
        for seed in &self.seeds {
            seed.validate()?;
            if seed
                .evidence
                .windows(2)
                .any(|pair| !compare_evidence(&pair[0], &pair[1]).is_lt())
            {
                return Err("seed detection evidence must be sorted and unique".into());
            }
        }
        Ok(())
    }
}

/// Limits complete consolidated seeds; no per-evidence cap, so returned seeds retain
/// all observed evidence and explanations. Exact totals require visiting all candidates.
pub fn build_seed_detection_result(
    candidates: &[SeedCandidate],
    config: &SeedDetectionConfig,
) -> Result<SeedDetectionResult, String> {
    let mut seeds = consolidate_seed_candidates(candidates)?;
    let total_detected = seeds.len();
    if let Some(limit) = config.max_seeds {
        seeds.truncate(limit);
    }
    let returned = seeds.len();
    let truncated = returned < total_detected;
    let result = SeedDetectionResult {
        model_version: SEED_MODEL_VERSION.into(),
        config: config.clone(),
        seeds,
        total_detected,
        returned,
        truncated,
        truncation_reason: truncated.then_some(SeedTruncationReason::MaxSeeds),
    };
    result.validate()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{build_seed_id, SeedEvidence, SeedTriggerFamily};
    use serde_json::json;

    fn candidate(anchor: &str, trigger: &str, site: &str) -> SeedCandidate {
        SeedCandidate {
            seed_id: build_seed_id(anchor, trigger).unwrap(),
            anchor_function_id: anchor.into(),
            trigger_id: trigger.into(),
            family: SeedTriggerFamily::MemoryManagement,
            reason: format!("Observed {trigger}"),
            evidence: vec![SeedEvidence {
                kind: "api".into(),
                value: trigger.into(),
                node_id: Some(trigger.into()),
                edge_type: Some("calls_api".into()),
                callsite: Some(site.into()),
            }],
        }
    }

    fn input() -> Vec<SeedCandidate> {
        vec![
            candidate("fn:C", "api.a", "30"),
            candidate("fn:A", "api.a", "10"),
            candidate("fn:B", "api.a", "20"),
        ]
    }

    #[test]
    fn unlimited_default_returns_all_seeds_without_truncation() {
        let config: SeedDetectionConfig = serde_json::from_str("{}").unwrap();
        let result = build_seed_detection_result(&input(), &config).unwrap();
        assert_eq!(result.returned, 3);
        assert_eq!(result.total_detected, 3);
        assert!(!result.truncated);
        assert_eq!(result.truncation_reason, None);
    }

    #[test]
    fn limit_returns_canonical_prefix_with_explicit_metadata() {
        let result =
            build_seed_detection_result(&input(), &SeedDetectionConfig { max_seeds: Some(2) })
                .unwrap();
        assert_eq!(
            result
                .seeds
                .iter()
                .map(|seed| seed.anchor_function_id.as_str())
                .collect::<Vec<_>>(),
            vec!["fn:A", "fn:B"]
        );
        assert_eq!((result.total_detected, result.returned), (3, 2));
        assert!(result.truncated);
        assert_eq!(
            result.truncation_reason,
            Some(SeedTruncationReason::MaxSeeds)
        );
    }

    #[test]
    fn zero_limit_and_empty_detection_have_distinct_truncation_status() {
        let config = SeedDetectionConfig { max_seeds: Some(0) };
        let result = build_seed_detection_result(&input(), &config).unwrap();
        assert!(result.seeds.is_empty());
        assert_eq!((result.total_detected, result.returned), (3, 0));
        assert!(result.truncated);
        let empty = build_seed_detection_result(&[], &config).unwrap();
        assert!(!empty.truncated);
        assert_eq!(empty.truncation_reason, None);
        assert_eq!(empty.total_detected, 0);
    }

    #[test]
    fn exact_or_larger_limits_do_not_mark_complete_output_as_truncated() {
        for limit in [3, 4, usize::MAX] {
            let result = build_seed_detection_result(
                &input(),
                &SeedDetectionConfig {
                    max_seeds: Some(limit),
                },
            )
            .unwrap();
            assert_eq!(result.returned, 3);
            assert!(!result.truncated);
        }
    }

    #[test]
    fn limits_count_consolidated_anchors_and_preserve_all_returned_provenance() {
        let mut candidates = input();
        candidates.push(candidate("fn:A", "api.b", "15"));
        candidates.push(candidate("fn:A", "api.a", "11"));
        candidates.extend(candidates.clone());
        let result =
            build_seed_detection_result(&candidates, &SeedDetectionConfig { max_seeds: Some(1) })
                .unwrap();
        assert_eq!(result.total_detected, 3);
        assert_eq!(result.seeds[0].trigger_ids, vec!["api.a", "api.b"]);
        assert_eq!(result.seeds[0].evidence.len(), 3);
        assert_eq!(result.seeds[0].reasons.len(), 2);
    }

    #[test]
    fn limited_output_is_invariant_under_candidate_permutations() {
        let config = SeedDetectionConfig { max_seeds: Some(2) };
        let mut candidates = input();
        let expected = build_seed_detection_result(&candidates, &config).unwrap();
        candidates.reverse();
        assert_eq!(
            expected,
            build_seed_detection_result(&candidates, &config).unwrap()
        );
    }

    #[test]
    fn config_rejects_invalid_limits_and_priority_settings() {
        for value in [
            json!({"max_seeds": -1}),
            json!({"max_seeds": 1.5}),
            json!({"max_seeds": "2"}),
            json!({"minimum_priority": 1}),
            json!({"max_seeds": 1, "score": 50}),
        ] {
            assert!(serde_json::from_value::<SeedDetectionConfig>(value).is_err());
        }
    }

    #[test]
    fn result_round_trip_and_metadata_validation() {
        let result =
            build_seed_detection_result(&input(), &SeedDetectionConfig { max_seeds: Some(2) })
                .unwrap();
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["truncation_reason"], "max_seeds");
        let decoded: SeedDetectionResult = serde_json::from_value(json).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, result);
        let mut invalid = result.clone();
        invalid.returned = 1;
        assert!(invalid.validate().is_err());
        invalid = result.clone();
        invalid.total_detected = 0;
        assert!(invalid.validate().is_err());
        invalid = result.clone();
        invalid.truncated = false;
        assert!(invalid.validate().is_err());
        invalid = result.clone();
        invalid.truncation_reason = None;
        assert!(invalid.validate().is_err());
        invalid = result.clone();
        invalid.seeds.reverse();
        assert!(invalid.validate().is_err());
        invalid = result;
        invalid.model_version = "0.3.0".into();
        assert!(invalid.validate().is_err());
    }
}
