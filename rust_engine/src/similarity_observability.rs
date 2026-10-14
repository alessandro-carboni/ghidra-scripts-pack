//! Observability diagnostics are separate from numerical semantic similarity.
use crate::fingerprint::{FingerprintFeature, OsgfFingerprint};
use crate::fingerprint_motifs::MotifTruncation;
use crate::local_subgraph::LocalTruncationMetadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityState {
    pub indirect_calls: Vec<FingerprintFeature>,
    pub unresolved_calls: Vec<FingerprintFeature>,
    pub unresolved_indirect_calls: Vec<FingerprintFeature>,
    pub explicit_dynamic_dispatch: Vec<FingerprintFeature>,
    /// Includes requested/effective depth and resource limits; these are not scores.
    pub local_graph: LocalTruncationMetadata,
    pub motif_truncation: BTreeMap<String, MotifTruncation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityDifference {
    pub field: String,
    pub query: Value,
    pub reference: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityComparison {
    pub query: ObservabilityState,
    pub reference: ObservabilityState,
    pub differences: Vec<ObservabilityDifference>,
    pub query_possibly_incomplete: bool,
    pub reference_possibly_incomplete: bool,
    pub possibly_incomplete: bool,
    pub warnings: Vec<String>,
}

impl ObservabilityState {
    pub fn from_fingerprint(fp: &OsgfFingerprint, local_graph: LocalTruncationMetadata) -> Self {
        let select = |kind: &str| {
            fp.observability_view
                .iter()
                .filter(|f| f.descriptor["kind"] == kind)
                .cloned()
                .collect()
        };
        Self {
            indirect_calls: select("indirect_calls"),
            unresolved_calls: select("unresolved_call"),
            unresolved_indirect_calls: select("unresolved_indirect_calls"),
            explicit_dynamic_dispatch: select("explicit_dynamic_dispatch"),
            local_graph,
            motif_truncation: fp.motif_truncation.clone(),
        }
    }

    fn warnings(&self, side: &str) -> Vec<String> {
        let mut warnings = vec![];
        if !self.unresolved_calls.is_empty() {
            warnings.push(format!("{side}: unresolved calls; targets remain unknown"));
        }
        if self.unresolved_indirect_calls.iter().any(|f| {
            f.descriptor["observed_count"]
                .as_u64()
                .is_some_and(|n| n > 0)
        }) {
            warnings.push(format!(
                "{side}: unresolved indirect calls; may overlap unresolved-call records"
            ));
        }
        for (kind, values) in [
            ("indirect_calls", &self.indirect_calls),
            ("unresolved_indirect_calls", &self.unresolved_indirect_calls),
            ("explicit_dynamic_dispatch", &self.explicit_dynamic_dispatch),
        ] {
            if values.is_empty()
                || values
                    .iter()
                    .any(|f| f.descriptor["observed_count"].is_null())
            {
                warnings.push(format!(
                    "{side}: {kind} observation unavailable; not interpreted as zero"
                ));
            }
        }
        if self.local_graph.truncated {
            warnings.push(format!("{side}: local graph truncated"));
        }
        for (family, metadata) in &self.motif_truncation {
            if metadata.truncated {
                warnings.push(format!("{side}: {family} motifs truncated"));
            }
        }
        // A lower effective depth can simply mean the reachable graph ended.
        // Neither it nor observed indirect/dynamic calls alone proves missing targets.
        warnings
    }
}

pub fn compare(
    query: ObservabilityState,
    reference: ObservabilityState,
) -> ObservabilityComparison {
    let q = serde_json::to_value(&query).unwrap();
    let r = serde_json::to_value(&reference).unwrap();
    let mut differences = vec![];
    for key in q.as_object().unwrap().keys() {
        if q[key] != r[key] {
            differences.push(ObservabilityDifference {
                field: key.clone(),
                query: q[key].clone(),
                reference: r[key].clone(),
            });
        }
    }
    let mut warnings = query.warnings("query");
    let query_possibly_incomplete = !warnings.is_empty();
    let reference_warnings = reference.warnings("reference");
    let reference_possibly_incomplete = !reference_warnings.is_empty();
    warnings.extend(reference_warnings);
    ObservabilityComparison {
        query,
        reference,
        differences,
        query_possibly_incomplete,
        reference_possibly_incomplete,
        possibly_incomplete: query_possibly_incomplete || reference_possibly_incomplete,
        warnings,
    }
}
