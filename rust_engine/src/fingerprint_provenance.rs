//! Source-bearing sidecar, deliberately separate from portable fingerprint bytes.
use crate::canonical::{CanonicalSubgraph, CoverageLedger, SourceReference};
use crate::fingerprint::OsgfFingerprint;
use crate::local_subgraph_schema::LocalSubgraphDocument;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum FeatureCoverage {
    Represented { feature_ids: Vec<String> },
    Excluded { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SourceCoverageTotals {
    pub nodes: usize,
    pub edges: usize,
    pub unresolved_records: usize,
    pub represented: usize,
    pub excluded: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalOrigin {
    pub canonical_element: String,
    pub source_references: Vec<SourceReference>,
    /// Metadata supports point directly into the embedded source document.
    pub source_metadata_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedOccurrence {
    pub multiplicity: u64,
    pub origins: Vec<CanonicalOrigin>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintProvenance {
    pub fingerprint_schema_version: String,
    pub fingerprint_digest: String,
    pub source_canonical_digest: String,
    pub source_document: LocalSubgraphDocument,
    pub canonical_source_coverage: CoverageLedger,
    pub features: BTreeMap<String, Vec<ResolvedOccurrence>>,
}

impl FingerprintProvenance {
    pub fn validate_against(
        &self,
        fingerprint: &OsgfFingerprint,
        canonical: &CanonicalSubgraph,
    ) -> Result<(), String> {
        if self != &fingerprint.resolve_provenance(canonical)? {
            return Err("fingerprint source sidecar is inconsistent".into());
        }
        Ok(())
    }
}

impl OsgfFingerprint {
    pub fn validate_against(&self, canonical: &CanonicalSubgraph) -> Result<(), String> {
        if self != &Self::with_config(canonical, self.config.clone())? {
            return Err("fingerprint differs from verified canonical source (features, counts, provenance, coverage or configuration)".into());
        }
        Ok(())
    }

    pub fn resolve_provenance(
        &self,
        canonical: &CanonicalSubgraph,
    ) -> Result<FingerprintProvenance, String> {
        self.validate_against(canonical)?;
        let mut features = BTreeMap::new();
        for (id, occurrences) in &self.provenance_index {
            let mut resolved = Vec::new();
            for occurrence in occurrences {
                let mut origins = Vec::new();
                for element in &occurrence.canonical_elements {
                    let (source_references, source_metadata_paths) = match element.as_str() {
                        "@local_graph_truncation" => (Vec::new(), vec!["/truncation".into()]),
                        "@coverage_ledger" => (
                            Vec::new(),
                            vec!["/nodes".into(), "/edges".into(), "/unresolved_calls".into()],
                        ),
                        _ => (
                            canonical
                                .provenance_map
                                .get(element)
                                .ok_or_else(|| format!("missing canonical provenance: {element}"))?
                                .clone(),
                            Vec::new(),
                        ),
                    };
                    origins.push(CanonicalOrigin {
                        canonical_element: element.clone(),
                        source_references,
                        source_metadata_paths,
                    });
                }
                resolved.push(ResolvedOccurrence {
                    multiplicity: occurrence.multiplicity,
                    origins,
                });
            }
            features.insert(id.clone(), resolved);
        }
        Ok(FingerprintProvenance {
            fingerprint_schema_version: self.schema_version.clone(),
            fingerprint_digest: self.fingerprint_digest.clone(),
            source_canonical_digest: canonical.canonical_digest.clone(),
            source_document: canonical.source_document.clone(),
            canonical_source_coverage: canonical.coverage_ledger.clone(),
            features,
        })
    }
}
