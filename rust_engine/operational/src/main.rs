//! Dedicated opt-in OSGF v0.2 executable; legacy entrypoint stays byte-identical.
#![allow(dead_code)]
// Legacy modules resolve bundled resources relative to the original crate.
// Preserve that lexical contract when compiling them in this nested package,
// without changing frozen source files or copying rules/fixtures. New package
// code can use std::env! explicitly for its actual Cargo manifest directory.
macro_rules! env {
    ("CARGO_MANIFEST_DIR") => {
        concat!(std::env!("CARGO_MANIFEST_DIR"), "/..")
    };
    ($($arguments:tt)*) => {
        std::env!($($arguments)*)
    };
}
#[path = "../../src/canonical.rs"]
mod canonical;
#[path = "../../src/canonical_order.rs"]
mod canonical_order;
#[path = "../../src/capability.rs"]
mod capability;
#[path = "../../src/enrichment.rs"]
mod enrichment;
#[path = "../../src/fingerprint.rs"]
mod fingerprint;
#[path = "../../src/fingerprint_motifs.rs"]
mod fingerprint_motifs;
#[path = "../../src/fingerprint_provenance.rs"]
mod fingerprint_provenance;
#[path = "../../src/graph.rs"]
mod graph;
#[path = "../../src/graph_indexes.rs"]
mod graph_indexes;
#[path = "../../src/local_subgraph.rs"]
mod local_subgraph;
#[path = "../../src/local_subgraph_schema.rs"]
mod local_subgraph_schema;
#[cfg(test)]
#[path = "../../src/local_subgraph_tests.rs"]
mod local_subgraph_tests;
#[path = "../../src/operational_context.rs"]
mod operational_context;
#[path = "../../src/operational_features.rs"]
mod operational_features;
#[path = "../../src/operational_schema.rs"]
mod operational_schema;
#[path = "../../src/operational_similarity.rs"]
mod operational_similarity;
#[path = "../../src/related_seed_grouping.rs"]
mod related_seed_grouping;
#[path = "../../src/rules.rs"]
mod rules;
#[path = "../../src/runtime_fingerprint.rs"]
mod runtime_fingerprint;
#[path = "../../src/runtime_operational.rs"]
mod runtime_operational;
#[path = "../../src/runtime_similarity.rs"]
mod runtime_similarity;
#[path = "../../src/runtime_subgraph_export.rs"]
mod runtime_subgraph_export;
#[path = "../../src/schema.rs"]
mod schema;
#[path = "../../src/scoring.rs"]
mod scoring;
#[path = "../../src/seed_consolidation.rs"]
mod seed_consolidation;
#[path = "../../src/seed_deduplication.rs"]
mod seed_deduplication;
#[path = "../../src/seed_detection.rs"]
mod seed_detection;
#[cfg(test)]
#[path = "../../src/seed_detection_tests.rs"]
mod seed_detection_tests;
#[path = "../../src/seed_limits.rs"]
mod seed_limits;
#[path = "../../src/seed_ordering.rs"]
mod seed_ordering;
#[path = "../../src/seed_rules.rs"]
mod seed_rules;
#[path = "../../src/seed_validation.rs"]
mod seed_validation;
#[path = "../../src/similarity.rs"]
mod similarity;
#[path = "../../src/similarity_observability.rs"]
mod similarity_observability;
#[path = "../../src/value_flow.rs"]
mod value_flow;

fn main() {
    if let Err(error) = runtime_operational::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("[!] {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod packaging_tests {
    #[test]
    fn shared_rules_resolve_to_original_repository_resource() {
        let expected = std::path::Path::new(std::env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/seed_rules.json")
            .canonicalize()
            .unwrap();
        assert_eq!(
            crate::seed_rules::bundled_seed_rules_path()
                .canonicalize()
                .unwrap(),
            expected
        );
        crate::seed_rules::load_seed_rules(&expected).unwrap();
    }
}
