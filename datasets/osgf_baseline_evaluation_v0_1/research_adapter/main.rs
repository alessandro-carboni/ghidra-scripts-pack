//! Separate research contract. No frozen CLI or frozen CanonicalSubgraph output.
#![allow(dead_code)]
mod canonical;
mod canonical_order;
mod fingerprint;
mod fingerprint_motifs;
mod fingerprint_provenance;
mod graph;
mod graph_indexes;
mod local_subgraph;
mod local_subgraph_schema;
mod schema;
mod seed_validation;
mod similarity;
mod similarity_observability;

use canonical::ResearchGraph;
use fingerprint::{FingerprintConfig, ResearchFingerprint};
use fingerprint_provenance::FingerprintProvenance;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: String,
    input_json: String,
    input_sha256: String,
    graph: ResearchGraph,
    fingerprint: ResearchFingerprint,
    provenance: FingerprintProvenance,
}

impl Bundle {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != "osgf-research-bundle-0.1.0"
            || self.input_sha256 != format!("{:x}", Sha256::digest(self.input_json.as_bytes()))
        {
            return Err("research input/version binding mismatch".into());
        }
        let local = serde_json::from_str(&self.input_json).map_err(|e| format!("local: {e}"))?;
        if self.graph != ResearchGraph::from_source(&local, &self.graph.condition)? {
            return Err("research source reconstruction mismatch".into());
        }
        self.graph.validate()?;
        self.fingerprint.validate_against(&self.graph)?;
        self.provenance
            .validate_against(&self.fingerprint, &self.graph)
    }
}

fn load(path: &str) -> Result<Bundle, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let bundle: Bundle = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    bundle.validate()?;
    Ok(bundle)
}

fn run(args: Vec<String>) -> Result<serde_json::Value, String> {
    match args.first().map(String::as_str) {
        Some("extract") if args.len() == 3 || args.len() == 5 => {
            let input_json = std::fs::read_to_string(&args[2]).map_err(|e| e.to_string())?;
            let local = serde_json::from_str(&input_json).map_err(|e| format!("local: {e}"))?;
            let graph = ResearchGraph::from_source(&local, &args[1])?;
            let config = if args.len() == 5 {
                FingerprintConfig {
                    max_topology_motifs: args[3].parse().map_err(|_| "invalid motif budget")?,
                    max_interaction_motifs: args[4].parse().map_err(|_| "invalid motif budget")?,
                }
            } else { FingerprintConfig::default() };
            let fingerprint = ResearchFingerprint::with_config(&graph, config)?;
            let provenance = fingerprint.resolve_provenance(&graph)?;
            let bundle = Bundle {
                schema_version: "osgf-research-bundle-0.1.0".into(),
                input_sha256: format!("{:x}", Sha256::digest(input_json.as_bytes())),
                input_json, graph, fingerprint, provenance,
            };
            bundle.validate()?;
            serde_json::to_value(bundle).map_err(|e| e.to_string())
        }
        Some("validate") if args.len() == 2 => {
            load(&args[1])?;
            Ok(serde_json::json!({"valid": true}))
        }
        Some("compare") if args.len() == 3 => {
            let q = load(&args[1])?;
            let r = load(&args[2])?;
            if q.graph.condition != r.graph.condition { return Err("cross-condition comparison forbidden".into()); }
            let result = similarity::SimilarityComparison::new(
                "query", &q.fingerprint, &q.graph, "reference", &r.fingerprint, &r.graph
            )?.finish_with_aggregate(true);
            serde_json::to_value(result).map_err(|e| e.to_string())
        }
        _ => Err("usage: research extract A|B local.json [topology_limit interaction_limit] | validate bundle.json | compare query.json reference.json".into()),
    }
}

fn main() {
    match run(std::env::args().skip(1).collect()) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
