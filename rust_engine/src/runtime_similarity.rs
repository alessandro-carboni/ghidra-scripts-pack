//! CLI comparison of existing fingerprints with their validating canonical inputs.
use crate::canonical::CanonicalSubgraph;
use crate::fingerprint::OsgfFingerprint;
use crate::similarity::SimilarityComparison;
use std::fs;
use std::io::Write;

pub const USAGE: &str = "usage: rust_engine compare-fingerprints <query-id> <query-canonical.json> <query-fingerprint.json> <reference-id> <reference-canonical.json> <reference-fingerprint.json> <new-result.json>";

pub fn run(args: Vec<String>) -> Result<(), String> {
    if args.len() != 7 {
        return Err(USAGE.into());
    }
    let load = |canonical_path: &str,
                fingerprint_path: &str|
     -> Result<(CanonicalSubgraph, OsgfFingerprint), String> {
        let canonical =
            serde_json::from_str(&fs::read_to_string(canonical_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("canonical JSON: {e}"))?;
        let fingerprint =
            serde_json::from_str(&fs::read_to_string(fingerprint_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("fingerprint JSON: {e}"))?;
        Ok((canonical, fingerprint))
    };
    let (qc, q) = load(&args[1], &args[2])?;
    let (rc, r) = load(&args[4], &args[5])?;
    let result = SimilarityComparison::new(&args[0], &q, &qc, &args[3], &r, &rc)?.finish();
    let bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    // A new file is required, also protecting source paths and aliases.
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[6])
        .map_err(|e| format!("create new similarity result: {e}"))?;
    output
        .write_all(&bytes)
        .map_err(|e| format!("write similarity: {e}"))?;
    for (name, view) in [
        ("topology", result.rooted_topology),
        ("evidence", result.typed_evidence),
        ("interaction", result.interaction_motif),
    ] {
        let view = view.unwrap();
        println!("[+] {name}: set={:?} multiset={:?} comparable={} complete={} matched={} missing_query={} missing_reference={}",view.set_similarity,view.multiset_similarity,view.comparable,view.comparison_complete,view.matched.len(),view.missing_from_query.len(),view.missing_from_reference.len());
        for warning in view.warnings {
            println!("[!] {warning}");
        }
    }
    for warning in result.observability_warnings {
        println!("[!] {warning}");
    }
    println!("[+] Similarity result: {}", args[6]);
    Ok(())
}
