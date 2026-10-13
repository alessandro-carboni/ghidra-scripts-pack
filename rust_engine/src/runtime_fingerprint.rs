//! CLI adapter: portable fingerprint plus a separate source-bearing sidecar.
use crate::canonical::CanonicalSubgraph;
use crate::fingerprint::{FingerprintConfig, OsgfFingerprint};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintOptions {
    pub input: String,
    pub output: String,
    pub config: FingerprintConfig,
}

pub fn parse_args(args: &[String]) -> Result<FingerprintOptions, String> {
    if args.len() < 2 || args[..2].iter().any(|a| a.starts_with('-')) {
        return Err("usage: rust_engine fingerprint-canonical <canonical.json> <fingerprint.json> [--max-topology-motifs N] [--max-interaction-motifs N]".into());
    }
    let mut config = FingerprintConfig::default();
    let mut seen = BTreeSet::new();
    let mut index = 2;
    while index < args.len() {
        let flag = &args[index];
        if !seen.insert(flag) {
            return Err(format!("duplicate option: {flag}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?
            .parse::<usize>()
            .map_err(|_| format!("invalid integer for {flag}"))?;
        match flag.as_str() {
            "--max-topology-motifs" => config.max_topology_motifs = value,
            "--max-interaction-motifs" => config.max_interaction_motifs = value,
            _ => return Err(format!("unknown option: {flag}")),
        }
        index += 2;
    }
    Ok(FingerprintOptions {
        input: args[0].clone(),
        output: args[1].clone(),
        config,
    })
}

pub fn run(options: FingerprintOptions) -> Result<(), String> {
    let input = Path::new(&options.input);
    let output = Path::new(&options.output);
    let sidecar = format!("{}.provenance.json", options.output);
    for target in [output, Path::new(&sidecar)] {
        if input == target
            || fs::canonicalize(input)
                .ok()
                .zip(fs::canonicalize(target).ok())
                .is_some_and(|(a, b)| a == b)
        {
            return Err("fingerprint outputs must not overwrite the canonical source".into());
        }
    }
    let text = fs::read_to_string(input).map_err(|e| format!("read canonical input: {e}"))?;
    let canonical: CanonicalSubgraph =
        serde_json::from_str(&text).map_err(|e| format!("invalid canonical JSON: {e}"))?;
    let fingerprint = OsgfFingerprint::with_config(&canonical, options.config)?;
    let serialized = fingerprint.to_json_pretty(&canonical)?;
    let provenance = fingerprint.resolve_provenance(&canonical)?;
    let provenance_json = serde_json::to_string_pretty(&provenance).map_err(|e| e.to_string())?;
    // Both documents are verified and serialized before either output is touched.
    fs::write(&sidecar, provenance_json)
        .map_err(|e| format!("write fingerprint provenance: {e}"))?;
    fs::write(output, serialized).map_err(|e| format!("write fingerprint: {e}"))?;
    println!(
        "[+] OSGF Fingerprint Baseline v0.1: {}",
        fingerprint.fingerprint_digest
    );
    println!("[+] Semantic digest: {}", fingerprint.semantic_digest);
    println!(
        "[+] Features: topology={} evidence={} interaction={} observability={}",
        fingerprint.rooted_topology_view.len(),
        fingerprint.typed_evidence_view.len(),
        fingerprint.interaction_motif_view.len(),
        fingerprint.observability_view.len()
    );
    for (view, limit) in &fingerprint.motif_truncation {
        println!(
            "[+] Motifs {view}: {} retained / {} enumerated; omitted={}",
            limit.retained, limit.enumerated, limit.omitted
        );
    }
    println!("[+] Fingerprint: {}", output.display());
    println!("[+] Provenance: {sidecar}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<FingerprintOptions, String> {
        parse_args(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }
    #[test]
    fn fingerprint_arguments_reject_duplicates_and_missing_values() {
        assert_eq!(
            parse(&["in", "out", "--max-topology-motifs", "0"])
                .unwrap()
                .config
                .max_topology_motifs,
            0
        );
        assert!(parse(&["in"]).is_err());
        assert!(parse(&["in", "out", "--max-topology-motifs"]).is_err());
        assert!(parse(&["in", "out", "--max-topology-motifs", "-1"]).is_err());
        assert!(parse(&["in", "out", "--unknown", "1"]).is_err());
        assert!(parse(&[
            "in",
            "out",
            "--max-topology-motifs",
            "1",
            "--max-topology-motifs",
            "2"
        ])
        .is_err());
    }
}
