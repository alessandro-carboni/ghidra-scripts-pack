#[allow(dead_code)]
mod canonical;
#[allow(dead_code)]
mod canonical_order;
#[allow(dead_code)]
mod fingerprint;
#[allow(dead_code)]
mod fingerprint_motifs;
#[allow(dead_code)]
mod fingerprint_provenance;
mod runtime_fingerprint;
mod runtime_similarity;
#[allow(dead_code)]
mod similarity;
mod similarity_observability;

#[allow(dead_code)]
mod local_subgraph;

#[allow(dead_code)]
mod local_subgraph_schema;

#[allow(dead_code)]
mod related_seed_grouping;

mod runtime_subgraph_export;

#[allow(dead_code)]
mod seed_validation;

#[allow(dead_code)]
mod graph_indexes;

#[allow(dead_code)]
mod graph;

mod capability;
mod enrichment;
mod rules;

#[allow(dead_code)]
mod seed_consolidation;

#[allow(dead_code)]
mod seed_detection;

#[allow(dead_code)]
mod seed_rules;

#[allow(dead_code)]
mod seed_ordering;

#[allow(dead_code)]
mod seed_deduplication;

#[allow(dead_code)]
mod seed_limits;

#[cfg(test)]
mod seed_detection_tests;

#[cfg(test)]
mod local_subgraph_tests;

mod schema;
mod scoring;

use std::env;
use std::fs;
use std::process;

use enrichment::build_rust_enrichment;
use runtime_subgraph_export::{
    export_local_subgraphs, parse_local_subgraph_export_args, LocalSubgraphExportOptions,
    SEEDED_SUBGRAPH_MANIFEST_FILENAME,
};
use schema::Report;

/// Parsed command-line invocation for the Rust enrichment engine.
///
/// `seeded_enabled` is recognized and stored here starting with Step 1.4, but it is
/// intentionally not read anywhere in the enrichment pipeline yet; that wiring belongs to
/// a later step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeOptions {
    input_path: String,
    output_path: String,
    seeded_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeCommand {
    Enrich(RuntimeOptions),
    ExportLocalSubgraphs(LocalSubgraphExportOptions),
    CanonicalizeLocalSubgraph { input: String, output: String },
    Fingerprint(runtime_fingerprint::FingerprintOptions),
    Similarity(Vec<String>),
}

/// Parses the engine's command-line arguments (excluding the program name).
///
/// Expected contract:
///   <input_report.json> <output_report.json> [--seeded]
///
/// - Exactly two positional arguments are required (input path, output path).
/// - `--seeded` is optional and, when present, sets `seeded_enabled = true`.
/// - Any other argument, a duplicate `--seeded`, a missing positional argument, or an
///   extra positional argument is rejected with a descriptive error instead of being
///   silently accepted or causing a panic.
fn parse_args<I, S>(args: I) -> Result<RuntimeOptions, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();

    if args.len() < 2 {
        return Err(
            "usage: rust_engine <input_report.json> <output_report.json> [--seeded]".to_string(),
        );
    }

    let input_path = args[0].clone();
    let output_path = args[1].clone();

    let mut seeded_enabled = false;

    for arg in &args[2..] {
        match arg.as_str() {
            "--seeded" => {
                if seeded_enabled {
                    return Err(format!("duplicate option: {}", arg));
                }
                seeded_enabled = true;
            }
            other => {
                return Err(format!("unknown argument: {}", other));
            }
        }
    }

    Ok(RuntimeOptions {
        input_path,
        output_path,
        seeded_enabled,
    })
}

fn parse_command<I, S>(args: I) -> Result<RuntimeCommand, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    if args.first().map(String::as_str) == Some("canonicalize-local-subgraph") {
        if args.len() != 3 || args[1..].iter().any(|a| a.starts_with('-')) {
            return Err(
                "usage: rust_engine canonicalize-local-subgraph <local.json> <canonical.json>"
                    .into(),
            );
        }
        return Ok(RuntimeCommand::CanonicalizeLocalSubgraph {
            input: args[1].clone(),
            output: args[2].clone(),
        });
    }
    if args.first().map(String::as_str) == Some("compare-fingerprints") {
        if !runtime_similarity::valid_args(&args[1..]) {
            return Err(runtime_similarity::USAGE.into());
        }
        return Ok(RuntimeCommand::Similarity(args[1..].to_vec()));
    }
    if args.first().map(String::as_str) == Some("fingerprint-canonical") {
        return runtime_fingerprint::parse_args(&args[1..]).map(RuntimeCommand::Fingerprint);
    }
    if args.first().map(String::as_str) == Some("export-local-subgraphs") {
        return parse_local_subgraph_export_args(args.into_iter().skip(1))
            .map(RuntimeCommand::ExportLocalSubgraphs);
    }
    parse_args(args).map(RuntimeCommand::Enrich)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[!] {}", err);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match parse_command(env::args().skip(1))? {
        RuntimeCommand::Similarity(args) => runtime_similarity::run(args),
        RuntimeCommand::Fingerprint(options) => runtime_fingerprint::run(options),
        RuntimeCommand::Enrich(options) => run_enrichment(options),
        RuntimeCommand::ExportLocalSubgraphs(options) => run_local_subgraph_export(options),
        RuntimeCommand::CanonicalizeLocalSubgraph { input, output } => {
            if input == output
                || fs::canonicalize(&input)
                    .ok()
                    .zip(fs::canonicalize(&output).ok())
                    .is_some_and(|(a, b)| a == b)
            {
                return Err("canonical output must differ from source path".into());
            }
            let text =
                fs::read_to_string(&input).map_err(|e| format!("read local subgraph: {e}"))?;
            let source: local_subgraph_schema::LocalSubgraphDocument =
                serde_json::from_str(&text).map_err(|e| format!("invalid local JSON: {e}"))?;
            let canonical = canonical::CanonicalSubgraph::from_source(&source)?;
            let text = canonical.to_json_pretty()?;
            fs::write(&output, text).map_err(|e| format!("write canonical subgraph: {e}"))?;
            println!(
                "[+] Canonicalization Baseline v0.1: {}",
                canonical.canonical_digest
            );
            println!(
                "[+] Coverage: {} represented / {} explicitly excluded",
                canonical.coverage_ledger.represented, canonical.coverage_ledger.excluded
            );
            println!("[+] Canonical subgraph: {output}");
            Ok(())
        }
    }
}

fn run_enrichment(options: RuntimeOptions) -> Result<(), String> {
    let input_data = fs::read_to_string(&options.input_path).map_err(|e| {
        format!(
            "failed to read input report '{}': {}",
            options.input_path, e
        )
    })?;

    let mut report: Report = serde_json::from_str(&input_data).map_err(|e| {
        format!(
            "failed to parse input report '{}': {}",
            options.input_path, e
        )
    })?;

    let enrichment = build_rust_enrichment(&report, options.seeded_enabled);
    report.rust_enrichment = Some(enrichment);

    let output_data = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("failed to serialize enriched report: {}", e))?;

    fs::write(&options.output_path, output_data).map_err(|e| {
        format!(
            "failed to write output report '{}': {}",
            options.output_path, e
        )
    })?;

    println!("[+] Enriched report written to: {}", options.output_path);
    Ok(())
}

fn run_local_subgraph_export(options: LocalSubgraphExportOptions) -> Result<(), String> {
    let manifest = export_local_subgraphs(&options)?;
    let manifest_path =
        std::path::Path::new(&options.output_dir).join(SEEDED_SUBGRAPH_MANIFEST_FILENAME);

    println!(
        "[+] Seeded local subgraphs exported to: {}",
        options.output_dir
    );
    println!(
        "[+] Seeds: {} returned / {} detected{}",
        manifest.seed_detection.returned,
        manifest.seed_detection.total_detected,
        if manifest.seed_detection.truncated {
            " (seed list truncated by technical max_seeds)"
        } else {
            ""
        }
    );
    println!("[+] Local subgraphs: {}", manifest.subgraphs.len());
    println!(
        "[+] Related seed groups: {}",
        manifest.related_seed_groups.len()
    );
    println!("[+] Manifest: {}", manifest_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_invocation_defaults_seeded_to_false() {
        let options = parse_args(vec!["input.json", "output.json"]).expect("should parse");

        assert_eq!(options.input_path, "input.json");
        assert_eq!(options.output_path, "output.json");
        assert!(!options.seeded_enabled);
    }

    #[test]
    fn seeded_flag_enables_seeded_mode() {
        let options =
            parse_args(vec!["input.json", "output.json", "--seeded"]).expect("should parse");

        assert_eq!(options.input_path, "input.json");
        assert_eq!(options.output_path, "output.json");
        assert!(options.seeded_enabled);
    }

    #[test]
    fn unknown_option_is_rejected() {
        let result = parse_args(vec!["input.json", "output.json", "--unknown"]);

        assert!(result.is_err());
    }

    #[test]
    fn missing_output_path_is_rejected() {
        let result = parse_args(vec!["input.json"]);

        assert!(result.is_err());
    }

    #[test]
    fn extra_positional_argument_is_rejected() {
        let result = parse_args(vec!["input.json", "output.json", "extra.json"]);

        assert!(result.is_err());
    }

    #[test]
    fn duplicate_seeded_argument_is_rejected() {
        let result = parse_args(vec!["input.json", "output.json", "--seeded", "--seeded"]);

        assert!(result.is_err());
    }

    #[test]
    fn export_subcommand_is_parsed_without_changing_legacy_contract() {
        let command = parse_command(vec![
            "export-local-subgraphs",
            "raw.json",
            "out",
            "--max-seeds",
            "3",
        ])
        .unwrap();

        match command {
            RuntimeCommand::ExportLocalSubgraphs(options) => {
                assert_eq!(options.input_path, "raw.json");
                assert_eq!(options.output_dir, "out");
                assert_eq!(options.seed_config.max_seeds, Some(3));
            }
            _ => panic!("expected export command"),
        }
    }

    #[test]
    fn legacy_command_still_uses_original_argument_parser() {
        assert_eq!(
            parse_command(vec!["input.json", "output.json", "--seeded"]).unwrap(),
            RuntimeCommand::Enrich(RuntimeOptions {
                input_path: "input.json".into(),
                output_path: "output.json".into(),
                seeded_enabled: true,
            })
        );
    }

    #[test]
    fn canonical_command_requires_exact_paths() {
        assert!(matches!(
            parse_command(["canonicalize-local-subgraph", "in.json", "out.json"]).unwrap(),
            RuntimeCommand::CanonicalizeLocalSubgraph { .. }
        ));
        assert!(parse_command(["canonicalize-local-subgraph", "in.json"]).is_err());
        assert!(parse_command([
            "canonicalize-local-subgraph",
            "in.json",
            "out.json",
            "extra"
        ])
        .is_err());
    }
}
