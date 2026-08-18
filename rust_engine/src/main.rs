mod capability;
mod enrichment;
mod rules;
mod schema;
mod scoring;

use std::env;
use std::fs;
use std::process;

use enrichment::build_rust_enrichment;
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

fn main() {
    if let Err(err) = run() {
        eprintln!("[!] {}", err);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_args(env::args().skip(1))?;

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
}
