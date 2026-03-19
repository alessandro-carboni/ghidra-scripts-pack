mod capability;
mod enrichment;
mod schema;
mod scoring;

use std::env;
use std::fs;
use std::process;

use enrichment::build_rust_enrichment;
use schema::Report;

fn main() {
    if let Err(err) = run() {
        eprintln!("[!] {}", err);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        return Err("usage: rust_engine <input_report.json> <output_report.json>".to_string());
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let input_data = fs::read_to_string(input_path)
        .map_err(|e| format!("failed to read input report '{}': {}", input_path, e))?;

    let mut report: Report = serde_json::from_str(&input_data)
        .map_err(|e| format!("failed to parse input report '{}': {}", input_path, e))?;

    let enrichment = build_rust_enrichment(&report);
    report.rust_enrichment = Some(enrichment);

    let output_data = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("failed to serialize enriched report: {}", e))?;

    fs::write(output_path, output_data)
        .map_err(|e| format!("failed to write output report '{}': {}", output_path, e))?;

    println!("[+] Enriched report written to: {}", output_path);
    Ok(())
}