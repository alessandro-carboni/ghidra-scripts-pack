//! Explicit additive CLI. Existing commands and default enrichment are unchanged.
use crate::graph::TypedGraph;
use crate::operational_context::{ContextConfig, GraphBundle, LocalEvidence};
use crate::operational_features::{FeatureConfig, OperationalCanonical, OperationalFingerprint};
use crate::operational_schema::{ensure, Evidence};
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io::Write};

pub const USAGE:&str="operational-bind <typed.json> <one-layer-evidence-dir> <new-graph.json> | operational-local <graph.json> <anchor-id> <config.json> <new-local.json> | operational-canonical <local.json> <new-canonical.json> | operational-fingerprint <canonical.json> <feature-config.json> <new-fingerprint.json> | operational-compare <query-fingerprint.json> <reference-fingerprint.json> <new-result.json>";
fn load<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn write<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())
}
pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("value-fingerprint") if args.len() == 3 => {
            let source: OperationalFingerprint = load(&args[1])?;
            write(
                &args[2],
                &crate::value_flow::ValueFingerprint::from_source(&source)?,
            )?;
        }
        Some("value-compare") if args.len() == 4 => {
            let q: crate::value_flow::ValueFingerprint = load(&args[1])?;
            let r: crate::value_flow::ValueFingerprint = load(&args[2])?;
            write(&args[3], &crate::value_flow::compare(&q, &r)?)?;
        }
        Some("operational-bind") if args.len() == 4 => {
            let graph: TypedGraph = load(&args[1])?;
            let mut evidence = Vec::new();
            let mut paths = fs::read_dir(&args[2])
                .map_err(|e| e.to_string())?
                .map(|p| p.map(|v| v.path()).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            paths.sort();
            for path in paths {
                if path.extension().is_some_and(|e| e == "json") {
                    let doc: Evidence = load(path.to_str().ok_or("invalid evidence path")?)?;
                    evidence.push(doc);
                }
            }
            ensure(!evidence.is_empty(), "no P-code evidence supplied")?;
            evidence.sort_by(|a, b| a.function.id.cmp(&b.function.id));
            let graph = GraphBundle {
                schema_version: "osgf.typed-operational-graph/0.2.0".into(),
                typed_graph: graph,
                operational_evidence: evidence,
            };
            graph.validate()?;
            write(&args[3], &graph)?;
        }
        Some("operational-local") if args.len() == 5 => {
            let graph: GraphBundle = load(&args[1])?;
            let config: ContextConfig = load(&args[3])?;
            write(
                &args[4],
                &LocalEvidence::from_graph(&graph, &args[2], config)?,
            )?;
        }
        Some("operational-canonical") if args.len() == 3 => {
            let local: LocalEvidence = load(&args[1])?;
            write(&args[2], &OperationalCanonical::from_source(&local)?)?;
        }
        Some("operational-fingerprint") if args.len() == 4 => {
            let canonical: OperationalCanonical = load(&args[1])?;
            let config: FeatureConfig = load(&args[2])?;
            write(
                &args[3],
                &OperationalFingerprint::from_canonical(&canonical, config)?,
            )?;
        }
        Some("operational-compare") if args.len() == 4 => {
            let q: OperationalFingerprint = load(&args[1])?;
            let r: OperationalFingerprint = load(&args[2])?;
            write(&args[3], &crate::operational_similarity::compare(&q, &r)?)?;
        }
        _ => return Err(USAGE.into()),
    }
    println!("PASS {}", args[0]);
    Ok(())
}
