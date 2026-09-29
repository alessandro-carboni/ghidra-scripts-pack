//! Runtime bridge from a real raw report to GUI-ready seeded local-subgraph JSON files.
//! This module performs no scoring and does not alter the legacy enrichment path.

use crate::graph::{TypedGraph, TYPED_GRAPH_MODEL_VERSION};
use crate::graph_indexes::GraphIndexes;
use crate::local_subgraph::{extract_local_subgraph, LocalExtractionConfig, LocalSubgraph};
use crate::local_subgraph_schema::{LocalSubgraphDocument, LOCAL_SUBGRAPH_SCHEMA_VERSION};
use crate::related_seed_grouping::{group_related_seeds, RelatedSeedGroup};
use crate::schema::Report;
use crate::seed_detection::detect_seeds_from_report;
use crate::seed_limits::{SeedDetectionConfig, SeedDetectionResult};
use crate::seed_rules::{bundled_seed_rules_path, load_seed_rules, SEED_RULES_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const SEEDED_SUBGRAPH_EXPORT_MANIFEST_VERSION: &str = "0.1.0";
pub const SEEDED_SUBGRAPH_MANIFEST_FILENAME: &str = "manifest.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSubgraphExportOptions {
    pub input_path: String,
    pub output_dir: String,
    pub rules_path: Option<String>,
    pub seed_config: SeedDetectionConfig,
    pub extraction_config: LocalExtractionConfig,
}

impl LocalSubgraphExportOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.input_path.trim().is_empty() {
            return Err("local-subgraph export input path cannot be empty".to_string());
        }
        if self.output_dir.trim().is_empty() {
            return Err("local-subgraph export output directory cannot be empty".to_string());
        }
        self.extraction_config.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSubgraphExportEntry {
    pub seed_id: String,
    pub anchor_function_id: String,
    pub file: String,
    pub truncated: bool,
    pub function_nodes: usize,
    pub evidence_nodes: usize,
    pub total_nodes: usize,
    pub edges: usize,
    pub unresolved_calls: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeededSubgraphExportManifest {
    pub schema_version: String,
    pub local_subgraph_schema_version: String,
    pub source_report: String,
    pub sample_name: String,
    pub graph_version: String,
    pub seed_rules_version: String,
    pub seed_detection: SeedDetectionResult,
    pub extraction_config: LocalExtractionConfig,
    pub subgraphs: Vec<LocalSubgraphExportEntry>,
    pub related_seed_groups: Vec<RelatedSeedGroup>,
}

impl SeededSubgraphExportManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SEEDED_SUBGRAPH_EXPORT_MANIFEST_VERSION {
            return Err(format!(
                "unsupported seeded-subgraph manifest version '{}'; expected '{}'",
                self.schema_version, SEEDED_SUBGRAPH_EXPORT_MANIFEST_VERSION
            ));
        }
        if self.local_subgraph_schema_version != LOCAL_SUBGRAPH_SCHEMA_VERSION {
            return Err(format!(
                "unexpected local-subgraph schema version '{}'; expected '{}'",
                self.local_subgraph_schema_version, LOCAL_SUBGRAPH_SCHEMA_VERSION
            ));
        }
        if self.source_report.trim().is_empty() {
            return Err("manifest source_report cannot be empty".to_string());
        }
        if self.graph_version != TYPED_GRAPH_MODEL_VERSION {
            return Err(format!(
                "unexpected typed graph version '{}'; expected '{}'",
                self.graph_version, TYPED_GRAPH_MODEL_VERSION
            ));
        }
        if self.seed_rules_version != SEED_RULES_SCHEMA_VERSION {
            return Err(format!(
                "unexpected seed rules version '{}'; expected '{}'",
                self.seed_rules_version, SEED_RULES_SCHEMA_VERSION
            ));
        }
        self.seed_detection.validate()?;
        self.extraction_config.validate()?;

        if self.subgraphs.len() != self.seed_detection.seeds.len() {
            return Err("manifest subgraph count must match returned seed count".to_string());
        }
        if self
            .subgraphs
            .windows(2)
            .any(|pair| pair[0].seed_id >= pair[1].seed_id)
        {
            return Err("manifest subgraphs must be sorted and unique by seed_id".to_string());
        }

        for (entry, seed) in self.subgraphs.iter().zip(&self.seed_detection.seeds) {
            if entry.seed_id != seed.seed_id || entry.anchor_function_id != seed.anchor_function_id
            {
                return Err("manifest subgraph entry does not match seed detection output".into());
            }
            if entry.file.trim().is_empty() || !entry.file.ends_with(".json") {
                return Err("manifest subgraph file must be a JSON filename".to_string());
            }
            if entry.total_nodes != entry.function_nodes + entry.evidence_nodes {
                return Err(
                    "manifest total_nodes must equal function_nodes + evidence_nodes".into(),
                );
            }
        }

        for group in &self.related_seed_groups {
            group.validate()?;
            for seed_id in &group.seed_ids {
                if !self
                    .seed_detection
                    .seeds
                    .iter()
                    .any(|seed| &seed.seed_id == seed_id)
                {
                    return Err(format!(
                        "related seed group references unknown seed_id '{seed_id}'"
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn to_json_pretty(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize seeded-subgraph export manifest: {e}"))
    }

    #[cfg(test)]
    pub fn from_json(data: &str) -> Result<Self, String> {
        let manifest: Self = serde_json::from_str(data)
            .map_err(|e| format!("invalid seeded-subgraph export manifest JSON: {e}"))?;
        manifest.validate()?;
        Ok(manifest)
    }
}

pub fn parse_local_subgraph_export_args<I, S>(args: I) -> Result<LocalSubgraphExportOptions, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    if args.len() < 2 {
        return Err(export_usage());
    }

    let input_path = args[0].clone();
    let output_dir = args[1].clone();
    let mut rules_path = None;
    let mut seed_config = SeedDetectionConfig::default();
    let mut extraction_config = LocalExtractionConfig::default();

    let mut index = 2;
    while index < args.len() {
        let option = args[index].as_str();
        if index + 1 >= args.len() {
            return Err(format!(
                "option '{option}' requires a value\n{}",
                export_usage()
            ));
        }
        let value = &args[index + 1];

        match option {
            "--rules" => set_once(&mut rules_path, value.clone(), "--rules")?,
            "--max-seeds" => set_usize_once(&mut seed_config.max_seeds, value, "--max-seeds")?,
            "--caller-depth" => {
                extraction_config.caller_depth = parse_usize(value, "--caller-depth")?
            }
            "--callee-depth" => {
                extraction_config.callee_depth = parse_usize(value, "--callee-depth")?
            }
            "--max-function-nodes" => set_usize_once(
                &mut extraction_config.max_function_nodes,
                value,
                "--max-function-nodes",
            )?,
            "--max-evidence-nodes" => set_usize_once(
                &mut extraction_config.max_evidence_nodes,
                value,
                "--max-evidence-nodes",
            )?,
            "--max-total-nodes" => set_usize_once(
                &mut extraction_config.max_total_nodes,
                value,
                "--max-total-nodes",
            )?,
            "--max-edges" => {
                set_usize_once(&mut extraction_config.max_edges, value, "--max-edges")?
            }
            other => {
                return Err(format!(
                    "unknown export option: {other}\n{}",
                    export_usage()
                ))
            }
        }

        index += 2;
    }

    let options = LocalSubgraphExportOptions {
        input_path,
        output_dir,
        rules_path,
        seed_config,
        extraction_config,
    };
    options.validate()?;
    Ok(options)
}

pub fn export_usage() -> String {
    concat!(
        "usage: rust_engine export-local-subgraphs <input_report.json> <output_dir>",
        " [--rules <seed_rules.json>]",
        " [--max-seeds <N>]",
        " [--caller-depth <N>]",
        " [--callee-depth <N>]",
        " [--max-function-nodes <N>]",
        " [--max-evidence-nodes <N>]",
        " [--max-total-nodes <N>]",
        " [--max-edges <N>]"
    )
    .to_string()
}

pub fn export_local_subgraphs(
    options: &LocalSubgraphExportOptions,
) -> Result<SeededSubgraphExportManifest, String> {
    options.validate()?;

    let input_path = Path::new(&options.input_path);
    let output_dir = Path::new(&options.output_dir);

    if output_dir.exists() {
        return Err(format!(
            "output directory '{}' already exists; choose a new directory so stale GUI data cannot be mixed with this export",
            output_dir.display()
        ));
    }

    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| format!("create output parent '{}': {e}", parent.display()))?;

    let dir_name = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output directory must have a valid final path component".to_string())?;
    let staging_dir = parent.join(format!(".{dir_name}.tmp-{}", std::process::id()));

    if staging_dir.exists() {
        return Err(format!(
            "temporary export directory '{}' already exists",
            staging_dir.display()
        ));
    }

    fs::create_dir(&staging_dir)
        .map_err(|e| format!("create staging directory '{}': {e}", staging_dir.display()))?;

    let result = export_into_directory(options, input_path, &staging_dir);
    match result {
        Ok(manifest) => {
            if let Err(err) = fs::rename(&staging_dir, output_dir) {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(format!(
                    "finalize seeded-subgraph export '{}' -> '{}': {err}",
                    staging_dir.display(),
                    output_dir.display()
                ));
            }
            Ok(manifest)
        }
        Err(err) => {
            let _ = fs::remove_dir_all(&staging_dir);
            Err(err)
        }
    }
}

fn export_into_directory(
    options: &LocalSubgraphExportOptions,
    input_path: &Path,
    output_dir: &Path,
) -> Result<SeededSubgraphExportManifest, String> {
    let input_data = fs::read_to_string(input_path).map_err(|e| {
        format!(
            "failed to read input report '{}': {e}",
            input_path.display()
        )
    })?;
    let report: Report = serde_json::from_str(&input_data).map_err(|e| {
        format!(
            "failed to parse input report '{}': {e}",
            input_path.display()
        )
    })?;

    let graph = TypedGraph::from_report(&report)?;
    let graph_index = GraphIndexes::new(&graph);

    let rules_path = options
        .rules_path
        .as_ref()
        .map(|path| PathBuf::from(path.as_str()))
        .unwrap_or_else(bundled_seed_rules_path);
    let rules = load_seed_rules(&rules_path)?;

    let seed_detection = detect_seeds_from_report(&report, &rules, &options.seed_config)?;
    seed_detection.validate()?;

    let mut local_subgraphs: Vec<LocalSubgraph> = Vec::with_capacity(seed_detection.seeds.len());
    let mut subgraphs = Vec::with_capacity(seed_detection.seeds.len());

    for seed in &seed_detection.seeds {
        let local = extract_local_subgraph(&graph_index, seed, &options.extraction_config)?;
        let document = LocalSubgraphDocument::from_local(&local)?;
        let file = local_subgraph_filename(&seed.seed_id);
        document.write_pretty(output_dir.join(&file))?;

        subgraphs.push(LocalSubgraphExportEntry {
            seed_id: seed.seed_id.clone(),
            anchor_function_id: seed.anchor_function_id.clone(),
            file,
            truncated: document.truncation.truncated,
            function_nodes: document.truncation.counts.function_nodes,
            evidence_nodes: document.truncation.counts.evidence_nodes,
            total_nodes: document.truncation.counts.total_nodes,
            edges: document.truncation.counts.edges,
            unresolved_calls: document.truncation.counts.unresolved_calls,
        });
        local_subgraphs.push(local);
    }

    let related_seed_groups = group_related_seeds(&seed_detection.seeds, &local_subgraphs)?;

    let source_report = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&options.input_path)
        .to_string();

    let sample_name = if report.sample.name.trim().is_empty() {
        report.summary.sample_name.clone()
    } else {
        report.sample.name.clone()
    };

    let manifest = SeededSubgraphExportManifest {
        schema_version: SEEDED_SUBGRAPH_EXPORT_MANIFEST_VERSION.to_string(),
        local_subgraph_schema_version: LOCAL_SUBGRAPH_SCHEMA_VERSION.to_string(),
        source_report,
        sample_name,
        graph_version: graph.model_version().to_string(),
        seed_rules_version: rules.schema_version.clone(),
        seed_detection,
        extraction_config: options.extraction_config.clone(),
        subgraphs,
        related_seed_groups,
    };
    manifest.validate()?;

    fs::write(
        output_dir.join(SEEDED_SUBGRAPH_MANIFEST_FILENAME),
        manifest.to_json_pretty()?,
    )
    .map_err(|e| {
        format!(
            "write seeded-subgraph manifest '{}': {e}",
            output_dir.join(SEEDED_SUBGRAPH_MANIFEST_FILENAME).display()
        )
    })?;

    Ok(manifest)
}

fn parse_usize(value: &str, option: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{option} requires a non-negative integer, got '{value}'"))
}

fn set_usize_once(slot: &mut Option<usize>, value: &str, option: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate option: {option}"));
    }
    *slot = Some(parse_usize(value, option)?);
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate option: {option}"));
    }
    *slot = Some(value);
    Ok(())
}

fn local_subgraph_filename(seed_id: &str) -> String {
    let safe: String = seed_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture_report() -> Report {
        let typed_graph: Value =
            serde_json::from_str(include_str!("../tests/fixtures/seed_detection.json")).unwrap();
        let mut report = Report::default();
        report.sample.name = "fixture.exe".to_string();
        report.typed_graph = Some(typed_graph);
        report
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghidra_seeded_subgraph_export_{label}_{}",
            std::process::id()
        ))
    }

    #[test]
    fn export_parser_preserves_defaults_and_accepts_all_resource_limits() {
        let defaults = parse_local_subgraph_export_args(["input.json", "out"]).unwrap();
        assert_eq!(defaults.extraction_config, LocalExtractionConfig::default());
        assert_eq!(defaults.seed_config, SeedDetectionConfig::default());
        assert!(defaults.rules_path.is_none());

        let configured = parse_local_subgraph_export_args([
            "input.json",
            "out",
            "--rules",
            "rules/custom.json",
            "--max-seeds",
            "5",
            "--caller-depth",
            "2",
            "--callee-depth",
            "3",
            "--max-function-nodes",
            "20",
            "--max-evidence-nodes",
            "40",
            "--max-total-nodes",
            "50",
            "--max-edges",
            "80",
        ])
        .unwrap();

        assert_eq!(configured.rules_path.as_deref(), Some("rules/custom.json"));
        assert_eq!(configured.seed_config.max_seeds, Some(5));
        assert_eq!(configured.extraction_config.caller_depth, 2);
        assert_eq!(configured.extraction_config.callee_depth, 3);
        assert_eq!(configured.extraction_config.max_function_nodes, Some(20));
        assert_eq!(configured.extraction_config.max_evidence_nodes, Some(40));
        assert_eq!(configured.extraction_config.max_total_nodes, Some(50));
        assert_eq!(configured.extraction_config.max_edges, Some(80));
    }

    #[test]
    fn export_parser_rejects_unknown_duplicate_and_invalid_options() {
        assert!(parse_local_subgraph_export_args(["input.json"]).is_err());
        assert!(parse_local_subgraph_export_args(["input.json", "out", "--unknown", "1"]).is_err());
        assert!(parse_local_subgraph_export_args([
            "input.json",
            "out",
            "--max-edges",
            "1",
            "--max-edges",
            "2"
        ])
        .is_err());
        assert!(parse_local_subgraph_export_args([
            "input.json",
            "out",
            "--max-function-nodes",
            "0"
        ])
        .is_err());
    }

    #[test]
    fn manifest_round_trip_preserves_gui_seed_metadata() {
        let report = fixture_report();
        let graph = TypedGraph::from_report(&report).unwrap();
        let rules = load_seed_rules(bundled_seed_rules_path()).unwrap();
        let seed_detection =
            detect_seeds_from_report(&report, &rules, &SeedDetectionConfig::default()).unwrap();
        let index = GraphIndexes::new(&graph);
        let seed = &seed_detection.seeds[0];
        let local =
            extract_local_subgraph(&index, seed, &LocalExtractionConfig::default()).unwrap();
        let document = LocalSubgraphDocument::from_local(&local).unwrap();

        let manifest = SeededSubgraphExportManifest {
            schema_version: SEEDED_SUBGRAPH_EXPORT_MANIFEST_VERSION.to_string(),
            local_subgraph_schema_version: LOCAL_SUBGRAPH_SCHEMA_VERSION.to_string(),
            source_report: "fixture.json".to_string(),
            sample_name: "fixture.exe".to_string(),
            graph_version: graph.model_version().to_string(),
            seed_rules_version: rules.schema_version.clone(),
            seed_detection: SeedDetectionResult {
                model_version: seed_detection.model_version.clone(),
                config: SeedDetectionConfig { max_seeds: Some(1) },
                seeds: vec![seed.clone()],
                total_detected: seed_detection.total_detected,
                returned: 1,
                truncated: seed_detection.total_detected > 1,
                truncation_reason: (seed_detection.total_detected > 1)
                    .then_some(crate::seed_limits::SeedTruncationReason::MaxSeeds),
            },
            extraction_config: LocalExtractionConfig::default(),
            subgraphs: vec![LocalSubgraphExportEntry {
                seed_id: seed.seed_id.clone(),
                anchor_function_id: seed.anchor_function_id.clone(),
                file: local_subgraph_filename(&seed.seed_id),
                truncated: document.truncation.truncated,
                function_nodes: document.truncation.counts.function_nodes,
                evidence_nodes: document.truncation.counts.evidence_nodes,
                total_nodes: document.truncation.counts.total_nodes,
                edges: document.truncation.counts.edges,
                unresolved_calls: document.truncation.counts.unresolved_calls,
            }],
            related_seed_groups: Vec::new(),
        };
        manifest.validate().unwrap();
        let encoded = manifest.to_json_pretty().unwrap();
        assert!(encoded.contains("trigger_ids"));
        assert!(encoded.contains("evidence"));
        assert_eq!(
            SeededSubgraphExportManifest::from_json(&encoded).unwrap(),
            manifest
        );
    }

    #[test]
    fn real_export_writes_manifest_and_one_valid_document_per_returned_seed() {
        let base = unique_temp_dir("write");
        let input = base.with_extension("input.json");
        let output = base.with_extension("output");
        let _ = fs::remove_file(&input);
        let _ = fs::remove_dir_all(&output);

        fs::write(
            &input,
            serde_json::to_string_pretty(&fixture_report()).unwrap(),
        )
        .unwrap();
        let options = LocalSubgraphExportOptions {
            input_path: input.to_string_lossy().into_owned(),
            output_dir: output.to_string_lossy().into_owned(),
            rules_path: None,
            seed_config: SeedDetectionConfig { max_seeds: Some(2) },
            extraction_config: LocalExtractionConfig::default(),
        };

        let manifest = export_local_subgraphs(&options).unwrap();
        assert_eq!(manifest.subgraphs.len(), manifest.seed_detection.returned);
        assert!(output.join(SEEDED_SUBGRAPH_MANIFEST_FILENAME).is_file());
        for entry in &manifest.subgraphs {
            let document = LocalSubgraphDocument::load(output.join(&entry.file)).unwrap();
            assert_eq!(document.seed_id, entry.seed_id);
            assert_eq!(document.anchor_function_id, entry.anchor_function_id);
        }
        let on_disk = SeededSubgraphExportManifest::from_json(
            &fs::read_to_string(output.join(SEEDED_SUBGRAPH_MANIFEST_FILENAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(on_disk, manifest);

        fs::remove_file(&input).unwrap();
        fs::remove_dir_all(&output).unwrap();
    }

    #[test]
    fn export_refuses_existing_output_directory_instead_of_mixing_stale_files() {
        let base = unique_temp_dir("existing");
        let input = base.with_extension("input.json");
        let output = base.with_extension("output");
        let _ = fs::remove_file(&input);
        let _ = fs::remove_dir_all(&output);

        fs::write(
            &input,
            serde_json::to_string_pretty(&fixture_report()).unwrap(),
        )
        .unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(
            output.join("stale.json"),
            json!({"stale": true}).to_string(),
        )
        .unwrap();

        let options = LocalSubgraphExportOptions {
            input_path: input.to_string_lossy().into_owned(),
            output_dir: output.to_string_lossy().into_owned(),
            rules_path: None,
            seed_config: SeedDetectionConfig::default(),
            extraction_config: LocalExtractionConfig::default(),
        };
        assert!(export_local_subgraphs(&options).is_err());
        assert!(output.join("stale.json").is_file());

        fs::remove_file(&input).unwrap();
        fs::remove_dir_all(&output).unwrap();
    }
}
