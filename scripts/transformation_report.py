"""Reports derived only from admitted run evidence; no invented benchmark or equivalence score."""

import json
from pathlib import Path

try:
    from .step9_preflight import ROOT, exact_hash
    from .transformation_extraction import register_bytes, transformation_observations, OBSERVATION_CONTRACT
    from .transformation_harness import load_run
    from .transformation_mapping import mapping_statistics
    from .transformation_schema import VERSION, serialize
    from .validate_transformation_harness import coverage, validate_run
except ImportError:
    from step9_preflight import ROOT, exact_hash
    from transformation_extraction import register_bytes, transformation_observations, OBSERVATION_CONTRACT
    from transformation_harness import load_run
    from transformation_mapping import mapping_statistics
    from transformation_schema import VERSION, serialize
    from validate_transformation_harness import coverage, validate_run


def compose_report(bundle, validation=None, fresh_replay=None, root=ROOT):
    run = bundle["runs"][0]
    admitted = all(run["statuses"][phase] == "passed" for phase in ("generation", "build", "extraction", "mapping", "validation"))
    accepted = admitted and validation is not None and validation.get("acceptance_status") == "passed" and validation.get("run_id") == run["run_id"] and validation.get("observation_contract") == OBSERVATION_CONTRACT
    unavailable = any(b["build_status"] in ("unavailable", "unsupported") for b in bundle["builds"]) or any(g["extraction_status"] == "unavailable" for g in bundle["graphs"])
    replay = dict(status="not_run", checks={})
    if fresh_replay is not None:
        required = {"specifications", "executions", "builds", "behaviors", "graphs", "mappings", "scientific_run_id", "artifact_hashes", "generation.json", "splits.json", "validation-v2.json"}
        if fresh_replay.get("run_id") != run["run_id"] or fresh_replay.get("status") != "passed" or set(fresh_replay.get("checks", {})) != required or any(value is not True for value in fresh_replay["checks"].values()):
            raise ValueError("Unverified fresh replay evidence")
        replay = dict(status="passed", checks=fresh_replay["checks"])
    return dict(
        schema_version=VERSION,
        run_id=run["run_id"],
        frozen_dataset_reference=bundle["frozen_dataset_reference"],
        experiment_configuration=run["experiment_configuration"],
        acceptance_status="passed" if accepted else "blocked" if unavailable else "not_accepted",
        phase_statuses=run["statuses"],
        scope="Per-run technical evidence; repository regression acceptance is documented separately in ACCEPTANCE.md.",
        observation_contract=OBSERVATION_CONTRACT,
        families=coverage(bundle, root),
        transformation_observations=transformation_observations(bundle, root),
        canonical_graph_count=sum(g["extraction_status"] == "success" for g in bundle["graphs"]),
        mapping_statistics=mapping_statistics(bundle["mappings"]),
        split_validation=validation["split_validation"] if accepted else "not_verified",
        family_holdouts=validation["family_holdouts"] if accepted else [],
        deterministic_checks=validation["deterministic_checks"] if accepted else {},
        fresh_end_to_end_replay=replay,
        failures=[dict(build_id=b["build_id"], status=b["build_status"], diagnostics=b["build_diagnostics"]) for b in bundle["builds"] if b["build_status"] != "success"]
        + [dict(graph_id=g["graph_id"], status=g["extraction_status"], diagnostics=g["diagnostics"]) for g in bundle["graphs"] if g["extraction_status"] != "success"],
        graph_records=[dict(graph_id=g["graph_id"], historical_or_current_annotation=g["observability_metadata"], extraction_status=g["extraction_status"], truncation=g["truncation_metadata"]) for g in sorted(bundle["graphs"], key=lambda g: g["graph_id"])],
        limitations=[
            "Source transformations only, not binary rewriting.",
            "Finite independent pure-byte oracle coverage is not equivalence for all inputs.",
            "Controlled symbol/provenance relations do not prove graph isomorphism or functional equivalence.",
            "Unknown and unmatched remain distinct; no similarity-derived labels or LLM inference.",
            "Compiler/OS/Ghidra differences may change binary and observed graph artifacts.",
            "Instruction order and branch guards are outside the typed-graph vocabulary.",
            "Family holdout coverage depends on compatible frozen source partitions.",
            "No Step 10 evaluation has been implemented.",
        ],
    )


def markdown(report):
    lines = [
        "# Transformation Harness run report",
        "",
        "Run: `" + report["run_id"] + "`",
        "",
        "Technical acceptance: **" + report["acceptance_status"].upper() + "**",
        "",
        report["scope"],
        "",
        "Frozen dataset: `" + report["frozen_dataset_reference"]["scientific_digest"] + "`",
        "",
        "| Family | Variants | Builds passed/failed | Oracle cases | Graphs passed/failed | Transformation/build observations |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for family, row in sorted(report["families"].items()):
        observations = ", ".join(f"{state}: {count}" for state, count in row["observed_effects"].items() if count) or "not run"
        lines.append(f"| {family} | {row['generated_variants']} | {row['successful_builds']}/{row['failed_builds']} | {row['oracle_checks']} | {row['extracted_graphs']}/{row['extraction_failures']} | {observations} |")
    lines += [
        "",
        "Independent transformation/build observations: " + str(len(report["transformation_observations"])),
        "Canonical graphs extracted: " + str(report["canonical_graph_count"]),
        "",
        "Provenance mapping statistics (not equivalence scores):",
        "",
        *[f"- {key}: {value}" for key, value in sorted(report["mapping_statistics"].items())],
        "",
        "Split validation: " + report["split_validation"],
        "",
        "Family holdouts:",
        "",
        *[f"- {v['family']}: {v['status']}; missing partitions: {', '.join(v['missing_partitions']) or 'none'}" for v in report["family_holdouts"]],
        "",
        "Fresh end-to-end replay: " + report["fresh_end_to_end_replay"]["status"],
        "",
        "Recorded failures: " + str(len(report["failures"])),
        "",
        "Limitations:",
        "",
        *["- " + limitation for limitation in report["limitations"]],
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def report_run(run_dir, engine=None, root=ROOT):
    root, run_dir = Path(root).resolve(), Path(run_dir).resolve()
    bundle = load_run(run_dir, root)
    validation = None
    if all(bundle["runs"][0]["statuses"][phase] == "passed" for phase in ("generation", "build", "extraction", "mapping")):
        policy = json.loads((run_dir / "splits.json").read_bytes())["policy"] if (run_dir / "splits.json").exists() else None
        options = {"policy": policy} if policy is not None else {}
        validation = validate_run(run_dir, engine, root=root, publish=False, **options)
        bundle = load_run(run_dir, root)
    replay_path = run_dir / "fresh_replay-v2.json"
    replay = json.loads(replay_path.read_bytes()) if replay_path.exists() else None
    if replay is not None and replay_path.relative_to(root).as_posix() not in bundle["runs"][0]["artifact_hashes"]:
        raise ValueError("Replay evidence absent from verified hash inventory")
    report = compose_report(bundle, validation, replay, root)
    report["input_manifest_sha256"] = exact_hash(run_dir / "manifest.json")
    # Versioned derived reports are bound to the input manifest without mutating historical evidence.
    for name, raw in (("report-v2.json", serialize(report)), ("report-v2.md", markdown(report)), ("validation-review-v2.json", serialize(validation))):
        register_bytes(root, {"artifact_hashes": {}}, run_dir / name, raw)
    print(markdown(report).decode(), flush=True)
    return report
