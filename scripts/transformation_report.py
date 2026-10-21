"""Reports derived only from admitted run evidence; no invented benchmark or equivalence score."""

import json
from pathlib import Path

try:
    from .step9_preflight import ROOT
    from .transformation_build import persist
    from .transformation_extraction import register_bytes
    from .transformation_harness import load_run
    from .transformation_mapping import mapping_statistics
    from .transformation_schema import VERSION, serialize
    from .validate_transformation_harness import coverage, validate_run
except ImportError:
    from step9_preflight import ROOT
    from transformation_build import persist
    from transformation_extraction import register_bytes
    from transformation_harness import load_run
    from transformation_mapping import mapping_statistics
    from transformation_schema import VERSION, serialize
    from validate_transformation_harness import coverage, validate_run


def compose_report(bundle, validation=None, fresh_replay=None):
    run = bundle["runs"][0]
    admitted = all(run["statuses"][phase] == "passed" for phase in ("generation", "build", "extraction", "mapping", "validation"))
    accepted = admitted and validation is not None and validation.get("acceptance_status") == "passed" and validation.get("run_id") == run["run_id"]
    unavailable = any(b["build_status"] in ("unavailable", "unsupported") for b in bundle["builds"]) or any(g["extraction_status"] == "unavailable" for g in bundle["graphs"])
    replay = dict(status="not_run", checks={})
    if fresh_replay is not None:
        required = {"specifications", "executions", "builds", "behaviors", "graphs", "mappings", "scientific_run_id", "artifact_hashes", "generation.json", "splits.json", "validation.json"}
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
        families=coverage(bundle),
        mapping_statistics=mapping_statistics(bundle["mappings"]),
        split_validation=validation["split_validation"] if accepted else "not_verified",
        family_holdouts=validation["family_holdouts"] if accepted else [],
        deterministic_checks=validation["deterministic_checks"] if accepted else {},
        fresh_end_to_end_replay=replay,
        failures=[dict(build_id=b["build_id"], status=b["build_status"], diagnostics=b["build_diagnostics"]) for b in bundle["builds"] if b["build_status"] != "success"]
        + [dict(graph_id=g["graph_id"], status=g["extraction_status"], diagnostics=g["diagnostics"]) for g in bundle["graphs"] if g["extraction_status"] != "success"],
        observations=[dict(graph_id=g["graph_id"], observation=g["observability_metadata"], truncation=g["truncation_metadata"]) for g in bundle["graphs"]],
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
        "| Family | Variants | Builds passed/failed | Oracle cases | Graphs passed/failed | Observation counts |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for family, row in sorted(report["families"].items()):
        observations = ", ".join(f"{state}: {count}" for state, count in row["observed_effects"].items() if count) or "not run"
        lines.append(f"| {family} | {row['generated_variants']} | {row['successful_builds']}/{row['failed_builds']} | {row['oracle_checks']} | {row['extracted_graphs']}/{row['extraction_failures']} | {observations} |")
    lines += [
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
        validation = validate_run(run_dir, engine, root=root, **options)
        bundle = load_run(run_dir, root)
    replay_path = run_dir / "fresh_replay.json"
    replay = json.loads(replay_path.read_bytes()) if replay_path.exists() else None
    if replay is not None and replay_path.relative_to(root).as_posix() not in bundle["runs"][0]["artifact_hashes"]:
        raise ValueError("Replay evidence absent from verified hash inventory")
    report = compose_report(bundle, validation, replay)
    run = bundle["runs"][0]
    for name, raw in (("report.json", serialize(report)), ("report.md", markdown(report))):
        reference, _ = register_bytes(root, run, run_dir / name, raw)
        run["report_references"] = sorted(set(run["report_references"]) | {reference})
    persist(run_dir, bundle, root)
    print(markdown(report).decode(), flush=True)
    return report
