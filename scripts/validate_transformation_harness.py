"""Strict per-run acceptance, independent behavior replay and deterministic provenance checks."""

import argparse
import json
from pathlib import Path
import subprocess

try:
    from .step9_preflight import ROOT, frozen_baseline, safe_path
    from .transformation_build import behavior_record, persist, verify_builds
    from .transformation_extraction import register_bytes
    from .transformation_harness import load_run, plan
    from .transformation_mapping import default_engine, validate_mappings
    from .transformation_schema import FAMILIES, VERSION, schema_documents, serialize
    from .transformation_splits import DEFAULT_POLICY, validate_split_report, validate_splits
except ImportError:
    from step9_preflight import ROOT, frozen_baseline, safe_path
    from transformation_build import behavior_record, persist, verify_builds
    from transformation_extraction import register_bytes
    from transformation_harness import load_run, plan
    from transformation_mapping import default_engine, validate_mappings
    from transformation_schema import FAMILIES, VERSION, schema_documents, serialize
    from transformation_splits import DEFAULT_POLICY, validate_split_report, validate_splits


def check_behavior(record, specification, generated, rows=None):
    if rows is None:
        rows = [f"{side} {case['case_id']} {case[field]}" for case in record["tested_cases"] for side, field in (("original", "original_result"), ("transformed", "transformed_result"))]
    expected = behavior_record(rows, specification, generated, record["build_id"])
    if expected["validation_status"] != "passed" or record != expected:
        raise ValueError("Independent oracle/input contract or replay mismatch")
    return len(expected["tested_cases"])


def coverage(bundle):
    executions = {e["execution_id"]: e for e in bundle["executions"]}
    specifications = {s["transformation_id"]: s for s in bundle["specifications"]}
    result = {}
    for family in FAMILIES:
        selected = {key for key, execution in executions.items() if specifications[execution["transformation_id"]]["transformation_family"] == family}
        builds = [b for b in bundle["builds"] if b["execution_id"] in selected]
        build_ids = {b["build_id"] for b in builds}
        behaviors = [b for b in bundle["behaviors"] if b["build_id"] in build_ids]
        graphs = [g for g in bundle["graphs"] if g["execution_id"] in selected]
        result[family] = dict(
            generated_variants=sum(executions[e]["generation_status"] == "generated" for e in selected),
            successful_builds=sum(b["build_status"] == "success" for b in builds),
            failed_builds=sum(b["build_status"] != "success" for b in builds),
            behavior_passes=sum(b["validation_status"] == "passed" for b in behaviors),
            oracle_checks=sum(len(b["tested_cases"]) for b in behaviors),
            behavior_mismatches=sum(len(b["mismatch_witnesses"]) for b in behaviors),
            extracted_graphs=sum(g["extraction_status"] == "success" for g in graphs),
            extraction_failures=sum(g["extraction_status"] != "success" for g in graphs),
            observed_effects={state: sum(g["observability_metadata"]["status"] == state for g in graphs) for state in ("observed", "partially_observed", "optimized_away", "not_observable", "unknown")},
            unsupported_variants=sum(executions[e]["generation_status"] == "unsupported" for e in selected),
        )
    return result


def validate_run(run_dir, engine=None, policy=DEFAULT_POLICY, root=ROOT):
    root, run_dir = Path(root).resolve(), Path(run_dir).resolve()
    baseline = json.loads((root / "datasets/osgf_transformations_v0_1/baseline.json").read_bytes())
    if frozen_baseline(root) != baseline:
        raise ValueError("Frozen Step 8 / scientific fixture baseline changed")
    for name, schema in schema_documents().items():
        if (root / "datasets/osgf_transformations_v0_1/schema" / name).read_bytes() != serialize(schema):
            raise ValueError("Versioned schema differs from runtime contract")
    bundle = load_run(run_dir, root)
    run = bundle["runs"][0]
    if any(run["statuses"][phase] != "passed" for phase in ("generation", "build", "extraction", "mapping")):
        raise ValueError("Incomplete or failed phases cannot become acceptance PASS")
    planned, sources = plan(run["experiment_configuration"], root)
    if planned["run_id"] != run["run_id"] or any(safe_path(root, name).read_bytes() != raw for name, raw in sources.items()):
        raise ValueError("Generation rerun is not byte-deterministic")
    verify_builds(bundle, root)
    specs = {s["transformation_id"]: s for s in bundle["specifications"]}
    executions = {e["execution_id"]: e for e in bundle["executions"]}
    generated = json.loads((run_dir / "generation.json").read_bytes())
    tests = 0
    for build in bundle["builds"]:
        if build["build_status"] != "success":
            raise ValueError("Non-admitted build")
        behaviors = [b for b in bundle["behaviors"] if b["build_id"] == build["build_id"]]
        if len(behaviors) != 1:
            raise ValueError("Missing or ambiguous independent behavior record")
        specification = specs[executions[build["execution_id"]]["transformation_id"]]
        check_behavior(behaviors[0], specification, generated[build["execution_id"]])
        completed = subprocess.run([str(safe_path(root, build["binary_artifact_reference"]))], check=True, timeout=min(run["experiment_configuration"]["execution_limits"]["timeout_seconds"], 180), capture_output=True, text=True)
        tests += check_behavior(behaviors[0], specification, generated[build["execution_id"]], completed.stdout.splitlines())
    statistics = validate_mappings(bundle, run_dir, root, engine or default_engine(root))
    splits_path = run_dir / "splits.json"
    if not splits_path.exists():
        validate_splits(run_dir, policy, root)
        bundle = load_run(run_dir, root)
        run = bundle["runs"][0]
    split_report = validate_split_report(bundle, run_dir, json.loads(splits_path.read_bytes()), root)
    if split_report["policy"] != policy:
        raise ValueError("Existing run split policy differs from requested policy")
    result = dict(
        schema_version=VERSION,
        run_id=run["run_id"],
        frozen_dataset_reference=bundle["frozen_dataset_reference"],
        acceptance_status="passed",
        scope="Per-run technical acceptance; repository regression results are recorded separately in ACCEPTANCE.md.",
        frozen_inventory_files=len(baseline["scientific_files"]),
        oracle_replay_cases=tests,
        coverage=coverage(bundle),
        mapping_statistics=statistics,
        split_validation="passed",
        family_holdouts=split_report["family_holdouts"],
        deterministic_checks=dict(source_bytes=True, scientific_run_id=True, canonical_reconstruction_bytes=True, mapping_reconstruction=True, oracle_outputs=True),
        limitations=["Finite pure-byte input contract only.", "No similarity-derived labels, LLM calls, rewrite equivalence or Step 10 evaluation.", "Instruction ordering/dead branch presence is not observable in this graph vocabulary.", "Fresh compiler/Ghidra replay is separate from artifact reconstruction."],
    )
    # The manifest is not hashed into its own derived report. Reports have no timestamps or personal paths.
    register_bytes(root, run, run_dir / "validation.json", serialize(result))
    run["statuses"]["validation"] = "passed"
    persist(run_dir, bundle, root)
    print("RUN ACCEPTANCE PASS:", run["run_id"], tests, "independent replay cases;", len(bundle["graphs"]), "verified graphs;", statistics["verified_mappings"], "verified provenance mappings", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--engine", type=Path)
    parser.add_argument("--split-policy", type=Path)
    args = parser.parse_args()
    validate_run(args.run, args.engine, json.loads(args.split_policy.read_bytes()) if args.split_policy else DEFAULT_POLICY)


if __name__ == "__main__":
    main()
