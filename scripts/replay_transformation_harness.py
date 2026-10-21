"""Fresh isolated compiler/Ghidra replay, retaining both runs and comparing scientific evidence."""

import argparse
import json
from pathlib import Path
import shutil
import tempfile

try:
    from .step9_preflight import ROOT, frozen_baseline, safe_path
    from .transformation_build import build_run, persist
    from .transformation_extraction import extract_run, register_bytes
    from .transformation_harness import generate_run, load_run
    from .transformation_mapping import map_run
    from .transformation_schema import serialize
    from .validate_transformation_harness import validate_run
except ImportError:
    from step9_preflight import ROOT, frozen_baseline, safe_path
    from transformation_build import build_run, persist
    from transformation_extraction import extract_run, register_bytes
    from transformation_harness import generate_run, load_run
    from transformation_mapping import map_run
    from transformation_schema import serialize
    from validate_transformation_harness import validate_run


def compare_runs(original, replay, original_dir, replay_dir):
    checks = {}
    for collection in ("specifications", "executions", "builds", "behaviors", "graphs", "mappings"):
        checks[collection] = original[collection] == replay[collection]
    checks["scientific_run_id"] = original["runs"][0]["run_id"] == replay["runs"][0]["run_id"]

    def scientific_hashes(run):
        return {path: digest for path, digest in run["artifact_hashes"].items() if Path(path).name not in ("fresh_replay.json", "report.json", "report.md", "fresh_replay-v2.json", "report-v2.json", "report-v2.md", "validation-review-v2.json")}

    checks["artifact_hashes"] = scientific_hashes(original["runs"][0]) == scientific_hashes(replay["runs"][0])
    for name in ("generation.json", "splits.json", "validation-v2.json"):
        checks[name] = (Path(original_dir) / name).read_bytes() == (Path(replay_dir) / name).read_bytes()
    if not all(checks.values()):
        raise ValueError("Fresh same-environment replay differs: " + str([k for k, v in checks.items() if not v]))
    return checks


def replay_run(run_dir, ghidra_dir, engine, source_root=ROOT, revalidate=False):
    source_root = Path(source_root).resolve()
    run_dir, engine, ghidra_dir = Path(run_dir).resolve(), Path(engine).resolve(), Path(ghidra_dir).resolve()
    original = load_run(run_dir, source_root)
    if original["runs"][0]["statuses"]["validation"] != "passed":
        raise ValueError("Fresh replay requires admitted per-run validation")
    if not revalidate and not (run_dir / "validation-v2.json").exists():
        raise ValueError("Historical run requires --revalidate: preserve old evidence and create isolated v2 runs")
    baseline = frozen_baseline(source_root)
    parent = ROOT / ".build-cache/step9-replays"
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="fresh-", dir=parent))
    for relative in baseline["scientific_files"]:
        destination = safe_path(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(source_root, relative), destination)
    for directory in ("ghidra_scripts", "datasets/osgf_transformations_v0_1/schema", "datasets/osgf_transformations_v0_1/config"):
        shutil.copytree(source_root / directory, root / directory, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copyfile(source_root / "datasets/osgf_transformations_v0_1/baseline.json", root / "datasets/osgf_transformations_v0_1/baseline.json")
    path, _ = generate_run(original["runs"][0]["experiment_configuration"], root)
    build_run(path, root)
    extract_run(path, ghidra_dir, engine, root)
    map_run(path, root, engine)
    policy = json.loads((run_dir / "splits.json").read_bytes())["policy"]
    validate_run(path, engine, policy, root)
    if revalidate:
        # Historical evidence remains untouched; compare two freshly admitted v2 runs.
        try:
            from .transformation_report import report_run
        except ImportError:
            from transformation_report import report_run
        print("REVALIDATED V2 WORKSPACE:", root, flush=True)
        result = replay_run(path, ghidra_dir, engine, source_root=root)
        report_run(path, engine, root)
        return result
    replay = load_run(path, root)
    checks = compare_runs(original, replay, run_dir, path)
    if frozen_baseline(source_root) != baseline:
        raise ValueError("Original baseline changed during replay")
    result = dict(run_id=original["runs"][0]["run_id"], status="passed", checks=checks, scope="Fresh source generation, compiler, executable oracle, Ghidra analysis, canonicalization and mappings in the same toolchain/environment.")
    # Ephemeral workspace locations stay in the console, outside scientific evidence.
    print("FRESH REPLAY WORKSPACE:", root.relative_to(ROOT).as_posix(), flush=True)
    register_bytes(source_root, original["runs"][0], run_dir / "fresh_replay-v2.json", serialize(result))
    persist(run_dir, original, source_root)
    print("FRESH END-TO-END REPLAY PASS:", checks, flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--ghidra-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--revalidate", action="store_true", help="Preserve the historical run and validate/replay in two new isolated v2 workspaces")
    args = parser.parse_args()
    replay_run(args.run, args.ghidra_dir, args.engine, revalidate=args.revalidate)
