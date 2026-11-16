"""Registered producer-depth ablation on existing real evidence; all observed splits are exploratory."""

import argparse
import copy
import json
from pathlib import Path

try:
    from . import evaluate_operational_baseline as base
    from .evaluate_value_flow import auc
except ImportError:
    import evaluate_operational_baseline as base
    from evaluate_value_flow import auc

CONDITIONS = ("exact", "depth_0", "depth_1", "depth_2", "mean_01", "mean_012", "exact_mean_012")
POLICY = "Previously observed corpus, including historical heldout: exploratory only; fixed equal means; discovery-only calibration; no promotion or new independent-test claim"


def validate_baseline(baseline):
    base.require(baseline["status"] == "PASS", "unsuccessful baseline")
    cases = {c["id"]: c for c in baseline["cases"]}
    base.require(len(cases) == len(baseline["cases"]), "duplicate case")
    families = {}
    for case in cases.values():
        base.require(case["split"] in ("discovery", "validation", "heldout"), "unknown split")
        base.require(case["family"] not in families or families[case["family"]] == case["split"], "source-family leakage")
        families[case["family"]] = case["split"]
    seen = set()
    for pair in baseline["pairs"]["C"]:
        base.require(type(pair["positive"]) is bool, "label must be boolean")
        q, r = cases[pair["query"]], cases[pair["reference"]]
        base.require(q["split"] == r["split"] == pair["split"], "pair crosses splits")
        key = (pair["query"], pair["reference"])
        base.require(key not in seen, "duplicate pair")
        seen.add(key)


def register(args):
    base.require(not args.protocol.exists(), "protocol exists; never overwrite registration")
    baseline = json.loads(args.baseline_results.read_bytes())
    validate_baseline(baseline)
    hashes = {str(args.baseline_results.resolve()): base.sha(args.baseline_results)}
    for index, case in enumerate(baseline["cases"]):
        for path in (Path(case["fingerprint"]), args.legacy_value_dir / f"case-{index}.json"):
            hashes[str(path.resolve())] = base.sha(path)
    for index, _ in enumerate(baseline["pairs"]["C"]):
        path = args.legacy_value_dir / f"pair-{index}.json"
        hashes[str(path.resolve())] = base.sha(path)
    implementation = base.implementation()
    for path in (Path(__file__), base.ROOT / "scripts/evaluate_value_flow.py"):
        implementation[path.resolve().relative_to(base.ROOT).as_posix()] = base.sha(path)
    protocol = dict(
        schema_version="osgf.multilevel-experiment/0.1.0",
        conditions=list(CONDITIONS),
        policy=POLICY,
        baseline_results=str(args.baseline_results.resolve()),
        legacy_value_dir=str(args.legacy_value_dir.resolve()),
        engine=str(args.engine.resolve()),
        engine_sha256=base.sha(args.engine),
        inputs_sha256=hashes,
        implementation_sha256=implementation,
    )
    base.save(args.protocol, protocol)
    print(f"REGISTERED {args.protocol}: {len(baseline['cases'])} cases; {len(baseline['pairs']['C'])} pairs; exploratory only", flush=True)


def verify(protocol):
    base.require(protocol["schema_version"] == "osgf.multilevel-experiment/0.1.0", "unknown protocol")
    base.require(protocol["conditions"] == list(CONDITIONS) and protocol["policy"] == POLICY, "method policy changed")
    base.require(base.sha(Path(protocol["engine"])) == protocol["engine_sha256"], "engine changed")
    for name, expected in protocol["inputs_sha256"].items():
        base.require(base.sha(Path(name)) == expected, "input changed: " + name)
    for name, expected in protocol["implementation_sha256"].items():
        base.require(base.sha(base.ROOT / name) == expected, "implementation changed: " + name)


def summarize(cases, pairs):
    summary = {}
    for condition, rows in pairs.items():
        threshold = base.calibrate([p for p in rows if p["split"] == "discovery"])
        splits = {}
        for split in ("discovery", "validation", "heldout"):
            selected = [p for p in rows if p["split"] == split]
            stats = base.metrics(selected, threshold)
            stats.update(base.retrieval([c for c in cases if c["split"] == split], selected))
            stats["roc_auc"] = auc(selected)
            stats["negative_score_one"] = sum(not p["positive"] and p["score"] == 1 for p in selected)
            splits[split] = stats
        summary[condition] = dict(discovery_threshold=threshold, splits=splits)
    return summary


def evaluate(args):
    protocol_bytes = args.protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    verify(protocol)
    baseline = json.loads(Path(protocol["baseline_results"]).read_bytes())
    validate_baseline(baseline)
    output = args.output.resolve()
    base.require(not output.exists(), "use fresh output directory")
    output.mkdir(parents=True)
    engine, legacy = Path(protocol["engine"]), Path(protocol["legacy_value_dir"])
    receipts, support, fingerprints = [], [], {}

    def command(verb, inputs, target):
        receipts.append(base.command([engine, verb, *inputs, target], target.with_suffix(".log")))

    for index, case in enumerate(baseline["cases"]):
        first, second = output / f"case-{index}.json", output / f"case-{index}.repeat.json"
        for target in (first, second):
            command("multilevel-fingerprint", [case["fingerprint"]], target)
        base.require(first.read_bytes() == second.read_bytes(), "nondeterministic multilevel fingerprint")
        old = output / f"case-{index}.legacy.json"
        command("value-fingerprint", [case["fingerprint"]], old)
        base.require(old.read_bytes() == (legacy / f"case-{index}.json").read_bytes(), "legacy value fingerprint changed")
        view, previous = json.loads(first.read_bytes()), json.loads(old.read_bytes())
        base.require(view["levels"]["depth_2"]["features"] == previous["features"], "depth two differs from legacy")
        fingerprints[case["id"]] = first
        support.append(dict(case=case["id"], levels={k: dict(features=len(v["features"]), paths_truncated=v["paths_truncated"]) for k, v in view["levels"].items()}, contracted_copies=len(view["contracted_copies"]), copy_barriers=view["copy_barriers"]))
    pairs = {condition: [] for condition in CONDITIONS}
    for index, pair in enumerate(baseline["pairs"]["C"]):
        first, second = output / f"pair-{index}.json", output / f"pair-{index}.repeat.json"
        for target in (first, second):
            command("multilevel-compare", [fingerprints[pair["query"]], fingerprints[pair["reference"]]], target)
        base.require(first.read_bytes() == second.read_bytes(), "nondeterministic multilevel comparison")
        result = json.loads(first.read_bytes())
        previous = json.loads((legacy / f"pair-{index}.json").read_bytes())
        base.require(result["baseline"] == previous["baseline"], "baseline comparison changed")
        base.require(result["baseline"]["operational"]["set_similarity"] == pair["score"], "exact score changed")
        for field in ("set_similarity", "multiset_similarity"):
            base.require(result["levels"]["depth_2"][field] == previous["normalized"][field], "legacy normalized score changed")
        values = {"exact": pair["score"], **{k: v["set_similarity"] for k, v in result["levels"].items()}, **{k: v["set_similarity"] for k, v in result["aggregates"].items()}}
        for condition in CONDITIONS:
            row = copy.deepcopy(pair)
            row["score"] = values[condition]
            pairs[condition].append(row)
        if (index + 1) % 27 == 0:
            print(f"PASS {index + 1} pairs: repeated bytes identical; legacy scores unchanged", flush=True)
    summary = summarize(baseline["cases"], pairs)
    verify(protocol)
    base.require(args.protocol.read_bytes() == protocol_bytes, "protocol changed during run")
    report = dict(status="PASS", policy=POLICY, protocol_sha256=base.sha(args.protocol), summary=summary, pairs=pairs, support=support, receipts=receipts, no_target_execution=True, fingerprint_reruns_identical=True, comparison_reruns_identical=True, legacy_unchanged=True)
    base.save(output / "results.json", report)
    for condition in CONDITIONS:
        stats = summary[condition]["splits"]["heldout"]
        print(f"{condition}: historical heldout (EXPLORATORY) BA={stats['balanced_accuracy']:.6f} AUC={stats['roc_auc']:.6f} MRR={stats['mrr']:.6f} FP={stats['fp']} FN={stats['fn']}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    registration = sub.add_parser("register")
    registration.add_argument("--protocol", type=Path, required=True)
    registration.add_argument("--baseline-results", type=Path, required=True)
    registration.add_argument("--legacy-value-dir", type=Path, required=True)
    registration.add_argument("--engine", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--protocol", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "register":
        register(args)
    else:
        evaluate(args)
