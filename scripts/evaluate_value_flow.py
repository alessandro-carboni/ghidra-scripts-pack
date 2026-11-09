"""Pinned exact/normalized/mean ablation; no target execution or score-based tuning."""

import argparse
import copy
import json
from pathlib import Path

try:
    from . import evaluate_operational_baseline as base
except ImportError:
    import evaluate_operational_baseline as base


def auc(pairs):
    positive = [p["score"] for p in pairs if p["positive"] and p["score"] is not None]
    negative = [p["score"] for p in pairs if not p["positive"] and p["score"] is not None]
    if not positive or not negative:
        return None
    return sum((a > b) + 0.5 * (a == b) for a in positive for b in negative) / (len(positive) * len(negative))


def verify(protocol, baseline_results, engine):
    base.require(protocol["engine_sha256"] == base.sha(engine), "value engine changed")
    base.require(protocol["baseline_results_sha256"] == base.sha(baseline_results), "baseline results changed")
    for relative, expected in protocol["implementation_sha256"].items():
        base.require(base.sha(base.ROOT / relative) == expected, "implementation changed: " + relative)
    for path, expected in protocol["fingerprint_sha256"].items():
        base.require(base.sha(Path(path)) == expected, "baseline fingerprint changed: " + path)


def evaluate(args):
    protocol = json.loads(args.protocol.read_bytes())
    verify(protocol, args.baseline_results, args.engine)
    baseline = json.loads(args.baseline_results.read_bytes())
    base.require(baseline["status"] == "PASS", "unsuccessful baseline")
    output = args.output.resolve()
    base.require(not output.exists(), "use a fresh output directory")
    output.mkdir(parents=True)
    cases = baseline["cases"]
    base.require(len({c["id"] for c in cases}) == len(cases), "duplicate cases")
    components = {}
    fingerprints, receipts, support = {}, [], []
    for index, case in enumerate(cases):
        family, split = case["family"], case["split"]
        base.require(family not in components or components[family] == split, "source-family leakage")
        components[family] = split
        first, second = output / f"case-{index}.json", output / f"case-{index}.repeat.json"
        for target in [first, second]:
            receipts.append(base.command([args.engine, "value-fingerprint", case["fingerprint"], target], target.with_suffix(".log")))
        base.require(first.read_bytes() == second.read_bytes(), "nondeterministic value fingerprint")
        fp = json.loads(first.read_bytes())
        fingerprints[case["id"]] = first
        support.append(dict(case=case["id"], features=len(fp["features"]), contracted_copies=len(fp["contracted_copies"]), copy_barriers=fp["copy_barriers"], paths_truncated=fp["paths_truncated"]))
    pairs = {condition: [] for condition in ("exact", "normalized", "mean")}
    for index, pair in enumerate(baseline["pairs"]["C"]):
        first, second = output / f"pair-{index}.json", output / f"pair-{index}.repeat.json"
        for target in [first, second]:
            receipts.append(base.command([args.engine, "value-compare", fingerprints[pair["query"]], fingerprints[pair["reference"]], target], target.with_suffix(".log")))
        base.require(first.read_bytes() == second.read_bytes(), "nondeterministic value comparison")
        result = json.loads(first.read_bytes())
        base.require(result["baseline"]["operational"]["set_similarity"] == pair["score"], "old operational score changed")
        values = [pair["score"], result["normalized"]["set_similarity"], result["exact_normalized_mean"]["set_similarity"]]
        for condition, score in zip(pairs, values):
            row = copy.deepcopy(pair)
            row["score"] = score
            pairs[condition].append(row)
        if (index + 1) % 27 == 0:
            print(f"PASS {index + 1} pairs: old scores unchanged; normalized reruns byte-identical", flush=True)
    summary = {}
    for condition, rows in pairs.items():
        threshold = base.calibrate([p for p in rows if p["split"] == "discovery"])
        summary[condition] = dict(discovery_threshold=threshold, splits={})
        for split in ("discovery", "validation", "heldout"):
            selected = [p for p in rows if p["split"] == split]
            stats = base.metrics(selected, threshold)
            stats.update(base.retrieval([c for c in cases if c["split"] == split], selected))
            stats["roc_auc"] = auc(selected)
            positives = [p["score"] for p in selected if p["positive"] and p["score"] is not None]
            stats["positive_mean"] = sum(positives) / len(positives) if positives else None
            stats["negative_score_one"] = sum(not p["positive"] and p["score"] == 1 for p in selected)
            for flag in ("cross_compiler", "cross_optimization"):
                scores = [p["score"] for p in selected if p["positive"] and p[flag] and p["score"] is not None]
                stats[flag + "_positive_mean"] = sum(scores) / len(scores) if scores else None
            summary[condition]["splits"][split] = stats
    verify(protocol, args.baseline_results, args.engine)
    report = dict(
        status="PASS",
        protocol_sha256=base.sha(args.protocol),
        summary=summary,
        pairs=pairs,
        support=support,
        receipts=receipts,
        no_target_execution=True,
        label_policy="Inherited source-derived ground truth; unchanged",
        caveat="Bounded descriptor similarity is not equivalence; family-correlated pilot, no population significance claim",
    )
    base.save(output / "results.json", report)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--baseline-results", required=True, type=Path)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    evaluate(parser.parse_args())
