"""Descriptive layer redundancy and threshold-transfer audit; never tunes the tested pipeline."""

import argparse
import itertools
import json
import math
from pathlib import Path

try:
    from .evaluate_operational_baseline import calibrate, metrics, require
    from .evaluate_value_flow import auc
    from .recovered_evidence import digest, encoded
except ImportError:
    from evaluate_operational_baseline import calibrate, metrics, require
    from evaluate_value_flow import auc
    from recovered_evidence import digest, encoded


def ranks(values):
    result = [0.0] * len(values)
    order = sorted(range(len(values)), key=values.__getitem__)
    i = 0
    while i < len(order):
        j = i + 1
        while j < len(order) and values[order[j]] == values[order[i]]:
            j += 1
        for k in range(i, j):
            result[order[k]] = (i + j - 1) / 2
        i = j
    return result


def correlation(a, b):
    if not a:
        return None
    am, bm = sum(a) / len(a), sum(b) / len(b)
    da, db = [v - am for v in a], [v - bm for v in b]
    denom = math.sqrt(sum(v * v for v in da) * sum(v * v for v in db))
    return sum(x * y for x, y in zip(da, db)) / denom if denom else None


def quantiles(values):
    values = sorted(values)
    return {str(p): values[round(p * (len(values) - 1))] if values else None for p in (0, 0.25, 0.5, 0.75, 1)}


def audit(result):
    pairs = result["pairs"]
    required = ["depth_0", "depth_1", "depth_2"]
    require(all(k in pairs for k in required), "missing layer")
    aligned = {}
    for name, rows in pairs.items():
        indexed = {(r["query"], r["reference"]): r for r in rows}
        require(len(indexed) == len(rows), "duplicate pair")
        aligned[name] = indexed
    keys = sorted(aligned["depth_0"])
    for rows in aligned.values():
        require(set(rows) == set(keys), "unaligned pairs")
        require(all((rows[k]["positive"], rows[k]["split"]) == (aligned["depth_0"][k]["positive"], aligned["depth_0"][k]["split"]) for k in keys), "changed labels/splits")
    # Leave-one-out means are diagnostic ablations, not selected replacements.
    conditions = dict(pairs)
    for omitted in required:
        others = [n for n in required if n != omitted]
        conditions["without_" + omitted] = [dict(aligned[others[0]][k], score=None if any(aligned[n][k]["score"] is None for n in others) else sum(aligned[n][k]["score"] for n in others) / 2) for k in keys]
    thresholds = {n: calibrate([r for r in rows if r["split"] == "discovery"]) for n, rows in conditions.items()}
    transfer = {}
    for name, rows in conditions.items():
        transfer[name] = dict(discovery_threshold=thresholds[name], splits={})
        for split in ("discovery", "validation", "heldout"):
            selected = [r for r in rows if r["split"] == split]
            stats = metrics(selected, thresholds[name])
            stats.update(roc_auc=auc(selected), positive_quantiles=quantiles([r["score"] for r in selected if r["positive"] and r["score"] is not None]), negative_quantiles=quantiles([r["score"] for r in selected if not r["positive"] and r["score"] is not None]))
            stats["threshold_above_all_scores"] = bool(selected) and all(r["score"] is None or r["score"] < thresholds[name] for r in selected)
            transfer[name]["splits"][split] = stats
    contribution = []
    for a, b in itertools.combinations(required, 2):
        for split in ("discovery", "validation", "heldout"):
            selected = [k for k in keys if aligned[a][k]["split"] == split and aligned[a][k]["score"] is not None and aligned[b][k]["score"] is not None]
            x, y = [[aligned[n][k]["score"] for k in selected] for n in (a, b)]
            row = dict(left=a, right=b, split=split, comparable=len(selected), pearson=correlation(x, y), spearman=correlation(ranks(x), ranks(y)), equal_scores=sum(xv == yv for xv, yv in zip(x, y)))
            for positive, label in [(True, "positive"), (False, "negative")]:
                group = [k for k in selected if aligned[a][k]["positive"] == positive]
                error = lambda n, k: (aligned[n][k]["score"] >= thresholds[n]) != positive  # noqa: E731
                row[label] = dict(n=len(group), both_wrong=sum(error(a, k) and error(b, k) for k in group), left_only_wrong=sum(error(a, k) and not error(b, k) for k in group), right_only_wrong=sum(not error(a, k) and error(b, k) for k in group))
            contribution.append(row)
    return dict(schema_version="osgf.layer-transfer-audit/0.1.0", input_digest=digest(result), contribution=contribution, threshold_transfer=transfer, policy="Descriptive observed-corpus audit; equal-rank handling for ties; no heldout threshold optimization, model selection or population-significance claim")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(json.loads(args.results.read_bytes()))
    with args.output.open("xb") as stream:
        stream.write(encoded(result))
    print("PASS: layer correlation/complementarity and discovery-threshold transfer audit", args.output)
