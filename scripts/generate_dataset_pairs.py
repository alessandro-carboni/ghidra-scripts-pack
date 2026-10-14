"""Deterministic pair construction using controlled source ground truth only."""

import argparse
from collections import Counter
from itertools import combinations
import json
from pathlib import Path

try:
    from .dataset_manifest import stable_id, validate
except ImportError:
    from dataset_manifest import stable_id, validate


def make_pair(manifest, left, right, label, category, family, truth):
    left, right = sorted((left, right), key=lambda graph: graph["graph_id"])
    samples = {s["sample_id"]: s for s in manifest["samples"]}
    lsample, rsample = (samples[g["sample_id"]] for g in (left, right))
    groups = sorted({left["source_group_id"], right["source_group_id"]})
    return dict(
        pair_id=stable_id("pair", left["graph_id"], right["graph_id"]),
        source_group_id=groups[0] if len(groups) == 1 else stable_id("source-groups", groups),
        source_group_ids=groups,
        left_sample_id=left["sample_id"],
        right_sample_id=right["sample_id"],
        left_graph_id=left["graph_id"],
        right_graph_id=right["graph_id"],
        equivalence_label=label,
        pair_category=category,
        transformation_family=family,
        transformation_parameters={},
        left_build_id=lsample["build_id"],
        right_build_id=rsample["build_id"],
        architecture=lsample["architecture"],
        validation_status="automatically_grounded",
        ground_truth=truth,
        split="discovery_train",
        notes="Provisional split; strict source/artifact assignment is applied by step 8.5.",
    )


def same_source_pairs(manifest):
    builds = {b["build_id"]: b for b in manifest["builds"]}
    samples = {s["sample_id"]: s for s in manifest["samples"]}
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    pairs = []
    for left, right in combinations(sorted(manifest["graphs"], key=lambda g: g["graph_id"]), 2):
        if left["routine_id"] != right["routine_id"] or left["variant"] != "original" or right["variant"] != "original":
            continue
        lb, rb = (builds[samples[g["sample_id"]]["build_id"]] for g in (left, right))
        if lb["source_hash"] != rb["source_hash"] or lb["architecture"] != rb["architecture"]:
            continue

        def configuration(b):
            return b["compiler"], b["compiler_version"], b["optimization"]

        if configuration(lb) == configuration(rb):
            continue
        truth = dict(method="same_controlled_source", label="equivalent", source_hash=lb["source_hash"], routine_body_sha256=routines[left["routine_id"]]["body_sha256"], evidence="Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.")
        pairs.append(make_pair(manifest, left, right, "equivalent", "same_source", "compiler_variation", truth))
    return pairs


def statistics(manifest):
    return dict(
        source_routines=len(manifest["routines"]),
        builds=len(manifest["builds"]),
        compiler_coverage=dict(sorted(Counter(b["compiler"] for b in manifest["builds"]).items())),
        optimization_coverage=dict(sorted(Counter(b["optimization"] for b in manifest["builds"]).items())),
        labels=dict(sorted(Counter(p["equivalence_label"] for p in manifest["pairs"]).items())),
        pair_categories=dict(sorted(Counter(p["pair_category"] for p in manifest["pairs"]).items())),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    manifest["pairs"] = sorted([p for p in manifest["pairs"] if p["pair_category"] != "same_source"] + same_source_pairs(manifest), key=lambda p: p["pair_id"])
    print("GENERATED:", validate(manifest))
    manifest["statistics"] = statistics(manifest)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest["statistics"], indent=2), flush=True)
