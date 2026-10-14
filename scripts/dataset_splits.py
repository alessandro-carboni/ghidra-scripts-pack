"""Deterministic source-component splits and independent leakage validation."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

try:
    from .dataset_manifest import FAMILIES, SPLITS, require
except ImportError:
    from dataset_manifest import FAMILIES, SPLITS, require


def config_hash(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def assignments(manifest, config):
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    return {g["graph_id"]: config["artifact_splits"][routines[g["routine_id"]]["artifact_group"]] for g in manifest["graphs"]}


def validate_leakage(manifest, config):
    require(manifest["split_protocol"]["configuration_sha256"] == config_hash(config), "split configuration changed")
    expected = assignments(manifest, config)
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    samples = {s["sample_id"]: s for s in manifest["samples"]}
    builds = {b["build_id"]: b for b in manifest["builds"]}
    graphs = {g["graph_id"]: g for g in manifest["graphs"]}
    memberships = {}

    def claim(key, split):
        require(split in SPLITS, "unknown split")
        memberships.setdefault(key, set()).add(split)
        require(len(memberships[key]) == 1, "source/artifact/near-duplicate leakage: " + str(key))

    for graph in graphs.values():
        split = graph["split"]
        routine = routines[graph["routine_id"]]
        build = builds[samples[graph["sample_id"]]["build_id"]]
        for key in (("source_group", graph["source_group_id"]), ("artifact", routine["artifact_group"]), ("source_hash", build["source_hash"]), ("body_hash", routine["body_sha256"]), ("source_path", routine["source_path"])):
            claim(key, split)
        for index, group in enumerate(config["near_duplicate_groups"]):
            if graph["source_group_id"] in group:
                claim(("near_duplicate", index), split)
        require(split == expected[graph["graph_id"]], "graph split differs from configured source component")
    seen = set()
    for pair in manifest["pairs"]:
        identity = tuple(sorted((pair["left_graph_id"], pair["right_graph_id"])))
        require(identity not in seen, "duplicate/reversed pair leakage")
        seen.add(identity)
        require(all(graphs[g]["split"] == pair["split"] for g in identity), "pair crosses source splits")
        require(not (pair["split"] == "held_out_test" and pair["validation_status"] in {"ambiguous", "rejected"}), "ineligible held-out pair")
    return split_statistics(manifest)


def split_statistics(manifest):
    graphs = {g["graph_id"]: g for g in manifest["graphs"]}
    samples = {s["sample_id"]: s for s in manifest["samples"]}
    builds = {b["build_id"]: b for b in manifest["builds"]}
    result = {}
    for split in sorted(SPLITS):
        pairs = [p for p in manifest["pairs"] if p["split"] == split]
        selected = [g for g in graphs.values() if g["split"] == split]
        build_ids = {samples[g["sample_id"]]["build_id"] for g in selected}
        result[split] = dict(
            source_groups=sorted({g["source_group_id"] for g in selected}),
            graphs=len(selected),
            positive_pairs=sum(p["equivalence_label"] == "equivalent" for p in pairs),
            negative_pairs=sum(p["equivalence_label"] == "non_equivalent" for p in pairs),
            compiler=dict(sorted(Counter(builds[b]["compiler"] for b in build_ids).items())),
            optimization_levels=dict(sorted(Counter(builds[b]["optimization"] for b in build_ids).items())),
            transformation_families=dict(sorted(Counter(p["transformation_family"] for p in pairs).items())),
            negative_categories=dict(sorted(Counter(p["negative_category"] for p in pairs if "negative_category" in p).items())),
        )
    return result


def apply_splits(manifest, config):
    assigned = assignments(manifest, config)
    for graph in manifest["graphs"]:
        graph["split"] = assigned[graph["graph_id"]]
    for pair in manifest["pairs"]:
        left, right = (assigned[pair[s + "_graph_id"]] for s in ("left", "right"))
        require(left == right, "pair spans incompatible source components")
        pair["split"] = left
        pair["notes"] = "Source/artifact component assignment; see split_config.json."
    manifest["split_protocol"] = dict(configuration=config, configuration_sha256=config_hash(config))
    manifest["split_statistics"] = validate_leakage(manifest, config)


def family_holdout(manifest, family):
    require(family in FAMILIES - {"none", "compiler_variation"}, "unknown structural family")
    result = {split: sorted(p["pair_id"] for p in manifest["pairs"] if p["split"] == split and p["validation_status"] not in {"ambiguous", "rejected"} and ((p["transformation_family"] == family) if split == "held_out_test" else (p["transformation_family"] != family))) for split in sorted(SPLITS)}
    require(all(result.values()), "empty family holdout partition")
    return dict(family=family, policy="Preserve source splits; exclude family from train/validation, select it in held-out test.", pair_ids=result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    config = json.loads(args.config.read_text())
    if not args.check:
        apply_splits(manifest, config)
        args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        holdouts = [family_holdout(manifest, f) for f in sorted(FAMILIES - {"none", "compiler_variation"})]
        args.manifest.with_name("family_holdouts.json").write_text(json.dumps(holdouts, indent=2, sort_keys=True) + "\n")
    print("LEAKAGE CHECK PASS:", json.dumps(validate_leakage(manifest, config), indent=2), flush=True)
