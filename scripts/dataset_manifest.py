"""Versioned pair manifest validation; ground truth never consumes similarity scores."""

import argparse
import hashlib
import json
from pathlib import Path

VERSION = "0.1.0"
FAMILIES = {"compiler_variation", "transparent_wrapper", "thunk", "function_splitting", "dead_branch", "harmless_strand", "linear_chain", "none"}
SPLITS = {"discovery_train", "validation", "held_out_test"}
STATUSES = {"unreviewed", "automatically_grounded", "manually_verified", "rejected", "ambiguous"}
PAIR_REQUIRED = {"pair_id", "source_group_id", "left_sample_id", "right_sample_id", "left_graph_id", "right_graph_id", "equivalence_label", "pair_category", "transformation_family", "transformation_parameters", "left_build_id", "right_build_id", "architecture", "validation_status", "ground_truth", "split", "notes"}


def stable_id(kind, *parts):
    return kind + ":" + hashlib.sha256(json.dumps(parts, separators=(",", ":"), sort_keys=True).encode()).hexdigest()[:24]


def indexed(items, key):
    result = {}
    for item in items:
        if not item.get(key) or item[key] in result:
            raise ValueError(f"missing/duplicate {key}")
        result[item[key]] = item
    return result


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(manifest, root=None):
    require(manifest.get("schema_version") == VERSION, "unsupported dataset version")
    samples = indexed(manifest["samples"], "sample_id")
    builds = indexed(manifest["builds"], "build_id")
    routines = indexed(manifest["routines"], "routine_id")
    graphs = indexed(manifest["graphs"], "graph_id")
    pairs = indexed(manifest["pairs"], "pair_id")
    for sample in samples.values():
        if sample["build_id"] is not None:
            require(sample["build_id"] in builds, "sample build missing")
            require(sample["sha256"] == builds[sample["build_id"]]["build_hash"], "sample/build hash mismatch")
    for graph in graphs.values():
        require(graph["sample_id"] in samples and graph["routine_id"] in routines, "graph sample/routine missing")
        require(graph["source_group_id"] == routines[graph["routine_id"]]["source_group_id"], "graph source group mismatch")
        if root:
            path = Path(root) / graph["path"]
            require(path.is_file(), f"graph file missing: {path}")
            require(hashlib.sha256(path.read_bytes()).hexdigest() == graph["sha256"], "graph hash mismatch")
            canonical = json.loads(path.read_text(encoding="utf-8"))
            require(canonical["canonical_digest"] == graph["canonical_digest"], "canonical digest mismatch")
    seen = set()
    for pair in pairs.values():
        require(PAIR_REQUIRED.issubset(pair), "pair fields missing")
        require(pair["equivalence_label"] in {"equivalent", "non_equivalent"}, "missing/unknown equivalence label")
        require(pair["transformation_family"] in FAMILIES, "unknown transformation family")
        require(pair["split"] in SPLITS, "missing/unknown split")
        require(pair["validation_status"] in STATUSES, "unknown validation status")
        require(pair["left_graph_id"] in graphs and pair["right_graph_id"] in graphs, "pair graph missing")
        identity = tuple(sorted((pair["left_graph_id"], pair["right_graph_id"])))
        require(identity[0] != identity[1] and identity not in seen, "self/duplicate/reversed pair")
        seen.add(identity)
        for side in ("left", "right"):
            graph = graphs[pair[side + "_graph_id"]]
            require(pair[side + "_sample_id"] == graph["sample_id"], "pair/sample graph mismatch")
            sample = samples[graph["sample_id"]]
            require(pair[side + "_build_id"] == sample["build_id"], "pair build mismatch")
            require(sample["architecture"] == pair["architecture"], "pair architecture mismatch")
        truth = pair["ground_truth"]
        require(truth.get("method") in {"same_controlled_source", "source_transformation_proof", "behavior_counterexample"}, "ground truth must be independent of similarity")
        require(truth.get("label") == pair["equivalence_label"], "contradictory ground truth")
        left, right = (graphs[pair[s + "_graph_id"]] for s in ("left", "right"))
        if pair["equivalence_label"] == "equivalent":
            require(left["source_group_id"] == right["source_group_id"] == pair["source_group_id"], "positive source groups differ")
            require(truth["method"] != "behavior_counterexample", "negative witness for positive label")
            if truth["method"] == "same_controlled_source":
                require(builds[pair["left_build_id"]]["source_hash"] == builds[pair["right_build_id"]]["source_hash"], "same-source label with different source artifacts")
                require(left["variant"] == right["variant"], "same-source pair variants differ")
                require(left["routine_id"] == right["routine_id"], "same-source pair routines differ")
                require(truth.get("source_hash") == builds[pair["left_build_id"]]["source_hash"], "ground truth source hash mismatch")
                require(truth.get("routine_body_sha256") == routines[left["routine_id"]].get("body_sha256") and bool(truth.get("routine_body_sha256")), "ground truth body hash mismatch")
            else:
                require(bool(truth.get("proof")) and truth.get("validation") == "passed", "transformation proof missing")
                transformation = truth.get("transformation", {})
                require(transformation in manifest.get("transformations", []), "transformation registry mismatch")
                require(transformation.get("family") == pair["transformation_family"] and transformation.get("parameters") == pair["transformation_parameters"], "transformation metadata mismatch")
                require({left["routine_id"], right["routine_id"]} == {transformation.get("original_routine"), transformation.get("transformed_routine")}, "transformation routines mismatch")
                require(truth["proof"] == transformation.get("rationale"), "transformation rationale mismatch")
        else:
            require(truth["method"] == "behavior_counterexample", "negative label lacks counterexample")
            require(truth.get("left_result") != truth.get("right_result"), "counterexample outputs do not differ")
            for side, graph in (("left", left), ("right", right)):
                transcript = builds[pair[side + "_build_id"]]["behavior"]
                expected_row = f"{graph['routine_id']} {truth.get('case')} {truth.get(side + '_result')}"
                require(expected_row in transcript, "counterexample absent from actual build transcript")
            require(pair["left_sample_id"] == pair["right_sample_id"], "counterexample input harness differs")
            case = truth.get("case")
            require(isinstance(case, int) and 0 <= case < 16, "unknown counterexample input case")
            require(truth.get("input_bytes") == [(j * 17 + case * 13) % 127 for j in range(case * 7)], "counterexample input mismatch")
            require(bool(pair.get("negative_category")) and pair.get("difficulty") in {"easy", "hard"}, "negative category/difficulty missing")
        if pair["validation_status"] == "ambiguous":
            require(pair["split"] != "held_out_test", "ambiguous pair in main held-out test")
    if "split_protocol" in manifest:
        try:
            from .dataset_splits import validate_leakage
        except ImportError:
            from dataset_splits import validate_leakage
        validate_leakage(manifest, manifest["split_protocol"]["configuration"])
    return dict(samples=len(samples), builds=len(builds), routines=len(routines), graphs=len(graphs), pairs=len(pairs))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    print("DATASET VALID:", validate(json.loads(args.manifest.read_text(encoding="utf-8")), args.root))
