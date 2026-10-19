"""Check Step 8 technical acceptance; final acceptance additionally requires a real review freeze."""

import argparse
from collections import Counter
import json
from pathlib import Path

from controlled_corpus import digest, execute, pe_architecture
from dataset_manifest import require, validate
from dataset_review import content_hash, validate_decisions
from dataset_splits import family_holdout, validate_leakage
from validate_structural_variants import validate as validate_variants
from interaction_sources import validate_behavior as validate_interaction

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets/osgf_pairs_v0_1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--technical-only", action="store_true", help="Explicitly exclude pending manual review/freeze; does not declare Step 8 complete")
    parser.add_argument("--replay", action="store_true", help="Execute all controlled builds again and compare recorded transcripts")
    args = parser.parse_args()
    manifest = json.loads((DATA / "manifest.json").read_text())
    counts = validate(manifest, ROOT)
    builds = {b["build_id"]: b for b in manifest["builds"]}
    samples = {s["sample_id"]: s for s in manifest["samples"]}
    for sample in samples.values():
        path = ROOT / sample["path"]
        require(digest(path) == sample["sha256"] and pe_architecture(path) == sample["architecture"], "sample integrity failure")
    for build in builds.values():
        require(digest(ROOT / build["source_path"]) == build["source_hash"], "source integrity failure")
        if build["artifact_group"].startswith("interaction_"):
            validate_interaction(build["artifact_group"].removeprefix("interaction_"), build["behavior"], build["independent_environment_observation"])
        if args.replay:
            sample = next(s for s in samples.values() if s["build_id"] == build["build_id"])
            require(execute([str(ROOT / sample["path"])]).splitlines() == build["behavior"], "runtime transcript changed: " + build["build_id"])
            print("REPLAY PASS:", build["build_id"], len(build["behavior"]), "outputs", flush=True)
    benign = [s for s in samples.values() if s["build_id"] is None]
    require(5 <= len(benign) <= 10, "real benign corpus missing")
    pair_samples = {p[side + "_sample_id"] for p in manifest["pairs"] for side in ("left", "right")}
    require(not pair_samples.intersection(s["sample_id"] for s in benign), "real corpus used as automatic ground truth")
    require({"O0", "O2", "O3"} <= {b["optimization"] for b in builds.values()}, "optimization coverage missing")
    require(any(builds[p["left_build_id"]]["compiler"] != builds[p["right_build_id"]]["compiler"] for p in manifest["pairs"] if p["pair_category"] == "same_source"), "cross compiler pairs missing")
    print("VARIANTS:", validate_variants(json.loads((DATA / "variants.json").read_text())), flush=True)
    stats = validate_leakage(manifest, json.loads((DATA / "split_config.json").read_text()))
    require(stats == manifest["split_statistics"], "stale split statistics")
    for family in ("transparent_wrapper", "thunk", "function_splitting", "dead_branch", "harmless_strand", "linear_chain"):
        family_holdout(manifest, family)
    categories = Counter(p.get("negative_category") for p in manifest["pairs"] if p["equivalence_label"] == "non_equivalent")
    require({"different_behavior", "similar_api_different_structure", "similar_topology_different_evidence", "benign_lookalike", "same_binary_different_routine", "similar_constants_different_behavior"} <= set(categories), "negative coverage missing")
    require({p.get("difficulty") for p in manifest["pairs"] if p["equivalence_label"] == "non_equivalent"} == {"easy", "hard"}, "easy/hard negative coverage missing")
    print("TECHNICAL ACCEPTANCE PASS:", counts, "negative categories:", dict(categories), flush=True)
    if args.technical_only:
        print("MANUAL REVIEW/FREEZE NOT CHECKED: this is not final Step 8 acceptance.", flush=True)
        return
    freezes = sorted((DATA / "freezes").glob("freeze-*.json"))
    require(bool(freezes), "Step 8 incomplete: manual review and final freeze are pending")
    frozen = json.loads(freezes[-1].read_text())
    require(frozen["manifest_sha256"] == content_hash(manifest) == content_hash(frozen["manifest_snapshot"]), "frozen dataset changed; explicit revision required")
    packet = frozen["review_packet"]
    validate_decisions(manifest, packet, dict(records=frozen["records"]))
    print("FINAL ACCEPTANCE PASS:", frozen["name"], flush=True)


if __name__ == "__main__":
    main()
