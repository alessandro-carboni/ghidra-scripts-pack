"""Step 10.0 read-only evidence/eligibility audit. No scores or evaluation protocol."""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess

try:
    from .step9_preflight import ROOT, DATA, exact_hash, frozen_baseline, safe_path, repository_state
    from .dataset_manifest import indexed, require, SPLITS
except ImportError:
    from step9_preflight import ROOT, DATA, exact_hash, frozen_baseline, safe_path, repository_state
    from dataset_manifest import indexed, require, SPLITS

AUDIT_DIR = "datasets/osgf_baseline_evaluation_v0_1"
ADMITTED = {"automatically_grounded", "manually_verified"}


def serialize(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def judged_galleries(manifest, exclusion="identity_only"):
    """Preliminary symmetric judged neighborhoods, not rankings or inferred relevance."""
    require(exclusion in {"identity_only", "equal_canonical_digest", "same_binary"}, "unknown audit scenario")
    graphs = indexed(manifest["graphs"], "graph_id")
    samples = indexed(manifest["samples"], "sample_id")
    indexed(manifest["pairs"], "pair_id")
    neighbors = {gid: {} for gid in graphs}
    seen = set()
    for pair in manifest["pairs"]:
        left, right = pair["left_graph_id"], pair["right_graph_id"]
        label = pair["equivalence_label"]
        require(label in {"equivalent", "non_equivalent"}, "unknown relevance label")
        require(left in graphs and right in graphs, "unknown graph")
        require(left != right, "self pair")
        identity = tuple(sorted((left, right)))
        require(identity not in seen, "duplicate or contradictory judgment")
        seen.add(identity)
        require(pair["split"] in SPLITS and graphs[left]["split"] == graphs[right]["split"] == pair["split"], "cross-split judgment")
        require(pair["ground_truth"]["label"] == label, "contradictory ground truth")
        if pair["validation_status"] not in ADMITTED:
            continue
        if exclusion == "equal_canonical_digest" and graphs[left]["canonical_digest"] == graphs[right]["canonical_digest"]:
            continue
        if exclusion == "same_binary" and samples[graphs[left]["sample_id"]]["sha256"] == samples[graphs[right]["sample_id"]]["sha256"]:
            continue
        for query, reference in ((left, right), (right, left)):
            neighbors[query][reference] = dict(reference_graph_id=reference, pair_id=pair["pair_id"], label=label)
    queries = []
    for gid, graph in sorted(graphs.items()):
        require(graph["split"] in SPLITS, "unknown graph split")
        candidates = [neighbors[gid][key] for key in sorted(neighbors[gid])]
        positives = sum(c["label"] == "equivalent" for c in candidates)
        queries.append(dict(query_graph_id=gid, split=graph["split"], gallery_size=len(candidates), positive_count=positives, negative_count=len(candidates) - positives, eligible=positives > 0, candidates=candidates))
    summary = {}
    for split in sorted(SPLITS):
        rows = [q for q in queries if q["split"] == split]
        eligible = [q for q in rows if q["eligible"]]
        summary[split] = dict(
            graphs=len(rows),
            eligible_queries=len(eligible),
            queries_without_positive=len(rows) - len(eligible),
            eligible_with_positive_and_negative=sum(q["negative_count"] > 0 for q in eligible),
            gallery_sizes=dict(sorted(Counter(str(q["gallery_size"]) for q in eligible).items())),
            candidates_at_least={str(k): sum(q["gallery_size"] >= k for q in eligible) for k in (1, 3, 5)},
        )
    return dict(scenario=exclusion, policy_status="audit sensitivity only; not pre-registered eligibility", summary=summary, queries=queries)


def build_audit(root=ROOT):
    root = Path(root).resolve()
    baseline = frozen_baseline(root)
    pinned = json.loads(safe_path(root, "datasets/osgf_transformations_v0_1/baseline.json").read_bytes())
    require(baseline == pinned, "Step 9 protected inventory changed")
    manifest = json.loads(safe_path(root, DATA + "/manifest.json").read_bytes())
    canonical_fields, source_fields = set(), set()
    for graph in manifest["graphs"]:
        canonical = json.loads(safe_path(root, graph["path"]).read_bytes())
        canonical_fields.update(canonical)
        source_fields.update(canonical["source_document"])
    return dict(
        audit_version="0.1.0",
        scope="Step 10.0 technical preflight only; no empirical scores or frozen evaluation protocol",
        frozen_input_inventory=baseline,
        step9_baseline_sha256=exact_hash(root / "datasets/osgf_transformations_v0_1/baseline.json"),
        counts=baseline["counts"],
        labels=dict(sorted(Counter(p["equivalence_label"] for p in manifest["pairs"]).items())),
        pair_splits=dict(sorted(Counter(p["split"] for p in manifest["pairs"]).items())),
        pair_statuses=dict(sorted(Counter(p["validation_status"] for p in manifest["pairs"]).items())),
        field_catalog={**{key: sorted(set().union(*(set(item) for item in manifest[key]))) for key in ("samples", "builds", "routines", "graphs", "pairs")}, "canonical_document": sorted(canonical_fields), "embedded_local_document": sorted(source_fields)},
        galleries={scenario: judged_galleries(manifest, scenario) for scenario in ("identity_only", "equal_canonical_digest", "same_binary")},
        binary_references=[dict(sample_id=s["sample_id"], path=s["path"], expected_sha256=s["sha256"], required_for_evaluation=False) for s in sorted(manifest["samples"], key=lambda s: s["sample_id"])],
        blockers=[
            "No non-canonical input route exists in the frozen fingerprint/comparison CLI; condition A needs a separately approved parity-tested research adapter.",
            "Judgments are sparse. Retrieval requires query-specific judged galleries and a pre-registered duplicate/K/positive eligibility policy; unjudged pairs are never negatives.",
            "Step 10.1 review/protocol and Step 10.2 A/B comparability approval are required before evaluation.",
        ],
    )


def check_local_binaries(root=ROOT):
    root = Path(root).resolve()
    manifest = json.loads(safe_path(root, DATA + "/manifest.json").read_bytes())
    results = []
    for sample in sorted(manifest["samples"], key=lambda s: s["sample_id"]):
        path = safe_path(root, sample["path"])
        if path.is_file():
            require(exact_hash(path) == sample["sha256"], "local binary hash mismatch: " + sample["sample_id"])
        results.append(dict(sample_id=sample["sample_id"], status="readable_hash_verified" if path.is_file() else "NOT_AVAILABLE_local_binary_not_required_for_canonical_evaluation"))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare against the versioned preliminary audit; never rewrite")
    parser.add_argument("--write-audit", action="store_true", help="Create the explicitly versioned preliminary audit; refuse replacement")
    args = parser.parse_args()
    require(not (args.check and args.write_audit), "choose check or write")
    state = repository_state()
    audit = build_audit()
    output = ROOT / AUDIT_DIR / "preliminary_audit.json"
    raw = serialize(audit)
    if args.check:
        require(output.read_bytes() == raw, "preliminary audit changed; review differences without overwriting")
    elif args.write_audit:
        with output.open("xb") as stream:
            stream.write(raw)
    ignored = subprocess.run(["git", "check-ignore", "-q", "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9/manifest.json"], cwd=ROOT, check=False)
    require(ignored.returncode == 0, "Step 9 local runs must remain ignored")
    print(
        json.dumps(
            dict(
                repository=state,
                counts=audit["counts"],
                labels=audit["labels"],
                splits=audit["pair_splits"],
                protected_files=len(audit["frozen_input_inventory"]["scientific_files"]),
                frozen_digest=audit["frozen_input_inventory"]["freeze_scientific_digest"],
                galleries={k: v["summary"] for k, v in audit["galleries"].items()},
                local_binaries=check_local_binaries(),
                step9_local_run="ignored; not a required baseline input",
            ),
            indent=2,
            sort_keys=True,
        )
    )
    print("STEP 10.0 AUDIT PASS; no scores computed; STOP before 10.1")


if __name__ == "__main__":
    main()
