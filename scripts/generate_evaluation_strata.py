"""Descriptive pair sets derived only from the exact manifest and graph audit."""

import argparse
import hashlib
import json
from pathlib import Path

try:
    from .audit_dataset_graph_signal import pair_signal, serialize
except ImportError:
    from audit_dataset_graph_signal import pair_signal, serialize

DATA = Path(__file__).resolve().parents[1] / "datasets/osgf_pairs_v0_1"


def generate(manifest_bytes, audit_bytes):
    manifest, audit = json.loads(manifest_bytes), json.loads(audit_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if audit["manifest_sha256"] != digest:
        raise ValueError("Audit does not describe the exact manifest bytes")
    graphs = {g["graph_id"]: g for g in audit["graphs"]}
    if len(graphs) != len(audit["graphs"]) or set(graphs) != {g["graph_id"] for g in manifest["graphs"]}:
        raise ValueError("Audit graph coverage mismatch")
    for graph in manifest["graphs"]:
        if graphs[graph["graph_id"]]["content_sha256"] != graph["sha256"] or graphs[graph["graph_id"]]["split"] != graph["split"]:
            raise ValueError("Audit graph provenance mismatch")
    pairs = sorted(manifest["pairs"], key=lambda p: p["pair_id"])
    if len({p["pair_id"] for p in pairs}) != len(pairs):
        raise ValueError("Duplicate pair ID")
    signals = {}
    for pair in pairs:
        signal = pair_signal(graphs[pair["left_graph_id"]], graphs[pair["right_graph_id"]])
        signals[pair["pair_id"]] = dict(
            all_pairs=True,
            both_anchor_only=signal["both_anchor_only"],
            at_least_one_non_anchor_signal=not signal["both_anchor_only"],
            both_typed_evidence=signal["both_typed_evidence"],
            both_function_call_topology=signal["both_topology"],
            both_interaction_capable=signal["both_interaction_capable"],
            either_observability_unknown=signal["either_observability_unknown"],
            either_observed_incomplete=signal["either_observed_incomplete"],
            both_observability_complete=signal["both_observability_complete"],
        )
    names = ("all_pairs", "both_anchor_only", "at_least_one_non_anchor_signal", "both_typed_evidence", "both_function_call_topology", "both_interaction_capable", "either_observability_unknown", "either_observed_incomplete", "both_observability_complete")

    def strata(selected):
        return {name: [p["pair_id"] for p in selected if signals[p["pair_id"]][name]] for name in names}

    return dict(
        strata_version="0.1.0",
        manifest_sha256=digest,
        graph_signal_audit_sha256=hashlib.sha256(audit_bytes).hexdigest(),
        scope="Descriptive overlapping pair sets only; no scores, exclusions, relabeling or split changes.",
        strata=strata(pairs),
        by_split={split: strata([p for p in pairs if p["split"] == split]) for split in sorted({p["split"] for p in pairs})},
        by_equivalence_label={label: strata([p for p in pairs if p["equivalence_label"] == label]) for label in sorted({p["equivalence_label"] for p in pairs})},
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DATA / "manifest.json")
    parser.add_argument("--audit", type=Path, default=DATA / "graph_signal_audit.json")
    parser.add_argument("--output", type=Path, default=DATA / "evaluation_strata.json")
    args = parser.parse_args()
    result = generate(args.manifest.read_bytes(), args.audit.read_bytes())
    if args.output.resolve() in {args.manifest.resolve(), args.audit.resolve()}:
        raise ValueError("Output must not overwrite inputs")
    if args.output.exists() and "strata_version" not in json.loads(args.output.read_bytes()):
        raise ValueError("Output is not an evaluation strata document")
    args.output.write_bytes(serialize(result))
    print("EVALUATION STRATA:", {key: len(ids) for key, ids in result["strata"].items()})


if __name__ == "__main__":
    main()
