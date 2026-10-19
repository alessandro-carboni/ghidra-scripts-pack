"""Prepare human review packets and append immutable, explicitly versioned review freezes."""

import argparse
import hashlib
import json
from pathlib import Path

try:
    from .dataset_manifest import require, validate
except ImportError:
    from dataset_manifest import require, validate


def content_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def transformation_evidence(pair, graphs, builds):
    proof = pair["ground_truth"]["transformation"]
    target = proof["transformed_routine"]
    side = next(side for side in ("left", "right") if graphs[pair[side + "_graph_id"]]["routine_id"] == target)
    build = builds[pair[side + "_build_id"]]
    rows = [row.split() for row in build["behavior"] if row.split()[0] == target]
    expected = proof.get("test_cases_per_build", proof.get("test_cases"))
    require(isinstance(expected, int) and expected > 0 and len(rows) == expected and {int(row[1]) for row in rows} == set(range(expected)), "transformation input coverage differs from recorded proof")
    if "test_cases_per_build" in proof:
        detail = f"{expected} deterministic cases per routine per build; {build['behavior_input']}. Contract requires stable read-only OS environment across calls/builds; observations and results depend on that environment."
    else:
        detail = f"{expected:,} deterministic inputs for the transformed routine, covering lengths 0..{proof['parameters']['max_length']} with four byte patterns."
    return "Validation: " + detail + " Tests are not exhaustive enumeration of byte strings; the source rationale is necessary."


def select_subset(manifest):
    builds = {b["build_id"]: b for b in manifest["builds"]}
    selected = {}
    criteria = {
        "optimization_variants": lambda p: p["pair_category"] == "same_source" and builds[p["left_build_id"]]["optimization"] != builds[p["right_build_id"]]["optimization"],
        "cross_compiler_variants": lambda p: p["pair_category"] == "same_source" and builds[p["left_build_id"]]["compiler"] != builds[p["right_build_id"]]["compiler"],
        "easy_negatives": lambda p: p.get("difficulty") == "easy",
        "hard_negatives": lambda p: p.get("difficulty") == "hard",
    }
    for family in ("transparent_wrapper", "thunk", "function_splitting", "dead_branch", "harmless_strand", "linear_chain"):
        criteria[family] = lambda p, family=family: p["transformation_family"] == family
    for category in ("similar_api_different_structure", "similar_topology_different_evidence", "benign_lookalike", "similar_constants_different_behavior"):
        criteria[category] = lambda p, category=category: p.get("negative_category") == category
    for criterion, predicate in criteria.items():
        candidates = sorted((p for p in manifest["pairs"] if predicate(p)), key=lambda p: p["pair_id"])
        require(bool(candidates), "missing review coverage: " + criterion)
        selected.setdefault(candidates[0]["pair_id"], []).append(criterion)
    return selected


def prepare(manifest, directory, refresh_pending=False):
    if refresh_pending:
        for name in ("review_packet.json", "review_decisions.json"):
            existing = directory / name
            if existing.exists():
                previous = json.loads(existing.read_text())
                require(all(r.get("decision") == "pending" and r.get("validation_status") == "unreviewed" and all(not r.get(key) for key in ("reviewer", "notes", "reason")) for r in previous["records"]), "cannot refresh a review containing human input")
    selected = select_subset(manifest)
    pairs = {p["pair_id"]: p for p in manifest["pairs"]}
    graphs = {g["graph_id"]: g for g in manifest["graphs"]}
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    builds = {b["build_id"]: b for b in manifest["builds"]}
    records = []
    lines = [
        "# Step 8 â€” Manual ground-truth review",
        "",
        "Status: pending human review. Automatic source proofs and runtime checks are supporting evidence, not human decisions.",
        "",
        "For each pair inspect the named C routines, the contract and the witness/proof. Record accept, reject or ambiguous with reviewer, notes and reason in review_decisions.json. Do not accept merely because tests pass.",
        "",
        "Contract: unsigned 32-bit result; 0 <= length <= 255; readable bytes followed by NUL. Pure reductions have no externally visible side effects. API negative functions use NUL-terminated input; baseline OS probes are host-state dependent.",
        "",
    ]
    legacy_outputs = sum(len(b["behavior"]) for b in builds.values() if "-variants-" in b["build_id"])
    interaction_outputs = sum(len(b["behavior"]) for b in builds.values() if b.get("artifact_group", "").startswith("interaction_"))
    lines += [f"Separate validation totals: legacy structural variants: {legacy_outputs:,} oracle checks; interaction corpus: {interaction_outputs} outputs across {sum(b.get('artifact_group', '').startswith('interaction_') for b in builds.values())} builds. These totals are not per-pair input counts.", ""]
    for pair_id, coverage in sorted(selected.items()):
        pair = pairs[pair_id]
        records.append(dict(pair_id=pair_id, coverage=coverage, pair_sha256=content_hash(pair), reviewer="", decision="pending", validation_status="unreviewed", notes="", reason=""))
        lines += [f"## {pair_id}", "", f"Coverage: {', '.join(coverage)}. Proposed label: **{pair['equivalence_label']}**. Split: {pair['split']}.", ""]
        for side in ("left", "right"):
            graph = graphs[pair[side + "_graph_id"]]
            routine = routines[graph["routine_id"]]
            build = builds[pair[side + "_build_id"]]
            lines += [f"- {side}: `{routine['routine_id']}` in `{routine['source_path']}`; {build['compiler']} {build['optimization']}; graph `{graph['graph_id']}`."]
            lines += [f"  Source contract: `{routine['contract']}`."]
            if "stable_readonly_environment" in routine["contract"]:
                lines += ["  Requires stable read-only OS state across calls and builds; file attributes, registry observations and socket results are environment-dependent."]
        truth = pair["ground_truth"]
        lines += ["", "Evidence: " + truth.get("proof", truth.get("evidence", "Same controlled source and body across compiler configurations."))]
        if truth["method"] == "behavior_counterexample":
            lines += [f"Input bytes: `{truth['input_bytes']}` (trailing NUL); results: left={truth['left_result']}, right={truth['right_result']}."]
        if truth["method"] == "source_transformation_proof":
            lines += [transformation_evidence(pair, graphs, builds)]
        lines += [""]
    packet = dict(schema_version="0.1.0", manifest_sha256=content_hash(manifest), records=records)
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in (("review_packet.json", packet), ("review_decisions.json", packet)):
        path = directory / name
        require(refresh_pending or not path.exists(), "review packet already exists; preserve decisions and use a new review directory")
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (directory / "REVIEW.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return len(records)


def validate_decisions(manifest, packet, decisions):
    require(packet["manifest_sha256"] == content_hash(manifest), "manifest changed since review packet")
    expected = {r["pair_id"]: r for r in packet["records"]}
    require(set(expected) == set(select_subset(manifest)), "review subset coverage changed")
    records = decisions["records"]
    require(len(records) == len(expected) and {r["pair_id"] for r in records} == set(expected), "review decisions missing/duplicated")
    pairs = {p["pair_id"]: p for p in manifest["pairs"]}
    for record in records:
        pair = pairs[record["pair_id"]]
        require(record["pair_sha256"] == expected[record["pair_id"]]["pair_sha256"] == content_hash(pair), "frozen pair content changed")
        require(bool(record["reviewer"].strip()) and bool(record["notes"].strip()) and bool(record["reason"].strip()), "reviewer/notes/reason required")
        status = {"accept": "manually_verified", "reject": "rejected", "ambiguous": "ambiguous"}.get(record["decision"])
        require(status is not None and record["validation_status"] == status, "review is pending or decision/status inconsistent")
        require(not (status in {"ambiguous", "rejected"} and pair["split"] == "held_out_test"), "exclude rejected/ambiguous held-out pair and regenerate review before freeze")
    required_coverage = {c for record in expected.values() for c in record["coverage"]}
    accepted_coverage = {c for record in records if record["decision"] == "accept" for c in expected[record["pair_id"]]["coverage"]}
    require(required_coverage <= accepted_coverage, "verified subset lacks coverage; select replacement pairs before freeze")
    return records


def freeze(manifest, directory, output, supersedes=None, reason=None):
    validate(manifest)
    packet = json.loads((directory / "review_packet.json").read_text())
    decisions = json.loads((directory / "review_decisions.json").read_text())
    records = validate_decisions(manifest, packet, decisions)
    existing = sorted(output.parent.glob("freeze-*.json"))
    require(not output.exists(), "never overwrite a frozen review")
    if existing:
        require(supersedes is not None and bool(reason), "revision requires supersedes and explicit reason")
        previous = json.loads(Path(supersedes).read_text())
        require(Path(supersedes).resolve() in {p.resolve() for p in existing}, "superseded freeze must be in this dataset revision history")
        parent_hash = content_hash(previous)
    else:
        require(supersedes is None, "no prior freeze to supersede")
        parent_hash = None
    result = dict(name="OSGF Equivalent / Non-Equivalent Pair Dataset v0.1", manifest_sha256=content_hash(manifest), records=records, review_packet=packet, supersedes_sha256=parent_hash, revision_reason=reason, manifest_snapshot=manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check", "freeze"))
    parser.add_argument("--manifest", type=Path, default=Path("datasets/osgf_pairs_v0_1/manifest.json"))
    parser.add_argument("--review-dir", type=Path, default=Path("datasets/osgf_pairs_v0_1/review"))
    parser.add_argument("--output", type=Path, default=Path("datasets/osgf_pairs_v0_1/freezes/freeze-001.json"))
    parser.add_argument("--supersedes", type=Path)
    parser.add_argument("--reason")
    parser.add_argument("--refresh-pending", action="store_true", help="Replace only an entirely unreviewed packet after a technical rebuild")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    if args.action == "prepare":
        print("REVIEW PACKET PREPARED:", prepare(manifest, args.review_dir, args.refresh_pending), "pairs; human decisions pending")
    elif args.action == "check":
        print("REVIEW VERIFIED:", len(validate_decisions(manifest, json.loads((args.review_dir / "review_packet.json").read_text()), json.loads((args.review_dir / "review_decisions.json").read_text()))))
    else:
        result = freeze(manifest, args.review_dir, args.output, args.supersedes, args.reason)
        print("FROZEN:", result["name"], content_hash(result))
