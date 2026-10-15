"""Read-only canonical graph signal audit; no scoring, labeling or evidence inference."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_TYPES = {"API", "STRING", "STRING_CATEGORY", "CONSTANT", "SECTION"}
ENDPOINTS = {
    "calls_function": ("FUNCTION", "FUNCTION"),
    "calls_api": ("FUNCTION", "API"),
    "references_string": ("FUNCTION", "STRING"),
    "uses_constant": ("FUNCTION", "CONSTANT"),
    "belongs_to_section": ("FUNCTION", "SECTION"),
    "has_string_category": ("STRING", "STRING_CATEGORY"),
    "contains_indirect_call": ("FUNCTION", "VISIBILITY_INDICATOR"),
}
EVIDENCE_EDGES = {"calls_api", "references_string", "uses_constant", "belongs_to_section"}
PROPERTIES = ("anchor_only", "has_topology", "topology_only", "typed_evidence_present", "interaction_capable", "degraded_observability")
COUNTS = (
    "function_node_count",
    "non_anchor_function_node_count",
    "typed_evidence_node_count",
    "edge_count",
    "calls_function_count",
    "calls_api_count",
    "references_string_count",
    "uses_constant_count",
    "category_node_count",
    "has_string_category_count",
    "category_chain_count",
    "interaction_support_count",
    "unresolved_call_count",
    "unresolved_call_occurrences",
)


def graph_signal(document):
    nodes = {n["id"]: n for n in document["nodes"]}
    edges = document["edges"]
    if len(nodes) != len(document["nodes"]):
        raise ValueError("Duplicate canonical node ID")
    for node in nodes.values():
        if node["kind"] not in EVIDENCE_TYPES | {"FUNCTION", "VISIBILITY_INDICATOR"}:
            raise ValueError("Unknown canonical node kind")
    for edge in edges:
        expected = ENDPOINTS.get(edge["kind"])
        actual = tuple(nodes[edge[end]]["kind"] for end in ("source", "target"))
        if expected != actual:
            raise ValueError("Invalid canonical edge/endpoints")
    functions = [n for n in nodes.values() if n["kind"] == "FUNCTION"]
    anchors = [n for n in functions if n["facts"].get("role") == "ANCHOR"]
    if len(anchors) != 1:
        raise ValueError("Expected exactly one canonical FUNCTION anchor")
    evidence = [n for n in nodes.values() if n["kind"] in EVIDENCE_TYPES]
    kinds = Counter(edge["kind"] for edge in edges)
    categories = [e for e in edges if e["kind"] == "has_string_category"]
    chains = [(reference, category) for reference in edges if reference["kind"] == "references_string" for category in categories if category["source"] == reference["target"]]
    interactions = [(call, evidence) for call in edges if call["kind"] == "calls_function" for evidence in edges if evidence["kind"] in EVIDENCE_EDGES and evidence["source"] == call["target"]]
    call_chains = sum(1 for _, evidence_edge in interactions if evidence_edge["kind"] == "references_string" for category in categories if category["source"] == evidence_edge["target"])
    visibility = [n for n in nodes.values() if n["kind"] == "VISIBILITY_INDICATOR"]
    unknown = [key for key in ("indirect_calls", "unresolved_indirect_calls", "explicit_dynamic_dispatch") if not visibility or any(n["facts"].get(key) is None for n in visibility)]
    unresolved = document["unresolved_calls"]
    local = document["local_graph_truncation"]
    if not isinstance(local.get("truncated"), bool):
        raise ValueError("Missing canonical truncation state")
    unresolved_indirect = sum(n["facts"].get("unresolved_indirect_calls") or 0 for n in visibility)
    reasons = []
    if unresolved:
        reasons.append("unresolved_calls_observed")
    if unresolved_indirect:
        reasons.append("unresolved_indirect_calls_observed")
    if local["truncated"]:
        reasons.append("local_graph_truncated")
    reasons.extend(key + "_observation_unavailable" for key in unknown)
    semantic_edges = [e for e in edges if e["kind"] != "contains_indirect_call"]
    return dict(
        function_node_count=len(functions),
        non_anchor_function_node_count=len(functions) - 1,
        typed_evidence_node_count=len(evidence),
        evidence_types_present=sorted({n["kind"] for n in evidence}),
        edge_count=len(edges),
        calls_function_count=kinds["calls_function"],
        calls_api_count=kinds["calls_api"],
        references_string_count=kinds["references_string"],
        uses_constant_count=kinds["uses_constant"],
        category_node_count=sum(n["kind"] == "STRING_CATEGORY" for n in nodes.values()),
        has_string_category_count=len(categories),
        category_chain_count=len(chains),
        interaction_support_count=len(interactions) + call_chains,
        call_category_chain_count=call_chains,
        unresolved_call_count=len(unresolved),
        unresolved_call_occurrences=sum(c["facts"]["occurrences"] for c in unresolved),
        unresolved_indirect_observed_count=unresolved_indirect,
        unknown_observation_fields=unknown,
        local_graph_truncated=local["truncated"],
        requested_depth=local.get("requested_depth"),
        effective_depth=local.get("effective_depth"),
        anchor_only=len(functions) == 1 and not evidence and not semantic_edges,
        has_topology=bool(kinds["calls_function"]),
        topology_only=bool(kinds["calls_function"]) and not evidence,
        typed_evidence_present=bool(evidence),
        interaction_capable=bool(interactions),
        degraded_observability=bool(reasons),
        observability_reasons=reasons,
    )


def graph_statistics(records):
    return dict(
        graphs=len(records),
        properties={key: sum(r[key] for r in records) for key in PROPERTIES},
        counts={key: sum(r[key] for r in records) for key in COUNTS},
        evidence_types_graph_counts=dict(sorted(Counter(t for r in records for t in r["evidence_types_present"]).items())),
        observability_reasons=dict(sorted(Counter(t for r in records for t in r["observability_reasons"]).items())),
    )


def pair_signal(left, right):
    return dict(
        both_anchor_only=left["anchor_only"] and right["anchor_only"],
        exactly_one_anchor_only=left["anchor_only"] != right["anchor_only"],
        both_typed_evidence=left["typed_evidence_present"] and right["typed_evidence_present"],
        both_topology=left["has_topology"] and right["has_topology"],
        both_interaction_capable=left["interaction_capable"] and right["interaction_capable"],
        either_degraded=left["degraded_observability"] or right["degraded_observability"],
    )


def audit(manifest_path, root=ROOT):
    manifest_bytes = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_bytes)
    records = {}
    protected = {Path(manifest_path).resolve()}
    for graph in sorted(manifest["graphs"], key=lambda g: g["graph_id"]):
        path = (Path(root) / graph["path"]).resolve()
        protected.add(path)
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != graph["sha256"]:
            raise ValueError("Graph content hash differs from manifest: " + graph["graph_id"])
        if graph["graph_id"] in records:
            raise ValueError("Duplicate graph ID in manifest")
        records[graph["graph_id"]] = dict(graph_id=graph["graph_id"], split=graph["split"], content_sha256=digest, **graph_signal(json.loads(raw)))
    pairs = []
    grouped = {key: defaultdict(list) for key in ("equivalence_label", "pair_category", "transformation_family", "negative_category", "split")}
    for pair in sorted(manifest["pairs"], key=lambda p: p["pair_id"]):
        signal = pair_signal(records[pair["left_graph_id"]], records[pair["right_graph_id"]])
        pairs.append(signal)
        for field, groups in grouped.items():
            if field in pair:
                groups[pair[field]].append(signal)

    def pair_statistics(items):
        keys = ("both_anchor_only", "exactly_one_anchor_only", "both_typed_evidence", "both_topology", "both_interaction_capable", "either_degraded")
        return dict(pairs=len(items), **{key: sum(item[key] for item in items) for key in keys})

    result = dict(
        audit_version="0.1.0",
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        definitions=dict(
            counts="Canonical nodes/edges (not callsite multiplicities); unresolved occurrences also reported separately.",
            anchor_only="One FUNCTION anchor and no other semantic structure; visibility/unknown observability may coexist.",
            interaction_capable="Explicit calls_function edge whose callee is source of calls_api/references_string/uses_constant/belongs_to_section (Step 6).",
            degraded_observability="Observed unresolved calls, local truncation, or unavailable visibility counts, as in Step 6/7. Unknown is not zero. No fingerprint motif-budget truncation inferred from canonical input.",
            scope="Read-only signal audit; categories overlap; no labels, exclusions, similarity or malware inference.",
        ),
        global_graph_statistics=graph_statistics(list(records.values())),
        per_split_graph_statistics={split: graph_statistics([r for r in records.values() if r["split"] == split]) for split in sorted({r["split"] for r in records.values()})},
        global_pair_statistics=pair_statistics(pairs),
        pair_statistics={field: {key: pair_statistics(items) for key, items in sorted(groups.items())} for field, groups in grouped.items()},
        graphs=list(records.values()),
    )
    return result, protected


def serialize(result):
    return (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_output(result, output, protected):
    output = Path(output)
    if output.resolve() in protected:
        raise ValueError("Audit output must not overwrite an input dataset file")
    if output.exists():
        previous = json.loads(output.read_bytes())
        if not isinstance(previous, dict) or "audit_version" not in previous or "global_graph_statistics" not in previous:
            raise ValueError("Refusing to overwrite a file that is not an audit report")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(serialize(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "datasets/osgf_pairs_v0_1/manifest.json")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result, protected = audit(args.manifest, args.root)
    if args.output:
        write_output(result, args.output, protected)
    stats = result["global_graph_statistics"]
    print("GRAPH SIGNAL AUDIT:", stats["graphs"], "graphs;", json.dumps(stats["properties"], sort_keys=True))
    for split, stats in result["per_split_graph_statistics"].items():
        print("SPLIT", split, stats["graphs"], "graphs;", json.dumps(stats["properties"], sort_keys=True))
    print("PAIRS:", json.dumps(result["global_pair_statistics"], sort_keys=True))
    for label, stats in result["pair_statistics"]["equivalence_label"].items():
        print("LABEL", label, json.dumps(stats, sort_keys=True))
    print("Manifest SHA-256:", result["manifest_sha256"])


if __name__ == "__main__":
    main()
