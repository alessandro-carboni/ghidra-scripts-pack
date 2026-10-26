"""Step 10.5: deterministic judged galleries; unknown pairs are never negatives."""

import json
import math
from pathlib import Path

try:
    from . import evaluation_pairs as pairs
except ImportError:
    import evaluation_pairs as pairs

ROOT, AUDIT_DIR = pairs.ROOT, pairs.AUDIT_DIR
require, serialize = pairs.require, pairs.serialize


def admitted_scores():
    """Recheck frozen inputs, identities, artifact bytes and independent score oracle."""
    expected = pairs.catalog.plan()
    folder = ROOT / AUDIT_DIR
    raw = (folder / "pair_matrix.json").read_bytes()
    require(pairs.sha(raw) == (folder / "pair_matrix.sha256").read_text().strip(), "matrix hash mismatch")
    require(raw == (ROOT / pairs.OUTPUT / "matrix.json").read_bytes(), "published matrix mismatch")
    matrix = json.loads(raw)
    require(matrix["status"] == "PASS", "incomplete matrix")
    catraw = (folder / "graph_catalog.json").read_bytes()
    require(catraw == (pairs.CATALOG / "catalog.json").read_bytes(), "catalog publication mismatch")
    catalog = json.loads(catraw)
    require(catalog["plan"] == expected and catalog["status"] == "PASS", "stale catalog identity")
    require(matrix["identity"]["catalog_sha256"] == pairs.sha(catraw), "matrix catalog mismatch")
    require(matrix["identity"]["generator_utf8_lf_sha256"] == pairs.sha(Path(pairs.__file__).read_text(encoding="utf-8").encode()), "stale matrix generator")
    for key in ("protocol_sha256", "engine_sha256", "research_engine_sha256"):
        require(matrix["identity"][key] == expected["identity"][key], "stale matrix dependency")
    manifest = json.loads((ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    jobs = pairs.pair_jobs(manifest, catalog["records"], matrix["identity"])
    require(len(jobs) == len(matrix["records"]), "matrix coverage mismatch")
    inputs = {r["record_id"]: pairs.load_input(r, pairs.CATALOG) for r in catalog["records"]}
    for job, row in zip(jobs, matrix["records"], strict=True):
        require(row["record_id"] == job["record_id"] and row["pair"] == job["pair"] and row["condition"] == job["condition"], "matrix label/identity mismatch")
        require(row["status"] == "success", "failed score")
        path = pairs.safe_path(ROOT / pairs.OUTPUT, row["artifact"]["path"])
        require(pairs.catalog.artifact(ROOT / pairs.OUTPUT, path) == row["artifact"], "score artifact mismatch")
        result = json.loads(path.read_bytes())
        q, r = job["query"], job["reference"]
        _, qfp, qp = inputs[q["record_id"]]
        _, rfp, rp = inputs[r["record_id"]]
        qid, rid = ("query", "reference") if row["condition"] == "A" else (q["graph_id"], r["graph_id"])
        pairs.check_result(result, qfp, rfp, qp, rp, qid, rid, row["condition"])
        require(row["query_graph_id"] == q["graph_id"] and row["reference_graph_id"] == r["graph_id"], "wrong matrix direction")
        require(row["primary_score"] == result["aggregate_multiset_similarity"], "score summary mismatch")
        require(row["aggregate_components"] == result["aggregate_components"], "component summary mismatch")
        require(row["views"] == {v: {k: result[v][k] for k in row["views"][v]} for v in pairs.VIEWS}, "view summary mismatch")
    return pairs.catalog.load_protocol(), matrix, catalog


def rank_query(query, condition, index):
    candidates = []
    seen = set()
    for candidate in query["candidates"]:
        reference = candidate["reference_graph_id"]
        require(reference not in seen and reference != query["query_graph_id"], "duplicate/self reference")
        seen.add(reference)
        require(candidate["label"] in {"equivalent", "non_equivalent"}, "unknown judgment")
        row = index.get((condition, candidate["pair_id"]))
        score = None
        if row is not None:
            pair = row["pair"]
            require({pair["left_graph_id"], pair["right_graph_id"]} == {query["query_graph_id"], reference}, "wrong judgment endpoints")
            require(pair["split"] == query["split"], "cross-split gallery")
            require(pair["equivalence_label"] == candidate["label"], "label tampering")
            score = row.get("primary_score") if row["status"] == "success" else None
            require(score is None or (type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1), "invalid score")
        candidates.append(dict(**candidate, score=score, score_record_id=row["record_id"] if row else None, orientation="forward" if row and row["query_graph_id"] == query["query_graph_id"] else "reverse_numeric_only" if row else "unavailable"))
    positives = sum(c["label"] == "equivalent" for c in candidates)
    require(positives == query["positive_count"] and len(candidates) == query["gallery_size"], "gallery counts mismatch")
    reason = "no_judged_positive" if not positives else "unavailable_candidate_score" if any(c["score"] is None for c in candidates) else None
    candidates.sort(key=(lambda c: c["reference_graph_id"]) if reason else (lambda c: (-c["score"], c["reference_graph_id"])))
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = None if reason else rank
    return dict(
        condition=condition,
        query_graph_id=query["query_graph_id"],
        split=query["split"],
        positive_count=positives,
        gallery_size=len(candidates),
        eligible=reason is None,
        reason=reason,
        candidates=candidates,
        top_k={str(k): [c["reference_graph_id"] for c in candidates[:k]] if reason is None and len(candidates) >= k else None for k in (1, 3, 5)},
    )


def galleries(protocol, matrix):
    index = {(r["condition"], r["pair"]["pair_id"]): r for r in matrix["records"]}
    require(len(index) == len(matrix["records"]), "duplicate score identity")
    records = []
    common = []
    for query in protocol["eligibility"]["queries"]:
        rows = [rank_query(query, condition, index) for condition in ("A", "B")]
        signatures = [{(c["reference_graph_id"], c["label"], c["pair_id"]) for c in row["candidates"]} for row in rows]
        require(signatures[0] == signatures[1], "condition gallery mismatch")
        compatible = all(matrix["paired_comparable_components"].get(c["pair_id"], False) for c in query["candidates"])
        paired = all(r["eligible"] for r in rows) and compatible
        if paired:
            common.append(query["query_graph_id"])
        for row in rows:
            row["paired_eligible"] = paired
        records.extend(rows)
    return dict(
        schema_version="0.1.0",
        matrix_sha256=pairs.sha(serialize(matrix)),
        protocol_sha256=pairs.catalog.exact_hash(ROOT / AUDIT_DIR / "protocol.json"),
        generator_utf8_lf_sha256=pairs.sha(Path(__file__).read_text(encoding="utf-8").encode()),
        records=records,
        common_query_ids=sorted(common),
        exclusions=protocol["eligibility"]["exclusions"],
    )


def publish(name, document):
    path = ROOT / AUDIT_DIR / name
    raw = serialize(document)
    if path.exists():
        require(path.read_bytes() == raw, "existing scientific output differs: " + name)
    else:
        with path.open("xb") as stream:
            stream.write(raw)
    print(name, "SHA256", pairs.sha(raw), flush=True)


def main():
    protocol, matrix, _ = admitted_scores()
    result = galleries(protocol, matrix)
    publish("judged_galleries.json", result)
    for split in protocol["design"]["cohort"]["splits"]:
        for condition in ("A", "B"):
            rows = [r for r in result["records"] if r["split"] == split and r["condition"] == condition]
            print(split, condition, "eligible", sum(r["eligible"] for r in rows), "common", sum(r["paired_eligible"] for r in rows), "K coverage", {k: sum(r["top_k"][str(k)] is not None for r in rows) for k in (1, 3, 5)}, flush=True)


if __name__ == "__main__":
    main()
