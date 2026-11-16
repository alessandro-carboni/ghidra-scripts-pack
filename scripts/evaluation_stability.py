"""Step 10.7: exact within-condition feature churn and matched-gallery rank stability."""

import json
import math
from pathlib import Path

try:
    from . import evaluation_metrics as m
except ImportError:
    import evaluation_metrics as m

g = m.g
require, serialize = g.require, g.serialize


def churn(left, right):
    g.pairs.oracle(left, right)  # Also enforces unique descriptors and positive counts.
    a = {serialize(f["descriptor"]): f["count"] for f in left}
    b = {serialize(f["descriptor"]): f["count"] for f in right}
    union = sorted(a.keys() | b.keys())
    changed = [dict(descriptor=json.loads(k), left_count=a.get(k, 0), right_count=b.get(k, 0), delta=b.get(k, 0) - a.get(k, 0), kind="inserted" if k not in a else "deleted" if k not in b else "count_changed") for k in union if a.get(k, 0) != b.get(k, 0)]
    instances = sum(abs(a.get(k, 0) - b.get(k, 0)) for k in union)
    denominator = sum(max(a.get(k, 0), b.get(k, 0)) for k in union)
    return dict(
        presence=len(a.keys() ^ b.keys()) / len(union) if union else None,
        multiplicity=instances / denominator if denominator else None,
        reason=None if union else "empty_both",
        union_descriptors=len(union),
        changed_descriptors=len(changed),
        changed_instances=instances,
        union_instances=denominator,
        inserted_instances=sum(max(r["delta"], 0) for r in changed),
        deleted_instances=sum(max(-r["delta"], 0) for r in changed),
        changes=changed,
    )


def tie_ranks(candidates):
    scores = {}
    for row in candidates:
        scores.setdefault(row["score"], []).append(row["reference_graph_id"])
    ranks, offset = {}, 1
    for score in sorted(scores, reverse=True):
        ids = scores[score]
        rank = offset + (len(ids) - 1) / 2
        ranks.update({gid: rank for gid in ids})
        offset += len(ids)
    return ranks


def rank_stability(a, b):
    require(a["query_graph_id"] == b["query_graph_id"] and a["split"] == b["split"], "different query or split")
    signatures = [{(c["reference_graph_id"], c["label"]) for c in r["candidates"]} for r in (a, b)]
    require(signatures[0] == signatures[1] and len(signatures[0]) == len(a["candidates"]) == len(b["candidates"]), "gallery mismatch")
    if not a["paired_eligible"] or not b["paired_eligible"]:
        return dict(status="unsupported", reason="query_not_in_common_scored_cohort", normalized_rank_difference=None, spearman=None, top_k_overlap={str(k): None for k in (1, 3, 5)})
    n = len(a["candidates"])
    ar, br = ({c["reference_graph_id"]: i for i, c in enumerate(r["candidates"], 1)} for r in (a, b))
    at, bt = (tie_ranks(r["candidates"]) for r in (a, b))
    mean = (n + 1) / 2
    covariance = sum((at[k] - mean) * (bt[k] - mean) for k in at)
    variance = math.sqrt(sum((v - mean) ** 2 for v in at.values()) * sum((v - mean) ** 2 for v in bt.values()))
    return dict(
        status="supported",
        reason=None,
        normalized_rank_difference=sum(abs(ar[k] - br[k]) for k in ar) / (n * (n - 1)) if n > 1 else 0.0,
        spearman=covariance / variance if variance else None,
        correlation_reason=None if variance else "singleton_or_constant_tie_ranks",
        top_k_overlap={str(k): len(set(a["top_k"][str(k)]) & set(b["top_k"][str(k)])) / k if n >= k else None for k in (1, 3, 5)},
    )


def evaluate(matrix, galleries, catalog):
    inputs = {(r["condition"], r["graph_id"]): g.pairs.load_input(r, g.pairs.CATALOG)[1] for r in catalog["records"]}
    changes = []
    for row in matrix["records"]:
        if row["pair"]["equivalence_label"] != "equivalent":
            continue
        q, r = (inputs[row["condition"], row[key]] for key in ("query_graph_id", "reference_graph_id"))
        views = {v: churn(q[v + "_view"], r[v + "_view"]) for v in g.pairs.VIEWS}
        changes.append(
            dict(
                condition=row["condition"],
                pair=row["pair"],
                score_record_id=row["record_id"],
                views=views,
                observability_warnings=row["observability_warnings"],
                motif_truncation=row["input_motif_truncation"],
                comparison_completeness={v: dict(complete=row["views"][v]["comparison_complete"], warnings=row["views"][v]["warnings"]) for v in g.pairs.VIEWS},
                interpretation="Differences in observed descriptors only; missing/truncated evidence is not proof of semantic absence.",
            )
        )
    index = {(r["condition"], r["query_graph_id"]): r for r in galleries["records"]}
    ranks = [dict(query_graph_id=qid, split=index["A", qid]["split"], dimension="A_vs_B", **rank_stability(index["A", qid], index["B", qid])) for qid in sorted(q for c, q in index if c == "A")]
    summaries = []
    for condition in ("A", "B"):
        for split in sorted({r["pair"]["split"] for r in changes}):
            families = sorted({r["pair"]["transformation_family"] for r in changes if r["pair"]["split"] == split})
            for family in [None] + families:
                rows = [r for r in changes if r["condition"] == condition and r["pair"]["split"] == split and (family is None or r["pair"]["transformation_family"] == family)]
                summaries.append(
                    dict(
                        condition=condition,
                        split=split,
                        family=family,
                        pair_n=len(rows),
                        views={v: {metric: m.distribution(r["views"][v][metric] for r in rows) for metric in ("presence", "multiplicity")} for v in g.pairs.VIEWS},
                        total_changed_instances=sum(r["views"][v]["changed_instances"] for r in rows for v in g.pairs.VIEWS),
                    )
                )
    return dict(
        schema_version="0.1.0",
        matrix_sha256=g.pairs.sha(serialize(matrix)),
        galleries_sha256=g.pairs.sha(serialize(galleries)),
        generator_utf8_lf_sha256=g.pairs.sha(Path(__file__).read_text(encoding="utf-8").encode()),
        churn=changes,
        summaries=summaries,
        rank_stability=ranks,
        cross_condition_feature_churn=dict(status="unsupported", reason="No approved mapping between lexical A and semantic B descriptors; version-dependent feature IDs never aligned."),
        secondary_rank_dimensions=dict(status="unsupported", reason="No preregistered identical-reference mapping for compiler/optimization/Step9 dimensions. Step9 remains a separate optional discovery cohort; two anchors in one PE are not independent binaries."),
    )


def main():
    protocol, matrix, catalog = g.admitted_scores()
    galleries = g.galleries(protocol, matrix)
    g.publish("judged_galleries.json", galleries)
    result = evaluate(matrix, galleries, catalog)
    g.publish("feature_rank_stability.json", result)
    supported = [r for r in result["rank_stability"] if r["status"] == "supported"]
    print("Equivalent pair-condition churn:", len(result["churn"]), "matched rankings:", len(supported), "rank difference:", m.distribution(r["normalized_rank_difference"] for r in supported), flush=True)


if __name__ == "__main__":
    main()
