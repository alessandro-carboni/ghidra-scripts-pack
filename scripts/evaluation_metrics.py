"""Step 10.6: preregistered query metrics and discovery-only thresholds."""

from fractions import Fraction
from pathlib import Path

try:
    from . import evaluation_galleries as g
except ImportError:
    import evaluation_galleries as g

require, serialize = g.require, g.serialize


def distribution(values):
    values = sorted(v for v in values if v is not None)

    def quantile(p):
        if not values:
            return None
        h = (len(values) - 1) * p
        i = int(h)
        return values[i] + (values[min(i + 1, len(values) - 1)] - values[i]) * (h - i)

    return dict(n=len(values), mean=sum(values) / len(values) if values else None, median=quantile(0.5), minimum=min(values) if values else None, maximum=max(values) if values else None, **{f"q{int(p * 100):02}": quantile(p) for p in (0.05, 0.25, 0.75, 0.95)})


def threshold(rows):
    require(all(r["pair"]["split"] == "discovery_train" for r in rows), "threshold may only read discovery")
    require(all(r["pair"]["equivalence_label"] in {"equivalent", "non_equivalent"} for r in rows), "unknown label")
    scored = [r for r in rows if r["status"] == "success" and r["primary_score"] is not None]
    positive = [r for r in scored if r["pair"]["equivalence_label"] == "equivalent"]
    negative = [r for r in scored if r["pair"]["equivalence_label"] == "non_equivalent"]
    binding = dict(
        selection_split="discovery_train",
        pair_ids=sorted(r["pair"]["pair_id"] for r in scored),
        calibration_sha256=g.pairs.sha(serialize(sorted([dict(pair_id=r["pair"]["pair_id"], label=r["pair"]["equivalence_label"], score=r["primary_score"]) for r in scored], key=lambda r: r["pair_id"]))),
        positive_n=len(positive),
        negative_n=len(negative),
    )
    if not positive or not negative:
        return dict(**binding, status="unsupported", reason="missing_class", value=None, reject_all=False, balanced_accuracy=None)
    choices = []
    for value in sorted({r["primary_score"] for r in scored}) + [None]:
        tp = sum(value is not None and r["primary_score"] >= value for r in positive)
        tn = sum(value is None or r["primary_score"] < value for r in negative)
        accuracy = (Fraction(tp, len(positive)) + Fraction(tn, len(negative))) / 2
        choices.append((accuracy, value is None, value))
    accuracy, reject_all, value = max(choices)
    return dict(**binding, status="supported", reason=None, value=value, reject_all=reject_all, balanced_accuracy=float(accuracy))


def calibrate(matrix):
    by_pair = {}
    for row in matrix["records"]:
        if row["pair"]["split"] == "discovery_train":
            by_pair.setdefault(row["pair"]["pair_id"], {})[row["condition"]] = row
    ids = sorted(pid for pid, rows in by_pair.items() if set(rows) == {"A", "B"} and matrix["paired_comparable_components"].get(pid, False) and all(r["status"] == "success" and r["primary_score"] is not None for r in rows.values()))
    return dict(schema_version="0.1.0", policy="discovery_only_max_balanced_accuracy_largest_threshold_tie", paired_calibration_ids=ids, conditions={c: threshold([by_pair[pid][c] for pid in ids]) for c in ("A", "B")})


def query_metrics(row):
    if not row["eligible"]:
        return dict(query_graph_id=row["query_graph_id"], reason=row["reason"], reciprocal_rank=None, false_top1=None, recall={str(k): None for k in (1, 3, 5)}, hit={str(k): None for k in (1, 3, 5)})
    candidates = row["candidates"]
    positive_ranks = [i for i, c in enumerate(candidates, 1) if c["label"] == "equivalent"]
    require(len(positive_ranks) == row["positive_count"] > 0, "invalid query relevance")
    return dict(
        query_graph_id=row["query_graph_id"],
        reason=None,
        reciprocal_rank=1 / positive_ranks[0],
        false_top1=int(positive_ranks[0] != 1),
        recall={str(k): sum(i <= k for i in positive_ranks) / len(positive_ranks) if len(candidates) >= k else None for k in (1, 3, 5)},
        hit={str(k): int(positive_ranks[0] <= k) if len(candidates) >= k else None for k in (1, 3, 5)},
    )


def retrieval(rows):
    values = [query_metrics(r) for r in rows]

    def mean_with_ids(key, k=None):
        available = [(r["query_graph_id"], r[key] if k is None else r[key][str(k)]) for r in values]
        available = [(qid, v) for qid, v in available if v is not None]
        return dict(value=sum(v for _, v in available) / len(available) if available else None, n=len(available), query_ids=sorted(qid for qid, _ in available), unsupported_n=len(rows) - len(available), reason=None if available else "no_supported_queries")

    return dict(query_n=len(rows), per_query=values, mrr=mean_with_ids("reciprocal_rank"), false_top1=mean_with_ids("false_top1"), recall={str(k): mean_with_ids("recall", k) for k in (1, 3, 5)}, hit={str(k): mean_with_ids("hit", k) for k in (1, 3, 5)})


def pair_summary(rows, cutoff):
    result = {}
    for label in ("equivalent", "non_equivalent"):
        selected = [r for r in rows if r["pair"]["equivalence_label"] == label]
        scored = [r for r in selected if r["status"] == "success" and r["primary_score"] is not None]
        result[label] = dict(
            pair_ids=sorted(r["pair"]["pair_id"] for r in selected),
            n=len(selected),
            noncomparable_n=len(selected) - len(scored),
            aggregate=distribution(r["primary_score"] for r in scored),
            views={v: {metric: distribution(r["views"][v][metric] for r in selected) for metric in ("set_similarity", "multiset_similarity")} for v in g.pairs.VIEWS},
        )
        if label == "non_equivalent":
            supported = cutoff["status"] == "supported" and bool(scored)
            false_ids = sorted(r["pair"]["pair_id"] for r in scored if supported and not cutoff["reject_all"] and r["primary_score"] >= cutoff["value"])
            result["false_match_rate"] = dict(value=len(false_ids) / len(scored) if supported else None, negative_n=len(scored), false_match_pair_ids=false_ids, reason=None if supported else "threshold_or_negative_cohort_unsupported")
    return result


def evaluate(protocol, matrix, galleries, thresholds):
    cells = []
    for split in protocol["design"]["cohort"]["splits"]:
        for condition in ("A", "B"):
            rows = [r for r in matrix["records"] if r["condition"] == condition and r["pair"]["split"] == split]
            queries = [r for r in galleries["records"] if r["condition"] == condition and r["split"] == split]
            cells.append(dict(split=split, condition=condition, pairwise=pair_summary(rows, thresholds["conditions"][condition]), retrieval=retrieval(queries), common_retrieval=retrieval([r for r in queries if r["paired_eligible"]])))
    return dict(
        schema_version="0.1.0",
        matrix_sha256=g.pairs.sha(serialize(matrix)),
        galleries_sha256=g.pairs.sha(serialize(galleries)),
        thresholds_sha256=g.pairs.sha(serialize(thresholds)),
        generator_utf8_lf_sha256=g.pairs.sha(Path(__file__).read_text(encoding="utf-8").encode()),
        scope="benign function equivalence; judged query-specific galleries, not open-world retrieval",
        cells=cells,
    )


def main():
    protocol, matrix, _ = g.admitted_scores()
    galleries = g.galleries(protocol, matrix)
    g.publish("judged_galleries.json", galleries)
    thresholds = calibrate(matrix)
    # Publish the discovery decision BEFORE evaluating validation or held-out metrics.
    g.publish("discovery_thresholds.json", thresholds)
    result = evaluate(protocol, matrix, galleries, thresholds)
    g.publish("primary_metrics.json", result)
    for cell in result["cells"]:
        r = cell["common_retrieval"]
        print(cell["split"], cell["condition"], "Recall", {k: (v["value"], v["n"]) for k, v in r["recall"].items()}, "MRR", r["mrr"]["value"], "FPR", cell["pairwise"]["false_match_rate"]["value"], flush=True)


if __name__ == "__main__":
    main()
