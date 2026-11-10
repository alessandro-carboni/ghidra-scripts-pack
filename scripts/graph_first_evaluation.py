"""Graph-first study metrics. Labels enter evaluation only, never fingerprints."""

from collections import defaultdict
import math

try:
    from .evaluate_operational_baseline import calibrate, metrics
except ImportError:
    from evaluate_operational_baseline import calibrate, metrics

CONDITIONS = ("A", "B", "C", "D", "E")
K = (1, 3, 5)


def roc(rows, maximum=0.05):
    usable = [r for r in rows if r["score"] is not None]
    pos = sum(r["positive"] for r in usable)
    neg = len(usable) - pos
    if not pos or not neg:
        return dict(auc=None, partial_auc=None, partial_interval=[0, maximum], partial_normalization="raw area, maximum=interval width")
    groups = defaultdict(list)
    for row in usable:
        groups[row["score"]].append(row["positive"])
    tp = fp = 0
    points = [(0.0, 0.0)]
    for score in sorted(groups, reverse=True):
        tp += sum(groups[score])
        fp += len(groups[score]) - sum(groups[score])
        points.append((fp / neg, tp / pos))
    area = partial = 0.0
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        area += (x1 - x0) * (y0 + y1) / 2
        end = min(x1, maximum)
        if x0 < end:
            y = y0 + (y1 - y0) * (end - x0) / (x1 - x0)
            partial += (end - x0) * (y0 + y) / 2
    return dict(auc=area, partial_auc=partial, partial_interval=[0, maximum], partial_normalization="raw area, maximum=interval width")


def rank(rows, condition, k=5):
    """E only reorders available operational slots within graph top-k.

    Missing operational evidence keeps its graph rank; no automatic penalty.
    Graph scores stay unchanged. The remaining gallery stays inspectable.
    """
    rows = sorted(rows, key=lambda r: (r["score"] is None, -(r["score"] or 0), r["reference"]))
    if condition != "E":
        return rows
    slots = [i for i, r in enumerate(rows[:k]) if r["score"] is not None and r["operational"] is not None]
    refined = sorted((rows[i] for i in slots), key=lambda r: (-r["operational"], -(r["score"] or 0), r["reference"]))
    for i, row in zip(slots, refined):
        rows[i] = row
    return rows


def retrieval(rows, condition, k=5):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["query"]].append(row)
    outputs = []
    for query, gallery in sorted(grouped.items()):
        positives = sum(r["positive"] for r in gallery)
        if not positives:
            continue
        ranked = rank(gallery, condition, k)
        usable = [r for r in ranked if r["score"] is not None]
        first = next((i for i, r in enumerate(usable, 1) if r["positive"]), None)
        available_positive = [r["score"] for r in usable if r["positive"]]
        negatives = [r["score"] for r in usable if not r["positive"]]
        tie_lower = tie_upper = 0.0
        if available_positive:
            best = max(available_positive)
            above = sum(r["score"] > best for r in usable)
            tied_negative = sum(r["score"] == best and not r["positive"] for r in usable)
            tie_lower, tie_upper = 1 / (above + tied_negative + 1), 1 / (above + 1)
        outputs.append(
            dict(
                query=query,
                candidates=len(gallery),
                true_references=positives,
                mrr=1 / first if first else 0,
                recall_at_k={str(n): sum(r["positive"] for r in usable[:n]) / positives for n in K},
                graph_tie_mrr_bounds=[tie_lower, tie_upper],
                tie_frequency=int(len({r["score"] for r in usable}) != len(usable)),
                margin=max(available_positive) - max(negatives) if available_positive and negatives else None,
                excluded_before_refinement=positives - sum(r["positive"] for r in rank(gallery, "B")[:k] if r["score"] is not None),
                candidate_recall_at_k={str(n): sum(r["positive"] for r in rank(gallery, "B")[:n] if r["score"] is not None) / positives for n in K},
            )
        )

    def mean(values):
        return sum(values) / len(values) if values else None

    return dict(
        queries=outputs,
        query_count=len(outputs),
        mrr=mean([r["mrr"] for r in outputs]),
        recall_at_k={str(n): mean([r["recall_at_k"][str(n)] for r in outputs]) for n in K},
        graph_tie_mrr_bounds=[mean([r["graph_tie_mrr_bounds"][i] for r in outputs]) for i in (0, 1)],
        queries_with_ties=sum(r["tie_frequency"] for r in outputs),
        excluded_true_references_before_refinement=sum(r["excluded_before_refinement"] for r in outputs),
        candidate_recall_at_k={str(n): mean([r["candidate_recall_at_k"][str(n)] for r in outputs]) for n in K},
    )


def summarize(pairs):
    result = {}
    for condition in CONDITIONS:
        rows = pairs[condition]
        discovery = [r for r in rows if r["split"] == "discovery"]
        threshold = calibrate(discovery) if any(r["positive"] and r["score"] is not None for r in discovery) and any(not r["positive"] and r["score"] is not None for r in discovery) else math.nextafter(1, 2)
        result[condition] = dict(discovery_threshold=threshold, splits={})
        for split in ("discovery", "validation", "heldout"):
            selected = [r for r in rows if r["split"] == split]
            result[condition]["splits"][split] = dict(
                classification=metrics(selected, threshold),
                continuous=roc(selected),
                retrieval=retrieval(selected, condition),
                same_family=metrics([r for r in selected if r["same_family"]], threshold),
                cross_family=metrics([r for r in selected if not r["same_family"]], threshold),
                structural_collision_count=sum(not r["positive"] and r["score"] == 1 for r in selected),
                positive_mean=sum(r["score"] for r in selected if r["positive"] and r["score"] is not None) / sum(r["positive"] and r["score"] is not None for r in selected) if any(r["positive"] and r["score"] is not None for r in selected) else None,
            )
    return result
