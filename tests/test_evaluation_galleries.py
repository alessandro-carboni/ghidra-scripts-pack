from copy import deepcopy
import pytest
from scripts import evaluation_galleries as g


def case(labels=("equivalent", "non_equivalent"), scores=(0.9, 0.1)):
    candidates = []
    index = {}
    for i, (label, score) in enumerate(zip(labels, scores, strict=True)):
        ref, pid = f"r{i}", f"p{i}"
        candidates.append(dict(reference_graph_id=ref, pair_id=pid, label=label))
        for condition in ("A", "B"):
            index[condition, pid] = dict(condition=condition, record_id=condition + pid, pair=dict(pair_id=pid, left_graph_id="q", right_graph_id=ref, split="discovery_train", equivalence_label=label), status="success", primary_score=score, query_graph_id="q")
    return dict(query_graph_id="q", split="discovery_train", candidates=candidates, positive_count=labels.count("equivalent"), gallery_size=len(labels)), index


@pytest.mark.parametrize("scores,first", [((1, 0), "r0"), ((0, 1), "r1"), ((0.5, 0.5), "r0")])
def test_ranking(scores, first):
    q, idx = case(scores=scores)
    row = g.rank_query(q, "A", idx)
    assert row["top_k"] == {"1": [first], "3": None, "5": None}
    assert [c["rank"] for c in row["candidates"]] == [1, 2]


@pytest.mark.parametrize("labels", [(), ("non_equivalent",), ("equivalent",), ("equivalent", "equivalent")])
def test_positives(labels):
    q, idx = case(labels, (0.5,) * len(labels))
    result = g.rank_query(q, "A", idx)
    assert result["eligible"] == ("equivalent" in labels)
    assert result["positive_count"] == labels.count("equivalent")


@pytest.mark.parametrize("missing", [True, False])
def test_missing_not_zero(missing):
    q, idx = case()
    if missing:
        del idx["A", "p1"]
    else:
        idx["A", "p1"]["primary_score"] = None
    row = g.rank_query(q, "A", idx)
    assert row["reason"] == "unavailable_candidate_score"
    assert all(c["rank"] is None for c in row["candidates"])
    assert len(row["candidates"]) == 2


@pytest.mark.parametrize("fault", ["duplicate", "unknown", "split", "label", "endpoint", "nan"])
def test_reject(fault):
    q, idx = case()
    if fault == "duplicate":
        q["candidates"].append(deepcopy(q["candidates"][0]))
    elif fault == "unknown":
        q["candidates"][0]["label"] = "unknown"
    elif fault == "split":
        idx["A", "p0"]["pair"]["split"] = "held_out_test"
    elif fault == "label":
        idx["A", "p0"]["pair"]["equivalence_label"] = "non_equivalent"
    elif fault == "endpoint":
        idx["A", "p0"]["pair"]["left_graph_id"] = "elsewhere"
    else:
        idx["A", "p0"]["primary_score"] = float("nan")
    with pytest.raises(ValueError):
        g.rank_query(q, "A", idx)


def test_common_cohort_and_no_unknown_backfill():
    q, idx = case()
    protocol = {"eligibility": {"queries": [q], "exclusions": []}}
    matrix = dict(records=list(idx.values()), paired_comparable_components={"p0": True, "p1": True})
    result = g.galleries(protocol, matrix)
    assert result["common_query_ids"] == ["q"]
    assert all(len(r["candidates"]) == 2 for r in result["records"])
    idx["B", "p0"]["primary_score"] = None
    result = g.galleries(protocol, matrix)
    assert result["common_query_ids"] == []
    assert result["records"][0]["eligible"]
    assert not result["records"][1]["eligible"]


def test_reverse_numeric_binding():
    q, idx = case()
    row = idx["A", "p0"]
    row["query_graph_id"] = "r0"
    row["pair"]["left_graph_id"], row["pair"]["right_graph_id"] = "r0", "q"
    result = g.rank_query(q, "A", idx)
    assert result["candidates"][0]["orientation"] == "reverse_numeric_only"
    assert result["candidates"][0]["score_record_id"] == "Ap0"
