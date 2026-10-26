from copy import deepcopy
import pytest
from scripts import evaluation_stability as s
from tests.test_evaluation_galleries import case


def features(*items):
    return [dict(descriptor={"kind": key}, count=n) for key, n in items]


def test_churn_oracle():
    r = s.churn(features(("a", 2), ("b", 1)), features(("a", 1), ("c", 3)))
    assert r["presence"] == 2 / 3
    assert r["multiplicity"] == 5 / 6
    assert r["inserted_instances"] == 3 and r["deleted_instances"] == 2
    assert [c["kind"] for c in r["changes"]] == ["count_changed", "deleted", "inserted"]


def test_empty_and_order():
    assert s.churn([], [])["presence"] is None
    assert s.churn([], features(("motif", 1)))["multiplicity"] == 1
    a = features(("edge", 2), ("motif", 1))
    assert s.churn(a, list(reversed(a)))["multiplicity"] == 0


def rankings(scores=(0.9, 0.1)):
    q, idx = case(scores=scores)
    a, b = (s.g.rank_query(q, c, idx) for c in ("A", "B"))
    a["paired_eligible"] = b["paired_eligible"] = True
    return a, b


def test_reversed_ranking():
    a, b = rankings()
    b["candidates"].reverse()
    for c, score in zip(b["candidates"], (0.9, 0.1), strict=True):
        c["score"] = score
    b["top_k"]["1"] = ["r1"]
    r = s.rank_stability(a, b)
    assert r["normalized_rank_difference"] == 1 and r["spearman"] == -1
    assert r["top_k_overlap"] == {"1": 0, "3": None, "5": None}


def test_ties_constant():
    a, b = rankings((0.5, 0.5))
    r = s.rank_stability(a, b)
    assert r["spearman"] is None and r["normalized_rank_difference"] == 0
    assert s.tie_ranks(a["candidates"]) == {"r0": 1.5, "r1": 1.5}


def test_gallery_mismatch():
    a, b = rankings()
    b["candidates"].pop()
    with pytest.raises(ValueError, match="gallery"):
        s.rank_stability(a, b)


def test_unavailable():
    a, b = rankings()
    b["paired_eligible"] = False
    assert s.rank_stability(a, b)["status"] == "unsupported"


def test_singleton():
    q, idx = case(("equivalent",), (1,))
    a = s.g.rank_query(q, "A", idx)
    a["paired_eligible"] = True
    r = s.rank_stability(a, deepcopy(a))
    assert r["spearman"] is None and r["normalized_rank_difference"] == 0


def test_feature_ids_do_not_align_descriptors():
    left, right = features(("edge", 2)), features(("edge", 2))
    left[0]["id"], right[0]["id"] = "version-a", "version-b"
    assert s.churn(left, right)["multiplicity"] == 0


def test_incomplete_observation_is_preserved(monkeypatch):
    q, idx = case(("equivalent",), (1,))
    row = idx["A", "p0"]
    row.update(reference_graph_id="r0", views={v: dict(comparison_complete=False, warnings=["truncated"]) for v in s.g.pairs.VIEWS}, observability_warnings=["unknown_source"], input_motif_truncation={"query": True, "reference": True})
    row["pair"]["transformation_family"] = "dead_branch"
    catalog = {"records": [dict(condition="A", graph_id=gid) for gid in ("q", "r0")]}
    fp = {v + "_view": features(("edge", 1)) for v in s.g.pairs.VIEWS}
    monkeypatch.setattr(s.g.pairs, "load_input", lambda *args: ({}, fp, {}))
    result = s.evaluate({"records": [row]}, {"records": []}, catalog)
    record = result["churn"][0]
    assert record["observability_warnings"] == ["unknown_source"]
    assert record["comparison_completeness"]["rooted_topology"]["complete"] is False
    assert record["views"]["rooted_topology"]["multiplicity"] == 0
    assert "not proof" in record["interpretation"]
