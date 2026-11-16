from copy import deepcopy
import pytest
from scripts import evaluation_metrics as m
from scripts import evaluation_galleries as g
from tests.test_evaluation_galleries import case


def test_query_hand_oracle():
    q, idx = case(("non_equivalent", "equivalent", "equivalent"), (1, 0.8, 0.4))
    v = m.query_metrics(g.rank_query(q, "A", idx))
    assert v["reciprocal_rank"] == 0.5
    assert v["recall"] == {"1": 0, "3": 1, "5": None}
    assert v["hit"] == {"1": 0, "3": 1, "5": None}
    assert v["false_top1"] == 1


def test_recall_is_not_hit():
    q, idx = case(("equivalent", "equivalent"), (1, 0.5))
    v = m.query_metrics(g.rank_query(q, "A", idx))
    assert v["recall"]["1"] == 0.5 and v["hit"]["1"] == 1


def test_macro_query_denominator():
    q, idx = case()
    row = g.rank_query(q, "A", idx)
    missing = deepcopy(row)
    missing.update(query_graph_id="missing", eligible=False, reason="unavailable_candidate_score")
    result = m.retrieval([row, missing])
    assert result["mrr"]["value"] == 1 and result["mrr"]["n"] == 1
    assert result["recall"]["3"]["value"] is None


@pytest.mark.parametrize("labels", [("equivalent",), ("non_equivalent",), ()])
def test_missing_class(labels):
    _, idx = case(labels, (0.5,) * len(labels))
    result = m.threshold([r for (c, _), r in idx.items() if c == "A"])
    assert result["status"] == "unsupported"


def test_threshold_hand_oracle_and_tie():
    _, idx = case(scores=(0.9, 0.1))
    rows = [r for (c, _), r in idx.items() if c == "A"]
    assert m.threshold(rows)["value"] == 0.9
    rows[0]["primary_score"] = 0.1
    assert m.threshold(rows)["reject_all"]


def test_non_discovery_rejected():
    _, idx = case()
    row = idx["A", "p0"]
    row["pair"]["split"] = "held_out_test"
    with pytest.raises(ValueError, match="discovery"):
        m.threshold([row])


def test_heldout_cannot_change_threshold():
    _, idx = case()
    matrix = dict(records=list(idx.values()), paired_comparable_components={"p0": True, "p1": True})
    first = m.calibrate(matrix)
    held = deepcopy(matrix["records"])
    for r in held:
        r["pair"]["split"] = "held_out_test"
        r["primary_score"] = 1 - r["primary_score"]
    matrix["records"] += held
    assert m.calibrate(matrix) == first


def test_quantiles():
    d = m.distribution([0, 1, None])
    assert d["median"] == 0.5 and d["q25"] == 0.25 and d["q95"] == 0.95
    assert m.distribution([])["mean"] is None


def test_paired_calibration_missing_component():
    _, idx = case()
    matrix = dict(records=list(idx.values()), paired_comparable_components={"p0": False, "p1": True})
    result = m.calibrate(matrix)
    assert result["paired_calibration_ids"] == ["p1"]
    assert all(v["status"] == "unsupported" for v in result["conditions"].values())
