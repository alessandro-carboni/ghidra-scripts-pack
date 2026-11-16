"""Scientific comparison mathematics; no tuning on the evaluation data."""

import pytest

from scripts.evaluate_operational_baseline import calibrate, metrics, retrieval


def test_calibration_uses_declared_tie_policy_and_denominators():
    pairs = [dict(positive=True, score=0.8), dict(positive=True, score=0.9), dict(positive=False, score=0.2), dict(positive=False, score=0.3)]
    threshold = calibrate(pairs)
    assert threshold == 0.8
    assert metrics(pairs, threshold)["balanced_accuracy"] == 1
    assert metrics(pairs + [dict(positive=True, score=None)], threshold)["nulls"] == 1
    with pytest.raises(ValueError, match="comparable"):
        calibrate([dict(positive=True, score=None), dict(positive=False, score=0.5)])


def test_retrieval_rejects_positive_only_galleries_and_stable_ties():
    cases = [dict(id=n) for n in "abc"]
    pairs = [dict(query="a", reference="b", positive=True, score=0.5), dict(query="a", reference="c", positive=False, score=0.5)]
    result = retrieval(cases, pairs)
    assert result["mixed_queries"] == 1
    assert result["mrr"] == 1
    assert result["queries_with_ties"] == 1
    assert result["recall_at_k"]["1"] == 1
