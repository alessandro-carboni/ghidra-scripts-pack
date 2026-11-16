"""Independent numerical checks for descriptive reports, not new scoring rules."""

import pytest

from scripts import reference_diagnostics as d


def test_distribution_retains_nulls_and_exact_empirical_counts():
    result = d.distribution([None, 0, 0.5, 0.5, 1])
    assert result["total"] == 5 and result["comparable"] == 4 and result["unavailable"] == 1
    assert result["mean"] == 0.5
    assert result["empirical_distribution"] == [dict(score=0, count=1), dict(score=0.5, count=2), dict(score=1, count=1)]
    assert d.distribution([None])["mean"] is None


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), -1, 1.1])
def test_invalid_score_cannot_enter_report(value):
    with pytest.raises(ValueError, match="invalid"):
        d.distribution([value])


def test_ordering_counts_ties_and_inversions_without_thresholds():
    rows = [dict(query="q", reference=str(i), score=s, positive=p, hard_negative=not p, operational=None, split="validation", group="family") for i, (s, p) in enumerate([(0.2, True), (0.8, True), (0.2, False), (0.5, False), (None, True)])]
    result = d.scores(rows, "D")
    assert result["positive_negative_ordering"] == dict(pair_comparisons=4, positive_below_negative=1, equal=1, positive_above_negative=2, inversion_rate=0.25)
    assert result["positive"]["unavailable"] == 1
    groups = d.grouped(rows, "D", ("split", "group"))
    assert len(groups) == 1 and groups[0]["group"] == dict(split="validation", group="family")
    assert "threshold" not in result
