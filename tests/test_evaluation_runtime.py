import subprocess
import pytest
from scripts import evaluation_runtime as r


def test_timer_and_failure():
    ticks = iter([10, 25])
    value, result = r.timed(lambda: 3, lambda: next(ticks))
    assert value == 3 and result["elapsed_ns"] == 15

    def failure():
        raise ValueError("bad subprocess")

    assert r.timed(failure)[1]["status"] == "failed"

    def timeout():
        raise subprocess.TimeoutExpired("engine", 120)

    assert r.timed(timeout)[1]["reason"] == "timeout"


def test_summary_warmup_oracle():
    rows = [dict(repetition=i, condition="A", stage="ranking", id="all", warmup=i == 0, status="success", elapsed_ns=n) for i, n in enumerate([999999999, 1000000, 3000000])]
    keys = [(r["repetition"], r["condition"], r["stage"], r["id"]) for r in rows]
    summary = r.summarize(rows, keys)[0]
    assert summary["attempted_n"] == 2
    assert summary["milliseconds"]["median"] == 2
    assert summary["milliseconds"]["q25"] == 1.5
    with pytest.raises(ValueError, match="cohort"):
        r.summarize(rows[:-1], keys)
    rows[0]["warmup"] = False
    with pytest.raises(ValueError, match="warmup"):
        r.summarize(rows, keys)


def test_negative_clock_rejected():
    ticks = iter([20, 10])
    with pytest.raises(ValueError, match="nonmonotonic"):
        r.timed(lambda: None, lambda: next(ticks))


def test_failed_measurement_disclosed():
    row = dict(repetition=1, condition="B", stage="ranking", id="all", warmup=False, status="failed", elapsed_ns=100)
    result = r.summarize([row], [(1, "B", "ranking", "all")])[0]
    assert result["failure_n"] == 1 and result["milliseconds"]["n"] == 0
