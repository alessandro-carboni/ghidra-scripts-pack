"""Final gates reject incomplete observations, altered replay and replacement freezes."""

from pathlib import Path
import pytest
from scripts import evaluation_acceptance as a
from scripts import evaluation_replay as replay


def test_freeze_is_immutable(tmp_path):
    folder = tmp_path / "freezes/freeze-001"
    a.freeze(folder, {"status": "PASS"}, "report\n", [])
    before = (folder / "scientific_manifest.json").read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        a.freeze(folder, {"status": "changed"}, "replacement", [])
    assert (folder / "scientific_manifest.json").read_bytes() == before


def test_replay_compares_bytes_and_inventory(tmp_path):
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    (left / "x").write_bytes(b"original")
    (right / "x").write_bytes(b"original")
    assert set(replay.compare_trees(left, right)) == {"x"}
    (right / "x").write_bytes(b"changed")
    with pytest.raises(ValueError, match="bytes differ"):
        replay.compare_trees(left, right)
    (right / "extra").write_bytes(b"")
    with pytest.raises(ValueError, match="inventory"):
        replay.compare_trees(left, right)


def test_missing_runtime_cohort_rejected():
    protocol, matrix, catalog = {}, {"records": []}, {"records": []}
    observation = dict(
        status="PASS", generator_utf8_lf_sha256=a.g.pairs.sha(Path(a.runtime.__file__).read_text(encoding="utf-8").encode()), protocol_sha256=a.g.pairs.sha(a.serialize(protocol)), matrix_sha256=a.g.pairs.sha(a.serialize(matrix)), catalog_sha256=a.g.pairs.sha(a.serialize(catalog)), observations=[], summary=[]
    )
    with pytest.raises(ValueError, match="cohort"):
        a.check_observation(observation, protocol, matrix, catalog)


def test_partial_benchmark_cannot_pass():
    with pytest.raises(ValueError, match="incomplete"):
        a.check_observation({"status": "INCOMPLETE"}, {}, {}, {})
