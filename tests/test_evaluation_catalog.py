"""Step 10.3 catalog coverage, strict cache identity, provenance and publication."""

import copy
import json
from pathlib import Path

import pytest

from scripts import evaluation_catalog as ec


@pytest.fixture(scope="module")
def planned():
    if not ec.ENGINE.is_file() or not ec.executable().is_file():
        pytest.skip("build frozen and approved research engines; catalog integration NOT RUN")
    return ec.plan()


def test_complete_real_plan_deterministic_and_distinct_provenance(planned):
    assert ec.serialize(ec.plan()) == ec.serialize(planned)
    assert planned["graph_count"] == 120
    rows = planned["records"]
    assert len(rows) == len({r["record_id"] for r in rows}) == 240
    assert {r["graph_id"] for r in rows if r["condition"] == "A"} == {r["graph_id"] for r in rows if r["condition"] == "B"}
    assert len({r["canonical_digest"] for r in rows}) < 120
    assert len({r["canonical_path"] for r in rows}) == 120
    assert not any(k in r for r in rows for k in ("label", "equivalence_label", "score"))
    assert str(ec.ROOT) not in ec.serialize(planned).decode()


def test_real_produce_readonly_deterministic_and_both_formats(planned, tmp_path):
    for row in planned["records"][:2]:
        source = ec.ROOT / row["canonical_path"]
        before = source.read_bytes()
        first = ec.produce(row, tmp_path / "first")
        second = ec.produce(row, tmp_path / "second")
        assert first == second and first["status"] == "success"
        assert source.read_bytes() == before
        assert len(first["artifacts"]) == 2
        assert first["fingerprint_version"] == ("research-0.1.0" if row["condition"] == "A" else "0.1.0")


@pytest.mark.parametrize("attack", ["hash", "local", "path", "condition"])
def test_invalid_sources_not_admitted(planned, tmp_path, attack):
    row = copy.deepcopy(planned["records"][0])
    if attack == "hash":
        row["canonical_sha256"] = "0" * 64
    elif attack == "local":
        row["local_serialization_sha256"] = "0" * 64
    elif attack == "path":
        row["canonical_path"] = "../outside.json"
    else:
        row["condition"] = "C"
    with pytest.raises(ValueError):
        ec.produce(row, tmp_path)
    assert not list(tmp_path.iterdir())
    if attack == "path":
        # An absent canonical file fails before creating even a partial artifact.
        with pytest.raises(FileNotFoundError):
            ec.produce(planned["records"][0], tmp_path, root=tmp_path)
        assert not list(tmp_path.iterdir())


def small_plan(planned, monkeypatch):
    subset = copy.deepcopy(planned)
    subset["records"] = subset["records"][:2]
    subset["graph_count"] = 1
    monkeypatch.setattr(ec, "plan", lambda *args: subset)
    return subset


def test_atomic_publication_collision_and_verified_replay(planned, tmp_path, monkeypatch):
    subset = small_plan(planned, monkeypatch)
    destination = tmp_path / "catalog"
    report = ec.materialize(subset, destination)
    assert report["status"] == "PASS"
    assert ec.verify(destination, subset) == report
    with pytest.raises(ValueError, match="collision"):
        ec.materialize(subset, destination)
    assert not list(tmp_path.glob(".catalog-stage-*"))
    stale = copy.deepcopy(subset)
    stale["identity"]["generator_version"] = "stale"
    with pytest.raises(ValueError, match="stale"):
        ec.verify(destination, stale)


@pytest.mark.parametrize("attack", ["bytes", "missing", "sidecar", "metadata", "extra", "version"])
def test_cache_corruption_rejected(planned, tmp_path, monkeypatch, attack):
    subset = small_plan(planned, monkeypatch)
    destination = tmp_path / "catalog"
    report = ec.materialize(subset, destination)
    item = report["records"][1]["artifacts"][1]
    path = destination / item["path"]
    if attack == "bytes":
        path.write_bytes(path.read_bytes() + b" ")
    elif attack == "missing":
        path.unlink()
    elif attack == "sidecar":
        value = json.loads(path.read_bytes())
        value["source_document"]["seed_id"] = "wrong-source"
        path.write_bytes(ec.serialize(value))
        item.update(ec.artifact(destination, path))  # hash-consistent corruption still fails reconstruction
    elif attack == "metadata":
        report["records"][0]["semantic_digest"] = "invented"
    elif attack == "extra":
        (destination / "unlisted.json").write_text("{}")
    else:
        report["schema_version"] = "future"
    (destination / "catalog.json").write_bytes(ec.serialize(report))
    with pytest.raises((ValueError, FileNotFoundError)):
        ec.verify(destination, subset)


def test_failure_cannot_publish_pass_and_abort_is_atomic(planned, tmp_path, monkeypatch):
    subset = small_plan(planned, monkeypatch)
    destination = tmp_path / "incomplete"
    monkeypatch.setattr(ec, "run", lambda *args: (_ for _ in ()).throw(ValueError("rejected")))
    report = ec.materialize(subset, destination)
    assert report["status"] == "INCOMPLETE"
    assert len(report["records"]) == 2 and all(r["status"] == "failed" and not r["artifacts"] for r in report["records"])
    with pytest.raises(ValueError, match="incomplete"):
        ec.verify(destination, subset)
    other = tmp_path / "aborted"
    monkeypatch.setattr(ec, "produce", lambda *args: (_ for _ in ()).throw(OSError("disk failure")))
    with pytest.raises(OSError):
        ec.materialize(subset, other)
    assert not other.exists()
    assert not list(tmp_path.glob(".catalog-stage-*"))


def test_stale_approval_rejected(tmp_path):
    folder = tmp_path / ec.AUDIT_DIR / "research_adapter"
    folder.mkdir(parents=True)
    (folder / "gate_evidence.json").write_text("{}")
    (folder / "approval.json").write_bytes(ec.serialize(dict(status="approved", gate_evidence_sha256="wrong")))
    with pytest.raises(ValueError, match="approval stale"):
        ec.method_approval(tmp_path)


def test_dry_plan_has_no_output_side_effects(planned, tmp_path, monkeypatch):
    monkeypatch.setattr(ec, "plan", lambda: planned)
    monkeypatch.setattr(ec, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["evaluation_catalog.py", "--dry-run"])
    ec.main()
    assert not list(Path(tmp_path).iterdir())
