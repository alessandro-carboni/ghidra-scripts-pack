import copy
import json

import pytest

from scripts.step9_preflight import ROOT
from scripts.transformation_harness import run_pipeline
from scripts.transformation_report import compose_report, markdown
from scripts.transformation_schema import serialize


@pytest.fixture
def data():
    # Report tests do not require local compilers or pretend these fixtures are real extraction.
    run = dict(run_id="fixture", statuses={phase: "passed" for phase in ("generation", "build", "extraction", "mapping", "validation")}, experiment_configuration={})
    bundle = dict(runs=[run], frozen_dataset_reference={"scientific_digest": "fixture"}, specifications=[], executions=[], builds=[], behaviors=[], graphs=[], mappings=[])
    validation = dict(observation_contract="structural-calls-v2", run_id="fixture", acceptance_status="passed", split_validation="passed", family_holdouts=[], deterministic_checks={})
    return bundle, validation


def test_reporting_is_deterministic_and_does_not_mutate(data):
    bundle, validation = data
    before = copy.deepcopy(bundle)
    first = compose_report(bundle, validation)
    assert serialize(first) == serialize(compose_report(bundle, validation))
    assert markdown(first) == markdown(compose_report(bundle, validation))
    assert b"not equivalence scores" in markdown(first)
    assert first["fresh_end_to_end_replay"]["status"] == "not_run"
    assert bundle == before


@pytest.mark.parametrize("failure", ["missing_validation", "failed_phase", "wrong_run", "unavailable"])
def test_report_cannot_hide_missing_or_failed_validation(data, failure):
    bundle, validation = data
    if failure == "missing_validation":
        validation = None
    elif failure == "wrong_run":
        validation["run_id"] = "other"
    else:
        bundle["runs"][0]["statuses"]["build"] = "failed"
        if failure == "unavailable":
            bundle["builds"] = [dict(build_id="b", execution_id="none", build_status="unavailable", build_diagnostics=["compiler unavailable"])]
    report = compose_report(bundle, validation)
    assert report["acceptance_status"] == ("blocked" if failure == "unavailable" else "not_accepted")
    assert report["split_validation"] == "not_verified"


def test_replay_evidence_must_be_complete(data):
    bundle, validation = data
    with pytest.raises(ValueError, match="replay"):
        compose_report(bundle, validation, dict(run_id="fixture", status="passed", checks={}))


def test_pipeline_stops_after_failed_build_and_reports(monkeypatch, data):
    from scripts import transformation_harness, transformation_build, transformation_extraction, transformation_report

    bundle, _ = data
    calls = []
    monkeypatch.setattr(transformation_harness, "generate_run", lambda config: (ROOT, bundle))

    def build(path):
        calls.append("build")
        bundle["runs"][0]["statuses"]["build"] = "failed"
        return bundle

    monkeypatch.setattr(transformation_build, "build_run", build)
    monkeypatch.setattr(transformation_extraction, "extract_run", lambda *args: pytest.fail("extraction after failed build"))
    monkeypatch.setattr(transformation_report, "report_run", lambda *args: calls.append("report"))
    with pytest.raises(ValueError, match="build incomplete"):
        run_pipeline({}, "ghidra", "engine", {})
    assert calls == ["build", "report"]


def test_real_report_counts_come_from_evidence():
    path = ROOT / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9"
    if not (path / "validation.json").exists():
        pytest.skip("Real local validation unavailable")
    bundle = json.loads((path / "manifest.json").read_bytes())
    validation = json.loads((path / "validation.json").read_bytes())
    replay = None
    report = compose_report(bundle, validation, replay)
    assert sum(row["oracle_checks"] for row in report["families"].values()) == sum(len(b["tested_cases"]) for b in bundle["behaviors"])
    assert sum(row["extracted_graphs"] for row in report["families"].values()) == len(bundle["graphs"])
    assert report["fresh_end_to_end_replay"]["status"] == "not_run"
    assert len(report["transformation_observations"]) == 6


def test_real_historical_reports_and_manifest_are_preserved():
    import os
    from scripts.transformation_report import report_run
    from scripts.step9_preflight import exact_hash

    path = ROOT / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9"
    engine = ROOT / "rust_engine/target/debug/rust_engine.exe"
    if os.name != "nt" or not engine.exists() or not (path / "validation.json").exists():
        pytest.skip("Real historical Windows run unavailable")
    bundle = json.loads((path / "manifest.json").read_bytes())
    before = {relative: exact_hash(ROOT / relative) for relative in bundle["runs"][0]["artifact_hashes"]}
    manifest_before = (path / "manifest.json").read_bytes()
    first = report_run(path, engine)
    assert first == report_run(path, engine)
    assert manifest_before == (path / "manifest.json").read_bytes()
    assert before == {relative: exact_hash(ROOT / relative) for relative in before}


def test_legacy_mutating_validation_is_rejected_before_work(tmp_path):
    from scripts.validate_transformation_harness import validate_run

    (tmp_path / "validation.json").write_bytes(b"historical evidence")
    with pytest.raises(ValueError, match="Historical run"):
        validate_run(tmp_path, root=tmp_path)
    assert list(tmp_path.iterdir()) == [tmp_path / "validation.json"]
    assert (tmp_path / "validation.json").read_bytes() == b"historical evidence"
