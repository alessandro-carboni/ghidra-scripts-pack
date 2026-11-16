import json
import shutil

import pytest

from scripts.controlled_build import BuildFailure
from scripts.step9_preflight import DATA, ROOT, frozen_baseline, inventory
from scripts.transformation_build import behavior_record, build_run, cases
from scripts.transformation_harness import default_config, generate_run
from scripts.validate_controlled_corpus import expected


def behavior_fixture():
    specification = dict(source_routine_id="sum_array", transformation_id="t", input_contract={"kind": "pure_bytes"})
    generated = dict(original_function="original_fn", transformed_function="variant_fn", proof_obligations=["pure delegation"])
    rows = [f"{side} {case} {expected('sum_array', values)}" for case, values in cases() for side in ("original", "transformed")]
    return rows, specification, generated


def test_independent_oracle_and_exact_input_coverage():
    rows, specification, generated = behavior_fixture()
    result = behavior_record(rows, specification, generated, "b")
    assert result["validation_status"] == "passed"
    assert len(result["tested_cases"]) == 1024
    assert result["tested_cases"][0]["input_bytes"] == []
    assert len(result["tested_cases"][-1]["input_bytes"]) == 255
    assert result["original_outputs_digest"] == result["transformed_outputs_digest"]
    assert cases() == cases()


@pytest.mark.parametrize("failure", ["mismatch", "original_wrong", "missing", "duplicate", "malformed", "oracle"])
def test_behavior_failure_records_witnesses(failure):
    rows, specification, generated = behavior_fixture()
    if failure == "mismatch":
        rows[1] = "transformed 0 999"
    elif failure == "original_wrong":
        rows[0] = "original 0 999"
        rows[1] = "transformed 0 999"  # Matching each other is not sufficient.
    elif failure == "missing":
        rows.pop()
    elif failure == "duplicate":
        rows.append(rows[0])
    elif failure == "malformed":
        rows[0] = "not a row"
    result = behavior_record(rows, specification, generated, "b", oracle=(lambda name, values: None) if failure == "oracle" else expected)
    assert result["validation_status"] != "passed"
    if failure in ("mismatch", "original_wrong"):
        assert result["mismatch_witnesses"][0]["case_id"] == 0
        assert result["mismatch_witnesses"][0]["input_bytes"] == []


@pytest.fixture
def run(tmp_path):
    for relative in (DATA, "samples/controlled/source", "rust_engine/tests/fixtures"):
        shutil.copytree(ROOT / relative, tmp_path / relative)
    config = default_config(frozen_baseline(tmp_path))
    config["transformations"] = config["transformations"][:1]
    path, bundle = generate_run(config, tmp_path)
    return tmp_path, path, bundle


def test_compiler_unavailable_is_explicit(run):
    root, path, _ = run
    before = inventory(root)
    result = build_run(path, root, inventory=lambda: ([], ["gcc unavailable"]))
    assert result["builds"][0]["build_status"] == "unavailable"
    assert result["runs"][0]["statuses"]["build"] == "failed"
    assert inventory(root) == before


@pytest.mark.parametrize("phase,kind,status", [("compile", "CommandFailure", "compile_failed"), ("validate_pe", "PermissionError", "artifact_access_failed"), ("validate_pe", "ValueError", "validation_failed")])
def test_structured_build_failures(run, phase, kind, status):
    root, path, _ = run
    compiler = dict(compiler="gcc", version="mock", path="mock", env={}, optimizations=["O0"])

    def fail(*args, **kwargs):
        raise BuildFailure(dict(attempts=1, error_kind=kind, diagnostic="controlled failure", attempt_diagnostics=[dict(phase=phase)]))

    result = build_run(path, root, inventory=lambda: ([compiler], []), builder=fail)
    assert result["builds"][0]["build_status"] == status
    assert result["builds"][0]["binary_sha256"] is None


def test_parameter_corruption_is_rejected_before_build(run):
    root, path, bundle = run
    bundle["executions"][0]["applied_parameters"] = {"unsafe": True}
    (path / "manifest.json").write_text(json.dumps(bundle))
    with pytest.raises(ValueError):
        build_run(path, root)
