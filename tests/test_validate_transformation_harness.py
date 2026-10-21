import copy
import json

import pytest

from scripts.transformation_build import behavior_record, cases
from scripts.validate_controlled_corpus import expected
from scripts.validate_transformation_harness import check_behavior, coverage


def fixture():
    specification = dict(source_routine_id="sum_array", transformation_id="t", input_contract={"kind": "pure_bytes"})
    generated = dict(original_function="original", transformed_function="variant", proof_obligations=["pure delegation"])
    rows = [f"{side} {case} {expected('sum_array', values)}" for case, values in cases() for side in ("original", "transformed")]
    return behavior_record(rows, specification, generated, "b"), specification, generated, rows


def test_complete_independent_oracle_reconstruction_and_replay():
    record, specification, generated, rows = fixture()
    assert check_behavior(record, specification, generated) == 1024
    assert check_behavior(record, specification, generated, rows) == 1024


@pytest.mark.parametrize("attack", ["input", "oracle", "digest", "partial", "replay", "original_and_variant"])
def test_no_false_pass_from_recorded_or_replayed_behavior(attack):
    record, specification, generated, rows = fixture()
    if attack == "input":
        record["tested_cases"][0]["input_bytes"] = [99]
    elif attack == "oracle":
        record["tested_cases"][0]["oracle_result"] = None
    elif attack == "digest":
        record["original_outputs_digest"] = "0" * 64
    elif attack == "partial":
        record["tested_cases"].pop()
    elif attack == "replay":
        rows[1] = "transformed 0 999"
    else:
        record["tested_cases"][0].update(original_result=999, transformed_result=999, oracle_result=999)
    with pytest.raises(ValueError, match="oracle"):
        check_behavior(record, specification, generated, rows if attack == "replay" else None)


def test_real_coverage_has_all_six_families_and_explicit_observability():
    from scripts.step9_preflight import ROOT

    path = ROOT / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9/manifest.json"
    if not path.exists():
        pytest.skip("Local example run unavailable")
    bundle = json.loads(path.read_bytes())
    before = copy.deepcopy(bundle)
    result = coverage(bundle)
    assert len(result) == 6
    assert all(row["successful_builds"] == 1 and row["oracle_checks"] == 1024 and row["extracted_graphs"] == 2 for row in result.values())
    assert result["dead_branch"]["observed_effects"]["not_observable"] == 2
    assert result["instruction_reordering"]["observed_effects"]["not_observable"] == 2
    assert all(row["observed_effects"]["optimized_away"] == 0 for row in result.values())
    assert bundle == before


def test_fresh_replay_compares_scientific_artifacts_and_rejects_changes(tmp_path):
    from scripts.replay_transformation_harness import compare_runs

    left, right = tmp_path / "left", tmp_path / "right"
    for directory in (left, right):
        directory.mkdir()
        for name in ("generation.json", "splits.json", "validation.json"):
            (directory / name).write_bytes(b"{}\n")
    bundle = dict(specifications=[], executions=[], builds=[], behaviors=[], graphs=[], mappings=[], runs=[dict(run_id="run", artifact_hashes={"toolchain.json": "a" * 64})])
    assert all(compare_runs(bundle, copy.deepcopy(bundle), left, right).values())
    changed = copy.deepcopy(bundle)
    changed["runs"][0]["artifact_hashes"]["toolchain.json"] = "b" * 64
    with pytest.raises(ValueError, match="artifact_hashes"):
        compare_runs(bundle, changed, left, right)
    (right / "validation.json").write_bytes(b'{"tampered": true}')
    with pytest.raises(ValueError, match="validation.json"):
        compare_runs(bundle, bundle, left, right)
