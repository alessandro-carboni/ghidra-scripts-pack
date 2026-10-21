import copy
import json

import pytest

from scripts import transformation_splits as splits
from scripts.step9_preflight import frozen_baseline
from scripts.transformation_harness import default_config, plan
from scripts.transformation_schema import serialize


def record(name, split, **changes):
    return dict(execution_id=name, source_routine_id=name, source_group_id=name, source_artifact=name, source_sha256=name, routine_body_sha256=name, inherited_component=name, source_split=split, experimental_role=splits.ROLES[split], **changes)


@pytest.mark.parametrize("field", ["source_routine_id", "source_group_id", "source_artifact", "source_sha256", "routine_body_sha256", "inherited_component"])
def test_cross_split_shared_identity_rejected(field):
    left, right = record("a", "discovery_train"), record("b", "held_out_test")
    right[field] = left[field]
    with pytest.raises(ValueError, match="leakage"):
        splits.validate_memberships([left, right], [])


def test_near_duplicate_and_held_out_contamination():
    left, right = record("a", "discovery_train"), record("b", "held_out_test")
    with pytest.raises(ValueError, match="leakage"):
        splits.validate_memberships([left, right], [["a", "b"]])
    right["experimental_role"] = "discovery"
    with pytest.raises(ValueError, match="contamination"):
        splits.validate_memberships([right], [])


def test_reversed_pair_and_cross_split_graph():
    pair = dict(original_graph_id="a", transformed_graph_id="b", source_split="discovery_train")
    splits.validate_pairs([pair], {"a": "discovery_train", "b": "discovery_train"})
    with pytest.raises(ValueError, match="reversed"):
        splits.validate_pairs([pair, dict(pair, original_graph_id="b", transformed_graph_id="a")], {"a": "discovery_train", "b": "discovery_train"})
    with pytest.raises(ValueError, match="Cross-split"):
        splits.validate_pairs([pair], {"a": "discovery_train", "b": "held_out_test"})


def test_family_holdout_filters_without_reassigning_and_reports_unsupported():
    records = [record(str(index), split, transformation_family=family) for index, (split, family) in enumerate([("discovery_train", "thunk"), ("validation", "thunk"), ("held_out_test", "dead_branch"), ("held_out_test", "thunk"), ("discovery_train", "dead_branch")])]
    before = copy.deepcopy(records)
    view = splits.family_view(records, "dead_branch")
    assert view["status"] == "supported"
    assert view["execution_ids"] == {"discovery_train": ["0"], "validation": ["1"], "held_out_test": ["2"]}
    assert splits.family_view(records, "function_splitting")["status"] == "unsupported"
    assert records == before


def test_actual_held_out_source_is_evaluation_only(tmp_path):
    config = default_config(frozen_baseline())
    config["selected_source_routines"] = ["count_digits"]
    planned, _ = plan(config)
    (tmp_path / "generation.json").write_bytes(serialize(planned["generated_metadata"]))
    report = splits.derive_split_report(planned["bundle"], tmp_path)
    assert len(report["records"]) == 6
    assert all(r["source_split"] == "held_out_test" and r["experimental_role"] == "held_out_evaluation" for r in report["records"])
    assert all(not view["execution_ids"]["discovery_train"] for view in report["family_holdouts"])


@pytest.fixture(scope="module")
def real_run():
    root = splits.ROOT
    path = root / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9"
    if not (path / "manifest.json").exists():
        pytest.skip("Local real run unavailable")
    bundle = json.loads((path / "manifest.json").read_bytes())
    report = splits.derive_split_report(bundle, path)
    return path, bundle, report


def test_real_frozen_inheritance_and_component_grouping(real_run):
    path, bundle, report = real_run
    before = (splits.ROOT / splits.DATA / "manifest.json").read_bytes()
    assert splits.validate_split_report(bundle, path, report) == splits.derive_split_report(bundle, path)
    assert {r["source_split"] for r in report["records"]} == {"discovery_train"}
    assert all(v["status"] == "unsupported" for v in report["family_holdouts"])
    manifest = json.loads(before)
    components = splits.component_map(manifest)
    assert components["sum_array"] == components["copy_buffer"]
    assert components["count_digits"] != components["sum_array"]
    assert before == (splits.ROOT / splits.DATA / "manifest.json").read_bytes()


@pytest.mark.parametrize("attack", ["group", "split", "body", "graph", "policy", "duplicate"])
def test_tampered_split_provenance_rejected(real_run, attack):
    path, bundle, original = real_run
    report = copy.deepcopy(original)
    if attack == "group":
        report["records"][0]["source_group_id"] = "tampered"
    elif attack == "split":
        report["records"][0]["source_split"] = "held_out_test"
    elif attack == "body":
        report["records"][0]["routine_body_sha256"] = "tampered"
    elif attack == "graph":
        report["graph_splits"][next(iter(report["graph_splits"]))] = "held_out_test"
    elif attack == "policy":
        report["policy"]["held_out_usage"] = "training"
    else:
        report["records"].append(copy.deepcopy(report["records"][0]))
    with pytest.raises(ValueError):
        splits.validate_split_report(bundle, path, report)
