import json
from copy import deepcopy
import pytest
from scripts import evaluation_stratification as e


def data():
    folder = e.g.ROOT / "datasets/osgf_pairs_v0_1"
    return [json.loads((folder / name).read_bytes()) for name in ("manifest.json", "evaluation_strata.json", "family_holdouts.json")]


def test_connected_source_components():
    manifest, _, _ = data()
    mapping = e.clusters(manifest)
    graphs = manifest["graphs"]
    numeric_memory = [mapping[g["graph_id"]] for g in graphs if g["source_group_id"] in ("sum_array", "copy_buffer")]
    assert len(set(numeric_memory)) == 1
    assert len(mapping) == 120
    assert len(set(mapping.values())) < 10


def test_component_leakage_rejected():
    manifest, _, _ = data()
    manifest["graphs"][0]["split"] = "validation"
    with pytest.raises(ValueError, match="cluster crosses"):
        e.clusters(manifest)


def test_frozen_cell_ids_and_overlap():
    manifest, strata, holdouts = data()
    before = deepcopy(manifest)
    cells = e.cells(manifest, strata, holdouts)
    allids = {p["pair_id"] for p in manifest["pairs"]}
    assert all(set(c["pair_ids"]) <= allids for c in cells)
    assert sum(len(c["pair_ids"]) for c in cells if c["dimension"] == "all") == 218
    assert sum(len(c["pair_ids"]) for c in cells) > 218
    assert manifest == before
    assert any(not c["pair_ids"] for c in cells)


def test_unknown_stratum_rejected():
    manifest, strata, holdouts = data()
    strata["strata"]["unknown"] = ["invented"]
    with pytest.raises(ValueError, match="unknown stratum"):
        e.cells(manifest, strata, holdouts)


def test_holdout_no_reassignment():
    manifest, strata, holdouts = data()
    holdouts[0]["pair_ids"]["held_out_test"].append(holdouts[0]["pair_ids"]["discovery_train"][0])
    with pytest.raises(ValueError, match="remaps"):
        e.cells(manifest, strata, holdouts)
