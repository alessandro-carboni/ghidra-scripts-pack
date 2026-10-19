import json
from pathlib import Path

import pytest

from scripts.audit_dataset_graph_signal import graph_signal
from scripts.interaction_sources import DESIGNS, expected, source, validate_behavior


@pytest.mark.parametrize("group", DESIGNS)
def test_independent_oracle_and_negative_witness(group):
    text, routines, transformations = source(group)
    assert source(group) == (text, routines, transformations)
    assert len(routines) == 5 and len(transformations) == 3
    rows = []
    for case in range(16):
        values = [(j * 17 + case * 13) % 127 for j in range(case * 7)]
        reference = expected(group, values, 7)
        for routine in routines:
            name = routine["routine_id"]
            value = reference ^ 1 if name.endswith("_flipped") else reference
            rows.append(f"{name} {case} {value}")
    validate_behavior(group, rows, 7)
    with pytest.raises(ValueError):
        validate_behavior(group, rows[:-1], 7)
    with pytest.raises(ValueError):
        validate_behavior(group, rows + rows[:1], 7)
    rows[0] = rows[0].rsplit(" ", 1)[0] + " 99999"
    with pytest.raises(ValueError):
        validate_behavior(group, rows, 7)


def test_real_extracted_interactions_and_witnesses_cover_each_split():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "datasets/osgf_pairs_v0_1/manifest.json").read_text())
    graphs = {g["graph_id"]: g for g in manifest["graphs"] if g["routine_id"].startswith("interaction_")}
    signals = {gid: graph_signal(json.loads((root / graph["path"]).read_text())) for gid, graph in graphs.items()}
    for split in ("discovery_train", "validation", "held_out_test"):
        for label in ("equivalent", "non_equivalent"):
            pairs = [p for p in manifest["pairs"] if p["split"] == split and p["equivalence_label"] == label and {p["left_graph_id"], p["right_graph_id"]} <= graphs.keys()]
            assert any(all(signals[p[side + "_graph_id"]]["interaction_capable"] and signals[p[side + "_graph_id"]]["typed_evidence_present"] for side in ("left", "right")) for p in pairs), (split, label)
    for build in manifest["builds"]:
        if build["artifact_group"].startswith("interaction_"):
            validate_behavior(build["artifact_group"].removeprefix("interaction_"), build["behavior"], build["independent_environment_observation"])
