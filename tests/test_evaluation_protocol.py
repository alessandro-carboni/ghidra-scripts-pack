"""Preregistered policies and real frozen eligibility, without measured scores."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest

from scripts import evaluation_protocol as ep


@pytest.fixture(scope="module")
def protocol():
    return ep.load_protocol()


def test_registered_bytes_schema_and_inputs(protocol):
    folder = ep.ROOT / ep.AUDIT_DIR
    raw = (folder / "protocol.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "35a4d37ba175e1316e4f2bd179179da5da28e2c534bfb7a1fa1005ddabb040eb"
    assert raw == ep.serialize(ep.proposed())
    assert json.loads((folder / "protocol.schema.json").read_bytes()) == ep.locked_schema(protocol)


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("threshold", "selection_split", "held_out_test"),
        ("threshold", "selection_on_validation_or_heldout", True),
        ("retrieval", "tie_policy", "random"),
        ("scoring", "all_empty", "zero"),
        ("scoring", "both_empty", "perfect_match"),
        ("scoring", "primary", "aggregate_set_similarity"),
        ("cohort", "labels", ["equivalent", "unknown"]),
        ("cohort", "split_assignment", "choose_by_score"),
    ],
)
def test_policy_changes_rejected(protocol, section, key, value):
    changed = copy.deepcopy(protocol)
    changed["design"][section][key] = value
    with pytest.raises(ValueError):
        ep.validate_protocol(changed)


def test_no_positive_query_stays_ineligible_and_small_k_unsupported(protocol):
    queries = protocol["eligibility"]["queries"]
    assert len(queries) == 120
    assert sum(q["eligible"] for q in queries) == 114
    for q in queries:
        assert q["eligible"] == (q["positive_count"] > 0)
        assert q["positive_count"] == sum(c["label"] == "equivalent" for c in q["candidates"])
    for split, counts in zip(ep.design()["cohort"]["splits"], [(61, 31, 31), (22, 16, 4), (31, 16, 15)]):
        assert tuple(sum(q["eligible"] and q["split"] == split and q["gallery_size"] >= k for q in queries) for k in (1, 3, 5)) == counts
    changed = copy.deepcopy(protocol)
    next(q for q in changed["eligibility"]["queries"] if not q["eligible"])["eligible"] = True
    with pytest.raises(ValueError, match="eligibility"):
        ep.validate_protocol(changed)


@pytest.mark.parametrize("attack", ["split", "label", "unknown_reference", "inventory"])
def test_actual_admission_tampering_rejected(protocol, attack):
    changed = copy.deepcopy(protocol)
    q = next(q for q in changed["eligibility"]["queries"] if q["candidates"])
    if attack == "split":
        q["split"] = "contradictory_group"
    elif attack == "label":
        q["candidates"][0]["label"] = "unknown"
    elif attack == "unknown_reference":
        q["candidates"][0]["reference_graph_id"] = "unjudged"
    else:
        changed["inputs"] = {}
    with pytest.raises(ValueError):
        ep.validate_protocol(changed)


def test_registration_refuses_overwrite(protocol):
    folder = ep.ROOT / ep.AUDIT_DIR
    before = {p.name: p.read_bytes() for p in folder.glob("protocol.*")}
    result = subprocess.run([sys.executable, "scripts/evaluation_protocol.py", "--register"], cwd=ep.ROOT, capture_output=True, text=True, timeout=120)
    assert result.returncode != 0 and "already registered" in result.stderr
    assert before == {p.name: p.read_bytes() for p in folder.glob("protocol.*")}


def test_bytes_and_schema_tampering_rejected(protocol, tmp_path):
    folder = tmp_path / ep.AUDIT_DIR
    folder.mkdir(parents=True)
    for p in (ep.ROOT / ep.AUDIT_DIR).glob("protocol.*"):
        (folder / p.name).write_bytes(p.read_bytes())
    original = (folder / "protocol.json").read_bytes()
    (folder / "protocol.json").write_bytes(original + b" ")
    with pytest.raises(ValueError, match="bytes changed"):
        ep.load_protocol(tmp_path)
    (folder / "protocol.json").write_bytes(original)
    (folder / "protocol.schema.json").write_text("{}")
    with pytest.raises(ValueError, match="schema mismatch"):
        ep.load_protocol(tmp_path)
