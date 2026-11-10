import copy
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from ghidra_scripts.recovered_extraction import parameter_candidate
from scripts import semantic_flow as s
from scripts.pcode_evidence import semantics
from scripts.recovered_evidence import envelope, validate, digest, encoded


def sample(opcode="INT_ADD", constant=0, slot=0, storage="10", dead=False):
    source = json.loads((Path(__file__).parent / "fixtures/pcode_evidence_v0_1/micro/sum_array.json").read_bytes())
    value = dict(kind="register", space="register", offset=storage, width=4)
    out = dict(kind="unique", space="unique", offset="100", width=4)
    con = dict(kind="constant", space="const", offset=format(constant, "x"), width=4)
    target = dict(kind="register", space="register", offset="0", width=8)
    rows = [(opcode, [value, con], out), ("RETURN", [target, out], None)]
    if dead:
        rows.append(("INT_MULT", [con, con], dict(out, offset="104")))
    source["operations"] = [dict(id=f"op:{i}", opcode=op, semantics=semantics(op), inputs=args, output=result, origin=dict(address=source["function"]["entry"], sequence=i)) for i, (op, args, result) in enumerate(rows)]
    source["dependencies"] = [dict(**{"from": "op:0", "to": "op:1", "input": 1}, basis="recovered-ssa")]
    source["observability"].update(state="complete", operations_seen=len(rows), dependencies_seen=1, unresolved_inputs=2, truncated=False)
    parameters = [dict(operation="op:0", input=0, slot=slot, width=4, basis="HighParam+input+full-width+no-def")]
    return envelope(source, parameters, [dict(id="b:0", successors=[])], {o["id"]: "b:0" for o in source["operations"]}, "complete")


def test_parameter_storage_invariance_and_slot_discrimination():
    a, b = s.fingerprint(sample()), s.fingerprint(sample(storage="ff"))
    result = s.compare(a, b)
    assert result["views"]["physical"]["set_similarity"] < 1
    assert result["views"]["parameters"]["set_similarity"] == 1
    assert result["views"]["algebra"]["set_similarity"] == 1
    other = s.fingerprint(sample(slot=1))
    assert s.compare(a, other)["views"]["parameters"]["set_similarity"] < 1


@pytest.mark.parametrize("change", ["definition", "not_input", "partial", "width", "slot", "not_param"])
def test_parameter_candidate_rejects_unreliable_evidence(change):
    high = NS(getSlot=lambda: -1 if change == "slot" else 0, getSize=lambda: 8 if change == "width" else 4, getOffset=lambda: 0 if change == "partial" else -1)
    value = NS(getHigh=lambda: high, getDef=lambda: object() if change == "definition" else None, isInput=lambda: change != "not_input", getSize=lambda: 4)
    assert parameter_candidate(value, lambda h: True) is None if change != "not_param" else parameter_candidate(value, lambda h: False) is None


def test_effect_slice_removes_only_dead_pure_work():
    a, b = s.fingerprint(sample()), s.fingerprint(sample(dead=True))
    assert "op:2" not in b["slice"]["retained"]
    result = s.compare(a, b)
    assert result["views"]["parameters"]["set_similarity"] < 1
    assert result["views"]["effects"]["set_similarity"] == 1


def test_cfg_control_dependency_retains_predicate_and_data():
    doc = sample()
    source = doc["source"]
    branch = dict(id="op:2", opcode="CBRANCH", semantics=semantics("CBRANCH"), inputs=[dict(kind="constant", space="const", offset="10", width=8), source["operations"][0]["output"]], output=None, origin=dict(address=source["function"]["entry"], sequence=2))
    source["operations"].append(branch)
    source["dependencies"].append(dict(**{"from": "op:0", "to": "op:2", "input": 1}, basis="recovered-ssa"))
    source["observability"].update(operations_seen=3, dependencies_seen=2)
    doc = envelope(source, doc["parameters"], [dict(id="b:0", successors=["b:1", "b:2"]), dict(id="b:1", successors=[]), dict(id="b:2", successors=[])], {"op:0": "b:0", "op:2": "b:0", "op:1": "b:1"}, "complete")
    fp = s.fingerprint(doc)
    assert "op:2" in fp["slice"]["guards"]
    assert fp["slice"]["control_policy"] == "recovered-CFG-postdominance"
    doc["blocks"][1]["successors"] = ["b:1"]
    fp = s.fingerprint(doc)
    assert "overapproximation" in fp["slice"]["control_policy"]


@pytest.mark.parametrize("opcode,constant", [("INT_ADD", 0), ("INT_SUB", 0), ("INT_MULT", 1), ("INT_AND", 0xFFFFFFFF), ("INT_OR", 0), ("INT_XOR", 0)])
def test_bitvector_neutral_rules_match_same_parameter(opcode, constant):
    a = s.fingerprint(sample(opcode, constant))
    b = s.fingerprint(sample("INT_ADD", 0))
    assert s.compare(a, b)["views"]["algebra"]["set_similarity"] == 1
    assert a["views"]["algebra"]["rewrites"]


def test_constant_folding_modulo_and_no_width_or_signed_cast_rewrite():
    nodes = {}
    args = []
    for n in [255, 1]:
        value = dict(kind="constant", width=1, bits=n)
        h = digest(value)
        nodes[h] = value
        args.append(h)
    h, reason = s.rewrite("INT_ADD", 1, args, nodes)
    assert nodes[h]["bits"] == 0 and reason == "modular-constant-fold"
    assert s.rewrite("INT_ADD", 2, args, nodes) == (None, None)
    for opcode in ["INT_SDIV", "INT_SEXT", "INT_ZEXT", "INT_LEFT", "FLOAT_ADD"]:
        assert s.rewrite(opcode, 1, args, nodes) == (None, None)
    # Exhaustive independent 8-bit checks for the arithmetic identities used above.
    for x in range(256):
        assert ((x + 0) & 255) == ((x - 0) & 255) == ((x * 1) & 255) == (x & 255) == (x | 0) == (x ^ 0) == x


def test_tamper_unknown_and_unavailable_never_pass_as_complete():
    doc = sample()
    bad = copy.deepcopy(doc)
    bad["parameters"][0]["width"] = 8
    with pytest.raises(ValueError):
        validate(bad)
    f = s.fingerprint(doc)
    other = copy.deepcopy(f)
    other["views"]["parameters"]["features"][0]["count"] += 1
    with pytest.raises(ValueError):
        s.compare(f, other)
    empty = copy.deepcopy(doc["source"])
    empty["operations"], empty["dependencies"] = [], []
    empty["observability"].update(state="failed", reason="test", operations_seen=0, dependencies_seen=0, unresolved_inputs=0)
    unavailable = s.fingerprint(envelope(empty))
    assert all(v["set_similarity"] is None and not v["comparison_complete"] for v in s.compare(f, unavailable)["views"].values())


def test_semantic_families_preserve_role_and_negative_constants():
    a, b = s.fingerprint(sample()), s.fingerprint(sample(constant=1))
    assert s.compare(a, b)["views"]["families"]["set_similarity"] < 1
    assert {f["descriptor"]["role"] for f in a["views"]["families"]["features"]} == {"effect", "data"}
    assert encoded(a) == encoded(s.fingerprint(sample()))
    for view in a["views"].values():
        assert all(f["count"] == len(f["occurrences"]) for f in view["features"])


def test_serialized_fingerprint_roundtrip_and_memory_effect_width():
    f = s.fingerprint(sample())
    assert s.compare(json.loads(encoded(f)), json.loads(encoded(f)))["views"]["algebra"]["set_similarity"] == 1
    a = sample()
    a["source"]["operations"][0]["output"].update(kind="memory", space="ram")
    a["source"]["operations"][1]["inputs"][1] = copy.deepcopy(a["source"]["operations"][0]["output"])
    a["source_digest"] = digest(a["source"])
    f = s.fingerprint(a)
    assert "op:0" in f["slice"]["roots"]
    feature = next(v for v in f["views"]["effects"]["features"] if v["descriptor"]["effect"] == "INT_ADD")
    assert feature["descriptor"]["memory_destination"]["space"] == "ram"
    assert feature["descriptor"]["output_width"] == 4


def test_layer_audit_ties_constant_scores_and_misalignment():
    from scripts.audit_semantic_layers import ranks, correlation, audit

    assert ranks([7, 3, 3]) == [2, 0.5, 0.5]
    assert correlation([1, 1], [0, 1]) is None
    assert correlation([0, 1], [1, 0]) == -1
    rows = [dict(query=f"q{i}", reference=f"r{i}", positive=bool(i % 2), score=float(i % 2), split=split) for i, split in enumerate(["discovery", "discovery", "heldout", "heldout"])]
    result = dict(pairs={k: copy.deepcopy(rows) for k in ["depth_0", "depth_1", "depth_2"]})
    audited = audit(result)
    assert audited["threshold_transfer"]["depth_0"]["splits"]["heldout"]["balanced_accuracy"] == 1
    assert audited["contribution"][0]["spearman"] == 1
    result["pairs"]["depth_1"][0]["positive"] = True
    with pytest.raises(ValueError, match="labels"):
        audit(result)


def test_low_fpr_threshold_does_not_guarantee_recall_or_test_transfer():
    from scripts.run_semantic_benchmark import low_fpr_threshold
    from scripts.evaluate_operational_baseline import metrics

    rows = [dict(positive=True, score=0.8), dict(positive=False, score=0.2)]
    threshold = low_fpr_threshold(rows)
    assert threshold == 0.8 and metrics(rows, threshold)["tpr"] == 1
    transferred = [dict(positive=True, score=0.7), dict(positive=False, score=0.9)]
    assert metrics(transferred, threshold)["tpr"] == 0 and metrics(transferred, threshold)["fpr"] == 1
    assert low_fpr_threshold([dict(positive=True, score=0.5), dict(positive=False, score=0.5)]) > 1
