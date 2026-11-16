"""Contract and extractor boundary tests, independent of a Ghidra installation."""

import copy
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from ghidra_scripts import pcode_extraction as x
from scripts import pcode_evidence as e


class Node:
    def __init__(self, kind="unique", offset=0, width=4, definition=None):
        self.kind, self.offset, self.width, self.definition = kind, offset, width, definition

    def isConstant(self):
        return self.kind == "constant"

    def isRegister(self):
        return self.kind == "register"

    def isUnique(self):
        return self.kind == "unique"

    def isAddress(self):
        return self.kind == "memory"

    def getSize(self):
        return self.width

    def getOffset(self):
        return self.offset

    def getAddress(self):
        return NS(getAddressSpace=lambda: NS(getName=lambda: self.kind))

    def getDef(self):
        return self.definition


def operation(name="INT_ADD", seq=0, inputs=None, output=None, address="00401000"):
    return NS(getMnemonic=lambda: name, getSeqnum=lambda: NS(getTarget=lambda: address, getTime=lambda: seq), getInputs=lambda: inputs or [], getOutput=lambda: output)


def run(ops=(), **kwargs):
    program = NS(getName=lambda: "test.exe", getExecutableSHA256=lambda: "a" * 64, getListing=lambda: NS(getInstructions=lambda *args: [NS(getPcode=lambda: ops)]))
    function = NS(getEntryPoint=lambda: "00401000", getName=lambda: "sample", getBody=lambda: None)
    monitor = kwargs.pop("monitor", NS(isCancelled=lambda: False))
    return x.extract(program, function, monitor, dict(ghidra_version="12.0.4", ghidra_revision="test", language="x86:LE:32:default", compiler_spec="gcc", analysis_policy="test"), **kwargs)


def sample():
    temp = Node()
    add = operation(inputs=[Node("constant", 1), Node("register", 8)], output=temp)
    temp.definition = add
    return [add, operation("STORE", 1, [Node("constant", 0), Node("memory", 256), temp])]


def test_raw_bounded_local_flow_and_roundtrip():
    doc = run(sample())
    assert len(doc["dependencies"]) == 1
    assert doc["operations"][1]["output"] is None
    assert doc["dependencies"][0]["input"] == 2
    assert e.serialize(e.loads(e.serialize(doc))) == e.serialize(doc)
    reversed_doc = copy.deepcopy(doc)
    reversed_doc["operations"].reverse()
    assert e.serialize(reversed_doc) == e.serialize(doc)


def test_raw_does_not_invent_global_or_register_dataflow():
    for kind in ("unique", "register"):
        node = Node(kind)
        doc = run([operation(output=node), operation("RETURN", 1, [node], address="00401004")])
        assert not doc["dependencies"]
        assert doc["observability"]["unresolved_inputs"] == 1


def test_overlapping_write_invalidates_unique_definition():
    doc = run([operation(output=Node()), operation(seq=1, output=Node(offset=1, width=1)), operation(seq=2, inputs=[Node()])])
    assert not doc["dependencies"]


def test_raw_does_not_link_after_internal_branch():
    doc = run([operation("CBRANCH"), operation(seq=1, output=Node()), operation(seq=2, inputs=[Node()])])
    assert not doc["dependencies"]


def test_schema_rejects_stale_definition_even_when_storage_matches():
    doc = run([operation(output=Node()), operation(seq=1, output=Node()), operation(seq=2, inputs=[Node()])])
    doc["dependencies"][0]["from"] = "op:0"
    with pytest.raises(ValueError, match="barrier"):
        e.validate(doc)


@pytest.mark.parametrize(
    "opcode,family,signedness",
    [
        ("INT_ADD", "arithmetic", "not_asserted"),
        ("INT_SUB", "arithmetic", "not_asserted"),
        ("INT_LESS", "predicate", "unsigned"),
        ("INT_SLESS", "predicate", "signed"),
        ("BOOL_AND", "boolean", "not_asserted"),
        ("INT_AND", "bitwise", "not_asserted"),
        ("CALLOTHER", "unsupported", "not_asserted"),
        ("UNIMPLEMENTED", "unsupported", "not_asserted"),
        ("MULTIEQUAL", "analysis", "not_asserted"),
        ("INDIRECT", "analysis", "not_asserted"),
        ("CALLIND", "control", "not_asserted"),
    ],
)
def test_semantic_families(opcode, family, signedness):
    doc = run([operation(opcode)])
    assert doc["operations"][0]["semantics"] == dict(family=family, signedness=signedness)
    assert bool([w for w in doc["warnings"] if "unsupported opcode" in w]) == (family == "unsupported")


def test_empty_cancelled_and_truncated_are_distinct():
    assert run()["observability"]["state"] == "complete"
    assert run(monitor=NS(isCancelled=lambda: True))["observability"]["state"] == "cancelled"
    doc = run(sample(), max_operations=1)
    assert doc["observability"]["truncated"] and doc["observability"]["state"] == "partial"
    assert not doc["dependencies"]


def test_dependency_budget_keeps_observability():
    ops = sample()
    ops.append(operation("RETURN", 2, [Node()]))
    doc = run(ops, max_dependencies=1)
    assert len(doc["dependencies"]) == 1
    assert doc["observability"]["dependencies_seen"] == 2
    assert doc["observability"]["truncated"]
    assert doc["observability"]["state"] == "partial"


def test_high_disposes_on_api_exception():
    disposed = []

    def fail(*args):
        raise RuntimeError("native API failed")

    interface = NS(setSimplificationStyle=lambda _: True, openProgram=lambda _: True, decompileFunction=fail, dispose=lambda: disposed.append(True))
    with pytest.raises(RuntimeError, match="native API"):
        run(representation="high", decompiler_factory=lambda: interface)
    assert disposed == [True]


@pytest.mark.parametrize("state", ["complete", "failed", "timeout", "cancelled", "unavailable", "open-failed"])
def test_high_lifecycle(state):
    disposed = []
    result = NS(isCancelled=lambda: state == "cancelled", isTimedOut=lambda: state == "timeout", decompileCompleted=lambda: state != "failed", getErrorMessage=lambda: "test diagnostic", getHighFunction=lambda: None if state == "unavailable" else NS(getPcodeOps=sample))
    interface = NS(setSimplificationStyle=lambda style: style == "decompile", openProgram=lambda _: state != "open-failed", decompileFunction=lambda *args: result, dispose=lambda: disposed.append(True))
    doc = run(representation="high", decompiler_factory=lambda: interface)
    assert disposed == [True]
    assert doc["observability"]["state"] == ("failed" if state == "open-failed" else state)
    if state == "complete":
        assert doc["dependencies"][0]["basis"] == "recovered-ssa"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(schema_version="unknown"),
        lambda d: d["operations"].append(copy.deepcopy(d["operations"][0])),
        lambda d: d["dependencies"][0].update(to="op:99"),
        lambda d: d["dependencies"][0].update(input=99),
        lambda d: d["function"].update(id="fn:wrong"),
        lambda d: d["source"].update(sha256="bad"),
        lambda d: d["operations"][0]["inputs"][0].update(width=0),
        lambda d: d["operations"][0]["semantics"].update(signedness="signed"),
        lambda d: d["observability"].update(truncated=True),
        lambda d: d["configuration"].update(max_operations=True),
        lambda d: d["operations"][0]["output"].update(offset="badbad"),
    ],
)
def test_invalid_documents_rejected(mutation):
    doc = run(sample())
    mutation(doc)
    with pytest.raises(ValueError):
        e.validate(doc)


def test_invalid_json_and_duplicate_keys():
    for data in ('{"a":1,"a":2}', '{"bad"', "null", "{}"):
        with pytest.raises((ValueError, json.JSONDecodeError)):
            e.loads(data)


def test_width_constants_and_memory_are_preserved():
    doc = run([operation(inputs=[Node("constant", -1, 8), Node("memory", 32, 1), Node("memory", 32, 8)])])
    values = doc["operations"][0]["inputs"]
    assert values[0]["offset"] == "ffffffffffffffff"
    assert values[1] != values[2]


def test_real_versioned_fixtures_and_behavior_distinctions():
    root = Path(__file__).parent / "fixtures/pcode_evidence_v0_1"
    manifest = json.loads((root / "manifest.json").read_bytes())
    assert len(manifest["records"]) == 6
    for record in manifest["records"]:
        data = (root / record["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        doc = e.loads(data)
        assert doc["source"]["sha256"] == record["source_binary_sha256"]
        assert e.serialize(doc) == data
    total = e.loads((root / "sum_array-high.json").read_bytes())
    count = e.loads((root / "count_matches-high.json").read_bytes())
    total_ops = {op["opcode"] for op in total["operations"]}
    count_ops = {op["opcode"] for op in count["operations"]}
    assert {"LOAD", "INT_ADD", "RETURN"} <= total_ops
    assert "INT_EQUAL" in count_ops and "INT_EQUAL" not in total_ops
    assert any(op["opcode"] == "INT_EQUAL" and any(v["kind"] == "constant" and v["offset"] == "20" for v in op["inputs"]) for op in count["operations"])
    assert total["dependencies"] and count["dependencies"]


def test_real_gate_rejects_missing_outputs_and_wrong_binary(tmp_path):
    from scripts.test_pcode_real import check_outputs

    with pytest.raises(ValueError, match="missing/extra"):
        check_outputs(tmp_path, ["sample"], "a" * 64)
    (tmp_path / "sample.json").write_bytes(e.serialize(run(sample())))
    with pytest.raises(ValueError, match="binary provenance"):
        check_outputs(tmp_path, ["sample"], "b" * 64)
