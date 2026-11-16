"""CLI contracts: synthetic structural context plus real Ghidra operation fixtures."""

import copy
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "rust_engine/operational/target/debug/osgf_operational.exe"
if not ENGINE.exists():
    ENGINE = ROOT / "rust_engine/operational/target/debug/osgf_operational"


@pytest.fixture
def pipeline(tmp_path):
    if not ENGINE.is_file():
        pytest.skip("operational CLI not built; run cargo build")
    counter = 0

    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def command(*args, ok=True):
        nonlocal counter
        counter += 1
        output = tmp_path / f"output-{counter}.json"
        result = subprocess.run([str(ENGINE), *map(str, args), str(output)], capture_output=True, text=True, timeout=60)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        if not ok:
            assert not output.exists()
            return None
        return output

    def build(name="sum_array", max_ops=10000, mutate=None):
        doc = json.loads((ROOT / "tests/fixtures/pcode_evidence_v0_1/micro" / (name + ".json")).read_bytes())
        if mutate:
            mutate(doc)
        graph = dict(model_version="0.12.0", metadata=dict(research_binary_sha256=doc["source"]["sha256"]), nodes=[dict(id=doc["function"]["id"], type="FUNCTION")], edges=[], unresolved_calls=[])
        bundle = write(f"bundle-{counter}-{name}.json", dict(schema_version="osgf.typed-operational-graph/0.2.0", typed_graph=graph, operational_evidence=[doc]))
        config = write("context.json", dict(structural=dict(caller_depth=0, callee_depth=0), max_operational_functions=4, max_operations=max_ops, max_dependencies=20000))
        local = command("operational-local", bundle, doc["function"]["id"], config)
        canonical = command("operational-canonical", local)
        features = write("features.json", dict(max_two_edge_paths=4096))
        fingerprint = command("operational-fingerprint", canonical, features)
        return local, canonical, fingerprint

    return write, command, build


def test_self_comparison_and_real_negative_constant(pipeline):
    _, command, build = pipeline
    _, _, q = build("count_matches")
    _, _, r = build("count_33")
    first = command("operational-compare", q, q)
    second = command("operational-compare", q, q)
    assert first.read_bytes() == second.read_bytes()
    result = json.loads(first.read_bytes())
    assert result["operational"]["set_similarity"] == result["operational"]["multiset_similarity"] == 1.0
    assert result["operational"]["missing_from_query"] == []
    negative = json.loads(command("operational-compare", q, r).read_bytes())
    assert negative["structural_v0_1"]["aggregate_set_similarity"] == 1.0
    assert negative["operational"]["set_similarity"] < 1.0
    assert negative["decision"] is None


def test_signed_unsigned_predicate_and_side_effects(pipeline):
    _, command, build = pipeline
    _, _, q = build("signed_less")
    _, _, r = build("unsigned_less")
    assert json.loads(command("operational-compare", q, r).read_bytes())["operational"]["set_similarity"] < 1
    _, _, memory = build("copy_bytes")
    features = json.loads(memory.read_bytes())["operational_view"]
    assert any(f["descriptor"].get("pattern", {}).get("operation", {}).get("opcode") == "STORE" for f in features)


def test_truncation_support_and_tampering_rejected(pipeline):
    write, command, build = pipeline
    local, _, fingerprint = build(max_ops=2)
    assert json.loads(local.read_bytes())["operational_evidence"][0]["observability"]["truncated"]
    compared = json.loads(command("operational-compare", fingerprint, fingerprint).read_bytes())
    assert not compared["operational"]["comparison_complete"]
    data = json.loads(fingerprint.read_bytes())
    data["operational_view"][0]["count"] += 1
    command("operational-compare", write("forged.json", data), fingerprint, ok=False)


def test_unknown_layer_domain_rejected(pipeline):
    _, command, build = pipeline
    _, _, q = build()
    _, _, r = build(mutate=lambda doc: doc["environment"].update(ghidra_version="different"))
    command("operational-compare", q, r, ok=False)


def test_unavailable_is_not_an_empty_semantic_match(pipeline):
    _, command, build = pipeline

    def unavailable(doc):
        doc["operations"] = []
        doc["dependencies"] = []
        doc["observability"].update(state="failed", reason="decompiler failed", operations_seen=0, dependencies_seen=0, unresolved_inputs=0)

    _, _, q = build(mutate=unavailable)
    _, _, r = build()
    result = json.loads(command("operational-compare", q, r).read_bytes())
    assert result["operational"]["set_similarity"] is None
    assert result["operational"]["query_support"]["status"] == "INSUFFICIENT_EVIDENCE"


def test_same_opcodes_different_dependencies(pipeline):
    _, command, build = pipeline

    def network(doc, chain):
        value = dict(kind="unique", width=4, space="unique", offset="10")
        constant = dict(kind="constant", width=4, space="const", offset="1")
        doc["operations"] = []
        doc["dependencies"] = []
        for i in range(3):
            output = dict(value, offset=format(16 + i * 4, "x"))
            inputs = [constant] if i == 0 else [dict(value, offset=format(16 + (i - 1 if chain else 0) * 4, "x"))]
            doc["operations"].append(dict(id=f"op:{i}", opcode="COPY", semantics=dict(family="transfer", signedness="not_asserted"), inputs=copy.deepcopy(inputs), output=output, origin=dict(address=doc["function"]["entry"], sequence=i)))
            if i:
                doc["dependencies"].append(dict(**{"from": f"op:{i - 1 if chain else 0}", "to": f"op:{i}", "input": 0}, basis="recovered-ssa"))
        doc["observability"].update(operations_seen=3, dependencies_seen=2, unresolved_inputs=0)

    _, _, q = build(mutate=lambda doc: network(doc, True))
    _, _, r = build(mutate=lambda doc: network(doc, False))
    result = json.loads(command("operational-compare", q, r).read_bytes())
    assert result["operational"]["set_similarity"] < 1
