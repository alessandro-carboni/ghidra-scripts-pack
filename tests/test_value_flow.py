"""Semantic guards for the optional value view; synthetic SSA, not real-binary proof."""

import copy
import json

import pytest

from tests.test_operational_pipeline import pipeline as pipeline


def network(doc, opcode="INT_SUB", swapped=False, shared=False, extra_copy=False):
    def value(n):
        return dict(kind="register", space="register", width=4, offset=format(16 + n * 4, "x"))

    def const(n):
        return dict(kind="constant", space="const", width=4, offset=format(n, "x"))

    from scripts.pcode_evidence import semantics

    rows = [("COPY", [const(1)], value(0)), ("COPY", [const(1 if shared else 2)], value(1)), (opcode, [value(1), value(0)] if swapped else [value(0), value(1)], value(2))]
    dependencies = [(1 if swapped else 0, 2, 0), (0 if swapped else 1, 2, 1)]
    if extra_copy:
        rows.append(("COPY", [value(2)], value(3)))
        dependencies.append((2, 3, 0))
    rows.append(("RETURN", [value(len(rows) - 1)], None))
    dependencies.append((len(rows) - 2, len(rows) - 1, 0))
    doc["operations"] = [dict(id=f"op:{i}", opcode=code, semantics=semantics(code), inputs=inputs, output=out, origin=dict(address=doc["function"]["entry"], sequence=i)) for i, (code, inputs, out) in enumerate(rows)]
    doc["dependencies"] = [dict(**{"from": f"op:{a}", "to": f"op:{b}", "input": slot}, basis="recovered-ssa") for a, b, slot in dependencies]
    doc["observability"].update(state="complete", reason="", operations_seen=len(rows), dependencies_seen=len(dependencies), unresolved_inputs=0, truncated=False)


def normalized(pipeline, mutate=None, name="sum_array"):
    _, command, build = pipeline
    _, _, fp = build(name, mutate=mutate)
    result = command("value-fingerprint", fp)
    return json.loads(result.read_bytes()), result


def science(document):
    return [(f["descriptor"], f["count"]) for f in document["features"]]


def test_defined_value_relocation_preserves_flow_but_not_exact_storage(pipeline):
    a, _ = normalized(pipeline, network)

    def renamed(doc):
        network(doc)
        for op in doc["operations"]:
            for v in op["inputs"] + ([op["output"]] if op["output"] else []):
                if v["kind"] == "register":
                    v.update(kind="unique", space="unique", offset=format(int(v["offset"], 16) + 400, "x"))

    b, _ = normalized(pipeline, renamed)
    assert a["source"]["semantic_digest"] != b["source"]["semantic_digest"]
    assert a["semantic_digest"] == b["semantic_digest"]
    assert science(a) == science(b)


def test_copy_chain_contracted_with_resolvable_provenance(pipeline):
    a, _ = normalized(pipeline, network)
    b, path = normalized(pipeline, lambda d: network(d, extra_copy=True))
    assert science(a) == science(b)
    assert a["semantic_digest"] == b["semantic_digest"]
    assert len(b["contracted_copies"]) == 1
    provenance = b["source"]["source_canonical"]["provenance"]
    assert all(k in provenance and v in provenance for k, v in b["contracted_copies"].items())
    _, command, _ = pipeline
    one = command("value-compare", path, path)
    two = command("value-compare", path, path)
    assert one.read_bytes() == two.read_bytes()
    assert json.loads(one.read_bytes())["normalized"]["set_similarity"] == 1


@pytest.mark.parametrize("opcode,expected_same", [("INT_ADD", True), ("INT_SUB", False), ("INT_LEFT", False), ("INT_LESS", False)])
def test_operand_direction_and_allowed_commutativity(pipeline, opcode, expected_same):
    a, _ = normalized(pipeline, lambda d: network(d, opcode=opcode))
    b, _ = normalized(pipeline, lambda d: network(d, opcode=opcode, swapped=True))
    assert (science(a) == science(b)) == expected_same


def test_same_producer_alias_is_not_two_distinct_producers(pipeline):
    a, _ = normalized(pipeline, lambda d: network(d, shared=True))

    def same(doc):
        network(doc, shared=True)
        doc["operations"][2]["inputs"][1] = copy.deepcopy(doc["operations"][0]["output"])
        doc["dependencies"][1]["from"] = "op:0"

    b, _ = normalized(pipeline, same)
    assert science(a) != science(b)


def test_unknown_register_inputs_keep_identity(pipeline):
    def external(doc, swap):
        network(doc)
        doc["dependencies"] = doc["dependencies"][2:]
        doc["operations"][2]["inputs"] = [dict(kind="register", space="register", width=4, offset=v) for v in (["a", "b"] if not swap else ["b", "a"])]
        doc["observability"].update(dependencies_seen=1, unresolved_inputs=2)

    a, _ = normalized(pipeline, lambda d: external(d, False))
    b, _ = normalized(pipeline, lambda d: external(d, True))
    assert science(a) != science(b)


@pytest.mark.parametrize("kind", ["stack", "width", "cast"])
def test_unsafe_copy_contraction_refused(pipeline, kind):
    def changed(doc):
        network(doc, extra_copy=True)
        out = doc["operations"][3]["output"]
        if kind == "stack":
            out.update(kind="memory", space="stack")
        elif kind == "width":
            out["width"] = 8
        else:
            doc["operations"][3]["opcode"] = "CAST"
        doc["operations"][4]["inputs"][0] = copy.deepcopy(out)

    b, _ = normalized(pipeline, changed)
    assert not b["contracted_copies"]


def test_copy_cycles_preserved_and_do_not_recurse(pipeline):
    def cycle(doc):
        network(doc)
        for index, other in [(0, 1), (1, 0)]:
            doc["operations"][index]["inputs"] = [copy.deepcopy(doc["operations"][other]["output"])]
            doc["dependencies"].append(dict(**{"from": f"op:{other}", "to": f"op:{index}", "input": 0}, basis="recovered-ssa"))
        doc["observability"]["dependencies_seen"] += 2

    a, _ = normalized(pipeline, cycle)
    assert not a["contracted_copies"]
    assert len(a["copy_barriers"]) == 2


def test_real_predicates_constants_and_store_stay_distinct(pipeline):
    a, _ = normalized(pipeline, name="signed_less")
    b, _ = normalized(pipeline, name="unsigned_less")
    assert science(a) != science(b)
    a, _ = normalized(pipeline, name="count_matches")
    b, _ = normalized(pipeline, name="count_33")
    assert science(a) != science(b)
    c, _ = normalized(pipeline, name="copy_bytes")
    assert any(f["descriptor"].get("pattern", {}).get("operation", {}).get("opcode") == "STORE" for f in c["features"])


@pytest.mark.parametrize("field", ["count", "ledger", "version"])
def test_tampered_fingerprint_rejected(pipeline, field):
    write, command, _ = pipeline
    a, path = normalized(pipeline, lambda d: network(d, extra_copy=True))
    if field == "count":
        a["features"][0]["count"] += 1
    elif field == "version":
        a["schema_version"] = "wrong"
    else:
        a["contracted_copies"] = {}
    command("value-compare", write("tampered.json", a), path, ok=False)


def test_unavailable_and_raw_evidence_are_not_successful_high(pipeline):
    _, command, build = pipeline

    def empty(doc):
        doc["operations"] = []
        doc["dependencies"] = []
        doc["observability"].update(state="failed", reason="test", operations_seen=0, dependencies_seen=0, unresolved_inputs=0)

    a, path = normalized(pipeline, empty)
    _, full = normalized(pipeline)
    result = json.loads(command("value-compare", path, full).read_bytes())
    assert not a["features"]
    assert result["normalized"]["set_similarity"] is None
    assert result["exact_normalized_mean"]["set_similarity"] is None

    def raw(doc):
        empty(doc)
        doc["representation"] = "raw"

    _, _, fp = build(mutate=raw)
    command("value-fingerprint", fp, ok=False)


def test_order_and_occurrences(pipeline):
    a, _ = normalized(pipeline)

    def reverse(doc):
        doc["operations"].reverse()
        doc["dependencies"].reverse()

    b, _ = normalized(pipeline, reverse)
    assert a == b
    provenance = a["source"]["source_canonical"]["provenance"]
    assert all(f["count"] == len(f["occurrences"]) and all(op in provenance for occurrence in f["occurrences"] for op in occurrence) for f in a["features"])


def test_auc_handles_ties_and_missing_classes():
    from scripts.evaluate_value_flow import auc

    assert auc([dict(positive=True, score=0.5), dict(positive=False, score=0.5)]) == 0.5
    assert auc([dict(positive=True, score=1), dict(positive=False, score=0)]) == 1
    assert auc([dict(positive=True, score=None), dict(positive=False, score=0)]) is None


def test_copy_budget_keeps_unresolved_chain_and_valid_references(pipeline):
    def long_chain(doc):
        network(doc)
        constant = copy.deepcopy(doc["operations"][0]["inputs"][0])
        template = copy.deepcopy(doc["operations"][0])
        doc["operations"] = []
        doc["dependencies"] = []
        for i in range(71):
            op = copy.deepcopy(template)
            op.update(id=f"op:{i}", inputs=[constant if not i else copy.deepcopy(doc["operations"][-1]["output"])])
            op["origin"]["sequence"] = i
            op["output"]["offset"] = format(16 + 4 * i, "x")
            doc["operations"].append(op)
            if i:
                doc["dependencies"].append(dict(**{"from": f"op:{i - 1}", "to": f"op:{i}", "input": 0}, basis="recovered-ssa"))
        doc["observability"].update(operations_seen=71, dependencies_seen=70)

    a, _ = normalized(pipeline, long_chain)
    assert a["copy_barriers"]
    assert set(a["copy_barriers"].values()) == {"copy_hop_budget_retained"}
    assert all(k not in a["contracted_copies"] for k in a["copy_barriers"])


def test_path_budget_is_explicit_in_normalized_comparison(pipeline):
    write, command, build = pipeline
    _, canonical, _ = build(mutate=network)
    source = command("operational-fingerprint", canonical, write("no-paths.json", dict(max_two_edge_paths=0)))
    fp = command("value-fingerprint", source)
    doc = json.loads(fp.read_bytes())
    assert doc["paths_truncated"]
    assert all(f["descriptor"]["family"] != "two_edge_path" for f in doc["features"])
    compared = json.loads(command("value-compare", fp, fp).read_bytes())
    assert not compared["normalized"]["comparison_complete"]
