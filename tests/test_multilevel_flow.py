"""Independent multiscale contracts; reuse real evidence fixtures without claiming equivalence."""

import copy
import json

import pytest

from tests.test_operational_pipeline import pipeline as pipeline
from tests.test_value_flow import network


def build_view(pipeline, mutate=network, name="sum_array"):
    _, command, build = pipeline
    _, _, source = build(name, mutate=mutate)
    output = command("multilevel-fingerprint", source)
    return json.loads(output.read_bytes()), output, source


def operation(view, depth, opcode):
    return [f["descriptor"]["pattern"]["operation"] for f in view["levels"][f"depth_{depth}"]["features"] if f["descriptor"]["family"] == "operation" and f["descriptor"]["pattern"]["operation"]["opcode"] == opcode]


def test_context_depth_is_bounded_and_local_matches_survive(pipeline):
    a, _, _ = build_view(pipeline)

    def upstream_change(doc):
        network(doc)
        doc["operations"][0]["inputs"][0]["offset"] = "3"

    b, _, _ = build_view(pipeline, upstream_change)
    assert operation(a, 0, "INT_SUB") == operation(b, 0, "INT_SUB")
    assert operation(a, 1, "INT_SUB") != operation(b, 1, "INT_SUB")
    assert operation(a, 1, "RETURN") == operation(b, 1, "RETURN")
    assert operation(a, 2, "RETURN") != operation(b, 2, "RETURN")
    assert operation(a, 0, "COPY") != operation(b, 0, "COPY")  # Never erase constants.


def test_depth_two_preserves_legacy_features_and_provenance(pipeline):
    _, command, _ = pipeline
    view, path, source = build_view(pipeline, lambda d: network(d, extra_copy=True))
    old = json.loads(command("value-fingerprint", source).read_bytes())
    assert view["levels"]["depth_2"]["features"] == old["features"]
    assert view["contracted_copies"] == old["contracted_copies"]
    assert view["copy_barriers"] == old["copy_barriers"]
    assert command("multilevel-fingerprint", source).read_bytes() == path.read_bytes()
    provenance = view["source"]["source_canonical"]["provenance"]
    for level in view["levels"].values():
        assert {f["descriptor"]["family"] for f in level["features"]} == {"operation", "dependency", "two_edge_path"}
        assert all(f["count"] == len(f["occurrences"]) and all(v in provenance for occ in f["occurrences"] for v in occ) for f in level["features"])


def test_comparison_independent_jaccard_and_fixed_means(pipeline):
    _, command, _ = pipeline
    a, apath, _ = build_view(pipeline)
    b, bpath, _ = build_view(pipeline, lambda d: network(d, swapped=True))
    first = command("multilevel-compare", apath, bpath)
    assert first.read_bytes() == command("multilevel-compare", apath, bpath).read_bytes()
    result = json.loads(first.read_bytes())
    for key in a["levels"]:

        def counts(view):
            return {json.dumps(f["descriptor"], sort_keys=True): f["count"] for f in view["levels"][key]["features"]}

        q, r = counts(a), counts(b)
        union = q.keys() | r.keys()
        assert result["levels"][key]["set_similarity"] == len(q.keys() & r.keys()) / len(union)
        assert result["levels"][key]["multiset_similarity"] == sum(min(q.get(k, 0), r.get(k, 0)) for k in union) / sum(max(q.get(k, 0), r.get(k, 0)) for k in union)
    for field in ("set_similarity", "multiset_similarity"):
        values = [result["levels"][f"depth_{d}"][field] for d in range(3)]
        assert result["aggregates"]["mean_01"][field] == sum(values[:2]) / 2
        assert result["aggregates"]["mean_012"][field] == sum(values) / 3
        assert result["aggregates"]["exact_mean_012"][field] == (result["baseline"]["operational"][field] + sum(values) / 3) / 2
    assert result["decision"] is None


@pytest.mark.parametrize("opcode,same", [("INT_ADD", True), ("INT_SUB", False), ("INT_LEFT", False)])
def test_operand_direction_and_commutativity(pipeline, opcode, same):
    a, _, _ = build_view(pipeline, lambda d: network(d, opcode=opcode))
    b, _, _ = build_view(pipeline, lambda d: network(d, opcode=opcode, swapped=True))
    for key in a["levels"]:
        assert (a["levels"][key]["semantic_digest"] == b["levels"][key]["semantic_digest"]) == same


@pytest.mark.parametrize("mutation", ["depth", "features", "missing", "digest", "version", "ledger"])
def test_tampering_rejected(pipeline, mutation):
    write, command, _ = pipeline
    view, path, _ = build_view(pipeline, lambda d: network(d, extra_copy=True))
    if mutation == "depth":
        view["levels"]["depth_0"]["producer_depth"] = 1
    elif mutation == "features":
        view["levels"]["depth_0"]["features"][0]["count"] += 1
    elif mutation == "missing":
        del view["levels"]["depth_1"]
    elif mutation == "digest":
        view["semantic_digest"] = "0" * 64
    elif mutation == "version":
        view["schema_version"] = "unknown"
    else:
        view["contracted_copies"] = {}
    command("multilevel-compare", write("tampered.json", view), path, ok=False)


def test_unavailable_raw_and_incompatible_sources(pipeline):
    _, command, build = pipeline

    def unavailable(doc):
        doc["operations"], doc["dependencies"] = [], []
        doc["observability"].update(state="failed", reason="test", operations_seen=0, dependencies_seen=0, unresolved_inputs=0)

    _, empty, _ = build_view(pipeline, unavailable)
    _, full, _ = build_view(pipeline)
    compared = json.loads(command("multilevel-compare", empty, full).read_bytes())
    assert all(v["set_similarity"] is None for v in compared["levels"].values())
    assert all(v["set_similarity"] is None for v in compared["aggregates"].values())

    def raw(doc):
        unavailable(doc)
        doc["representation"] = "raw"

    _, _, source = build(mutate=raw)
    command("multilevel-fingerprint", source, ok=False)
    _, other, _ = build_view(pipeline, lambda d: d["environment"].update(ghidra_version="other"))
    command("multilevel-compare", full, other, ok=False)


def test_budget_and_empty_family_are_explicit(pipeline):
    write, command, build = pipeline
    _, canonical, _ = build(mutate=network)
    source = command("operational-fingerprint", canonical, write("zero-paths.json", dict(max_two_edge_paths=0)))
    path = command("multilevel-fingerprint", source)
    result = json.loads(command("multilevel-compare", path, path).read_bytes())
    for level in result["levels"].values():
        assert level["set_similarity"] == level["multiset_similarity"] == 1
        assert level["paths_truncated"] and not level["comparison_complete"]
        assert level["families"]["two_edge_path"]["set_similarity"] is None
    assert all(not v["comparison_complete"] for v in result["aggregates"].values())


def test_permutation_and_defined_storage_renaming(pipeline):
    a, _, _ = build_view(pipeline)

    def rename(doc):
        network(doc)
        for op in doc["operations"]:
            for v in op["inputs"] + ([op["output"]] if op["output"] else []):
                if v["kind"] == "register":
                    v.update(kind="unique", space="unique", offset=format(int(v["offset"], 16) + 400, "x"))
        doc["operations"].reverse()
        doc["dependencies"].reverse()

    b, _, _ = build_view(pipeline, rename)
    assert a["semantic_digest"] == b["semantic_digest"]


def test_unknown_inputs_and_real_signedness_remain_distinct(pipeline):
    def external(doc, changed=False):
        network(doc)
        doc["dependencies"] = doc["dependencies"][2:]
        doc["observability"].update(dependencies_seen=1, unresolved_inputs=2)
        if changed:
            doc["operations"][2]["inputs"][0]["offset"] = "ff"

    a, _, _ = build_view(pipeline, external)
    b, _, _ = build_view(pipeline, lambda d: external(d, True))
    for key in a["levels"]:
        assert a["levels"][key]["semantic_digest"] != b["levels"][key]["semantic_digest"]
    a, _, _ = build_view(pipeline, None, "signed_less")
    b, _, _ = build_view(pipeline, None, "unsigned_less")
    for key in a["levels"]:
        assert a["levels"][key]["semantic_digest"] != b["levels"][key]["semantic_digest"]


def test_shared_value_does_not_become_distinct_values(pipeline):
    a, _, _ = build_view(pipeline, lambda d: network(d, shared=True))

    def shared(doc):
        network(doc, shared=True)
        doc["operations"][2]["inputs"][1] = copy.deepcopy(doc["operations"][0]["output"])
        doc["dependencies"][1]["from"] = "op:0"

    b, _, _ = build_view(pipeline, shared)
    for key in a["levels"]:
        assert a["levels"][key]["semantic_digest"] != b["levels"][key]["semantic_digest"]


@pytest.mark.parametrize("violation", ["family", "pair", "duplicate", "label"])
def test_experiment_rejects_leakage_and_invalid_labels(violation):
    from scripts.evaluate_multilevel_flow import validate_baseline

    cases = [dict(id="a", family="one", split="discovery"), dict(id="b", family="two", split="discovery")]
    pair = dict(query="a", reference="b", split="discovery", positive=False)
    baseline = dict(status="PASS", cases=cases, pairs={"C": [pair]})
    validate_baseline(baseline)
    if violation == "family":
        cases[1].update(family="one", split="heldout")
    elif violation == "pair":
        cases[1]["split"] = "heldout"
    elif violation == "duplicate":
        baseline["pairs"]["C"].append(copy.deepcopy(pair))
    else:
        pair["positive"] = "yes"
    with pytest.raises(ValueError):
        validate_baseline(baseline)
