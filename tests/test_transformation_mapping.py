import copy
import json

import pytest

from scripts import transformation_mapping as mapping


EVIDENCE = [dict(artifact_id="artifact", artifact_path="test.json", artifact_sha256="a" * 64, reference="test")]
EXECUTION = dict(transformation_id="t", execution_id="e")


@pytest.mark.parametrize("left,right,kind", [(["a"], ["b"], "one_to_one"), (["a"], ["b", "c"], "one_to_many"), (["a", "b"], ["c"], "many_to_one"), ([], ["b"], "unmatched"), (["a"], [], "unknown"), (["a", "b"], ["c", "d"], "ambiguous")])
def test_all_cardinalities(left, right, kind):
    status = kind if kind in ("unmatched", "unknown", "ambiguous") else "verified"
    result = mapping.relation(EXECUTION, "canonical_subgraph", left, right, EVIDENCE, "fixture provenance", status, kind)
    assert result["mapping_kind"] == kind
    assert result == mapping.relation(EXECUTION, "canonical_subgraph", list(reversed(left)), list(reversed(right)), EVIDENCE, "fixture provenance", status, kind)


def test_provenance_components_allow_splitting_merging_and_unknown():
    assert mapping.match_provenance({"a": {"1", "2"}}, {"b": {"1"}, "c": {"2"}}) == [(["a"], ["b", "c"])]
    assert mapping.match_provenance({"a": {"1"}, "b": {"2"}}, {"c": {"1", "2"}}) == [(["a", "b"], ["c"])]
    assert mapping.match_provenance({"a": {"missing"}}, {}) == [(["a"], [])]
    # Missing optimized-away wrapper cannot manufacture correspondence.
    assert mapping.match_provenance({"original": {"original"}}, {"wrapper": set()}) == [(["original"], []), ([], ["wrapper"])]


def test_false_structural_correspondence_rejected():
    left = [dict(id="a", source="x", target="y", type="calls_function")]
    right = [dict(id="b", source="p", target="q", type="calls_function")]
    mapping.structural_edge_consistency(left, right, {"x": "p", "y": "q"}, [("a", "b")])
    with pytest.raises(ValueError, match="Impossible"):
        mapping.structural_edge_consistency(left, right, {"x": "q", "y": "p"}, [("a", "b")])
    with pytest.raises(ValueError, match="Dangling"):
        mapping.structural_edge_consistency(left, right, {}, [("a", "missing")])


def test_missing_canonical_provenance_rejected():
    with pytest.raises(ValueError, match="provenance"):
        mapping.project_elements({"source_document": {}, "coverage_ledger": {}}, "canonical_subgraph")


@pytest.fixture(scope="module")
def real_run():
    path = mapping.ROOT / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9"
    if not (path / "manifest.json").exists() or not mapping.default_engine().exists():
        pytest.skip("Real local extraction/engine unavailable")
    bundle = json.loads((path / "manifest.json").read_bytes())
    if bundle["runs"][0]["statuses"]["extraction"] != "passed":
        pytest.skip("Real extraction not completed")
    bundle["mappings"] = mapping.derive_mappings(bundle, path)
    return path, bundle


def test_real_mapping_deterministic_and_all_levels(real_run):
    path, bundle = real_run
    stats = mapping.validate_mappings(bundle, path)
    assert stats["verified_mappings"] > 0
    assert stats["unmatched_elements"] > 0
    assert {m["mapping_level"] for m in bundle["mappings"]} == {"source", "generated_function", "binary_function", "typed_graph", "canonical_subgraph"}
    reordered = copy.deepcopy(bundle)
    for key in ("graphs", "builds", "executions", "specifications"):
        reordered[key].reverse()
    assert mapping.derive_mappings(reordered, path) == bundle["mappings"]
    assert mapping.derive_mappings(bundle, path.relative_to(mapping.ROOT)) == bundle["mappings"]
    assert any(m["mapping_kind"] == "one_to_many" and m["mapping_level"] == "binary_function" for m in bundle["mappings"])


@pytest.mark.parametrize("attack", ["dangling", "duplicate", "transformation", "verified_unknown", "missing_graph", "hash", "sample", "observability", "truncation", "toolchain"])
def test_real_mapping_corruption_rejected(real_run, attack):
    path, original = real_run
    bundle = copy.deepcopy(original)
    if attack == "dangling":
        bundle["mappings"][0]["transformed_element_references"] = ["invented-node"]
    elif attack == "duplicate":
        bundle["mappings"].append(copy.deepcopy(bundle["mappings"][0]))
    elif attack == "transformation":
        bundle["mappings"][0]["transformation_id"] = "wrong"
    elif attack == "verified_unknown":
        unknown = next(m for m in bundle["mappings"] if m["mapping_kind"] in ("unknown", "unmatched"))
        unknown["validation_status"] = "verified"
    elif attack == "missing_graph":
        bundle["graphs"].pop()
    elif attack == "hash":
        bundle["graphs"][0]["canonical_graph_sha256"] = "0" * 64
    elif attack == "observability":
        bundle["graphs"][0]["observability_metadata"]["status"] = "optimized_away"
    elif attack == "truncation":
        bundle["graphs"][0]["truncation_metadata"]["truncated"] = not bundle["graphs"][0]["truncation_metadata"]["truncated"]
    elif attack == "toolchain":
        bundle["graphs"][0]["ghidra_version"] = "invented"
    else:
        bundle["graphs"][0]["binary_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        mapping.validate_mappings(bundle, path)
