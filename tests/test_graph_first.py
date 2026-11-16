"""Graph-first specificity, conservative limits, provenance and seed workflow."""

import copy
import json
from pathlib import Path

import pytest

from scripts import graph_first as g
from scripts import graph_first_evaluation as ev
from scripts import run_graph_first_study as study

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "rust_engine/target/debug" / ("rust_engine.exe" if __import__("os").name == "nt" else "rust_engine")


def engine():
    if not ENGINE.is_file():
        pytest.skip("Rust executable unavailable; pure graph-contract tests still run")
    return ENGINE


def canonical_fixture(swapped=False):
    """Same role marginals and one-call evidence, different co-location."""
    nodes = [dict(id="root", kind="FUNCTION", facts=dict(role="ANCHOR", caller_distance=0, callee_distance=0))]
    nodes += [dict(id=n, kind="FUNCTION", facts=dict(role="CALLEE", caller_distance=None, callee_distance=1)) for n in ("f1", "f2")]
    nodes += [dict(id=n, kind="API", facts=dict(canonical_value=n)) for n in ("a", "b", "c", "d")]
    pairs = [("root", "f1", "calls_function"), ("root", "f2", "calls_function")]
    pairs += [(f, a, "calls_api") for f, a in zip(("f1", "f1", "f2", "f2"), ("a", "c", "b", "d") if swapped else ("a", "b", "c", "d"))]
    edges = [dict(id=f"E{i}", source=s, target=t, kind=k, facts=dict(occurrences=1)) for i, (s, t, k) in enumerate(pairs)]
    return dict(nodes=nodes, edges=edges)


def test_colocation_distinguishes_equal_role_marginals():
    a, b = canonical_fixture(), canonical_fixture(True)
    assert sorted((e["kind"], e["target"]) for e in a["edges"]) == sorted((e["kind"], e["target"]) for e in b["edges"])
    assert g.jaccard(g.relations(a)["features"], g.relations(b)["features"])["set_similarity"] == 0


def test_permutation_relocation_and_no_incidental_identifiers():
    a = canonical_fixture()
    b = copy.deepcopy(a)
    b["nodes"].reverse()
    b["edges"].reverse()
    for node in b["nodes"]:
        node["id"] = "renamed:" + node["id"]
    for edge in b["edges"]:
        for key in ("source", "target"):
            edge[key] = "renamed:" + edge[key]
    assert g.relations(a)["features"] == g.relations(b)["features"]
    assert g.relations(a)["support"] != g.relations(b)["support"]


def test_occurrence_counts_are_not_products_and_budget_explicit(monkeypatch):
    a = canonical_fixture()
    expected = g.relations(a)
    for e in a["edges"]:
        e["facts"]["occurrences"] = 100
    assert g.relations(a) == expected
    monkeypatch.setattr(g, "MAX_MOTIFS", 1)
    assert g.relations(a)["omitted"] == 1
    monkeypatch.setattr(g, "MAX_ENUMERATION", 1)
    with pytest.raises(ValueError, match="budget"):
        g.relations(a)


def test_generic_topology_does_not_invent_evidence():
    a = canonical_fixture()
    a["edges"] = [e for e in a["edges"] if e["kind"] == "calls_function"]
    assert not g.relations(a)["features"]
    assert g.jaccard([], [dict(descriptor={"fact": 1}, count=1)])["set_similarity"] == 0
    assert g.jaccard([], [])["set_similarity"] is None


def test_real_legacy_source_roundtrip_provenance_and_tamper():
    local = g.load(ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json")
    fp = g.fingerprint(local, engine())
    assert fp == g.fingerprint(local, engine())
    result = g.compare(fp, json.loads(g.encoded(fp)), engine())
    assert result["graph_similarity"]["set_similarity"] == 1
    assert result["operational_evidence"]["score"] is None
    assert result["verified_contradictions"] == []
    assert result["evidence_support"]["query"]["unresolved_records"] > 0
    bad = copy.deepcopy(fp)
    bad["co_observations"]["features"][0]["count"] += 1
    with pytest.raises(ValueError, match="reconstruction"):
        g.validate(bad, engine())
    with pytest.raises(ValueError, match="schema"):
        g.validate(dict(schema_version="unknown"), engine())


def test_automatic_seeds_and_no_seed_are_explicit(tmp_path):
    graph = g.load(ROOT / "rust_engine/tests/fixtures/seed_detection.json")
    result = g.extract(graph, engine(), tmp_path / "seeded")
    assert result["eligible"] and len(result["records"]) == 2
    assert result["seed_manifest"]["seed_detection"]["seeds"][0]["evidence"]
    no_seed = dict(model_version="0.12.0", nodes=[dict(id="fn:1", type="FUNCTION")], edges=[], unresolved_calls=[])
    result = g.extract(no_seed, engine(), tmp_path / "empty")
    assert not result["eligible"] and result["records"] == []
    assert result["missing_seed_reason"]
    with pytest.raises(ValueError, match="fresh"):
        g.extract(no_seed, engine(), tmp_path / "empty")


def test_operational_mismatched_source_rejected(tmp_path):
    p = tmp_path / "op.json"
    g.write(p, dict(source_canonical=dict(source_document=dict(structural={"different": True}))))
    result = dict(provenance=dict(query=dict(canonical=dict(source_document={}))))
    with pytest.raises(ValueError, match="source/context"):
        g.operational(result, p, p, engine())


def test_auc_partial_ties_and_retrieval_missing_candidates():
    rows = [dict(query="q", reference="p", score=1.0, positive=True, operational=None), dict(query="q", reference="n", score=0.0, positive=False, operational=1.0)]
    assert ev.roc(rows)["auc"] == 1
    assert ev.roc(rows)["partial_auc"] == pytest.approx(0.05)
    assert ev.rank(rows, "E")[0]["reference"] == "p"
    rows[1]["score"] = 1.0
    assert ev.roc(rows)["auc"] == 0.5
    stats = ev.retrieval(rows, "B")
    assert stats["graph_tie_mrr_bounds"] == [0.5, 1]
    assert stats["recall_at_k"]["1"] == 0
    rows[0]["score"] = None
    assert ev.retrieval(rows, "B")["mrr"] == 0
    assert ev.retrieval(rows, "E")["excluded_true_references_before_refinement"] == 1
    for r in rows:
        r.update(split="discovery", same_family=True)
    summary = ev.summarize({c: rows for c in ev.CONDITIONS})
    assert summary["B"]["splits"]["discovery"]["positive_mean"] is None


def test_refinement_keeps_graph_scores_and_only_admitted_slots():
    rows = [dict(reference=str(i), score=1 - i / 10, operational=float(i), positive=i == 5, query="q") for i in range(6)]
    out = ev.rank(rows, "E")
    assert out[-1]["reference"] == "5"
    assert out[0]["reference"] == "4"
    assert ev.retrieval(rows, "E")["excluded_true_references_before_refinement"] == 1


def test_actual_three_view_collision_and_relational_ablation(tmp_path):
    fps = []
    for swapped in (False, True):
        c = canonical_fixture(swapped)
        graph = dict(model_version="0.12.0", nodes=[], edges=[], unresolved_calls=[])
        for n in c["nodes"]:
            node = dict(id=("fn:" if n["kind"] == "FUNCTION" else "api:") + n["id"], type=n["kind"])
            if n["kind"] == "API":
                node["normalized_name"] = n["id"]
            graph["nodes"].append(node)
        graph["nodes"].append(dict(id="api:seed", type="API", normalized_name="VirtualAlloc"))
        graph["edges"] = [dict(type=e["kind"], source="fn:" + e["source"], target=("fn:" if e["kind"] == "calls_function" else "api:") + e["target"], occurrences=1) for e in c["edges"]]
        graph["edges"].append(dict(type="calls_api", source="fn:root", target="api:seed", occurrences=1))
        folder = tmp_path / str(swapped)
        index = g.extract(graph, engine(), folder)
        record = next(r for r in index["records"] if r["anchor"] == "fn:root")
        fps.append(g.load(folder / record["fingerprint"]))
    assert fps[0]["baseline"]["semantic_digest"] == fps[1]["baseline"]["semantic_digest"]
    assert fps[0]["semantic_digest"] != fps[1]["semantic_digest"]
    result = g.compare(*fps, engine())
    assert result["baseline_comparison"]["aggregate_set_similarity"] == 1
    assert result["graph_similarity"]["set_similarity"] < 1
    assert result["identities"]["query"]["triggering_observations"]["evidence"]


@pytest.mark.parametrize("transformation", ["wrapper", "thunk", "split", "inline", "irrelevant_surrounding"])
def test_controlled_context_transformations_preserve_observed_seed_provenance(tmp_path, transformation):
    graph = dict(model_version="0.12.0", nodes=[dict(id="fn:root", type="FUNCTION"), dict(id="api:alloc", type="API", normalized_name="VirtualAlloc")], edges=[dict(type="calls_api", source="fn:root", target="api:alloc", occurrences=1)], unresolved_calls=[])
    expected = "fn:root"
    if transformation in {"wrapper", "thunk", "split"}:
        graph["nodes"].append(dict(id="fn:helper", type="FUNCTION"))
        graph["edges"][0]["source"] = "fn:helper"
        graph["edges"].append(dict(type="calls_function", source="fn:root", target="fn:helper", occurrences=1))
        expected = "fn:helper"
    if transformation == "irrelevant_surrounding":
        graph["nodes"].append(dict(id="fn:unused", type="FUNCTION"))
    index = g.extract(graph, engine(), tmp_path / transformation)
    assert [r["anchor"] for r in index["records"]] == [expected]
    fp = g.load(tmp_path / transformation / index["records"][0]["fingerprint"])
    assert fp["seed_origin"]["seed"]["evidence"]
    selection = fp["canonical"]["source_document"]["function_selection"]["function_ids"]
    assert "fn:unused" not in selection
    assert "fn:root" in selection
    if expected == "fn:helper":
        assert "fn:helper" in selection


def test_partial_benchmark_cannot_report_complete():
    sources = [dict(family=f"{split}{i}", split=split, sha256="h") for split in ("discovery", "validation", "heldout") for i in range(2)]
    manifest = dict(sources=sources, builds=[])
    with pytest.raises(ValueError, match="all 18"):
        study.validate_manifest(manifest)
    manifest["builds"] = [dict(family=s["family"], split=s["split"], source_sha256="h", compiler=c, optimization=o) for s in sources for c, o in (("gcc", "O0"), ("gcc", "O2"), ("msvc", "O0"))]
    study.validate_manifest(manifest)
    manifest["builds"][0]["split"] = "heldout"
    with pytest.raises(ValueError, match="source/split"):
        study.validate_manifest(manifest)
