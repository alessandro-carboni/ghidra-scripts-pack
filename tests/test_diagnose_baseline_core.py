"""Independent audit mathematics and evidence-preservation contracts."""

import json

import pytest

from scripts import diagnose_baseline_core as d


def feature(name, count=1):
    return dict(descriptor={"name": name}, count=count)


def test_independent_jaccard_counts_empty_and_large_integers():
    assert d.jaccard([], [feature("a")])["multiset_similarity"] == 0
    assert d.jaccard([], [])["set_similarity"] is None
    result = d.jaccard([feature("a", 3), feature("b", 2)], [feature("a", 1), feature("c", 4)])
    assert result["set_similarity"] == 1 / 3
    assert result["multiset_similarity"] == 1 / 9
    assert result["multiset_union"] == 9
    big = [feature("a", 2**64 - 1), feature("b", 2**64 - 1)]
    assert d.jaccard(big, big)["multiset_union"] == 2 * (2**64 - 1)
    assert d.jaccard(big, big)["multiset_similarity"] == 1


@pytest.mark.parametrize("value", [0, -1, True, 1.5, 2**64])
def test_invalid_counts(value):
    with pytest.raises(ValueError):
        d.counts([feature("a", value)])


def test_duplicate_and_descriptor_order():
    with pytest.raises(ValueError):
        d.counts([feature("a"), feature("a")])
    assert d.encoded(dict(a=1, b=2)) == d.encoded(dict(b=2, a=1))


def test_threshold_nulls_ties_and_reject_all():
    rows = [("equivalent", 0.3), ("non_equivalent", 0.3), ("equivalent", None), ("non_equivalent", 0.2)]
    c = d.confusion(rows, 0.3)
    assert [c[k] for k in ("TP", "FP", "TN", "FN", "null")] == [1, 1, 1, 0, 1]
    assert d.confusion(rows, None)["FP"] == 0
    with pytest.raises(ValueError):
        d.confusion([("unknown", 1)], 0.3)
    assert d.auc([(label, 1) for label in ("equivalent", "non_equivalent")])["roc_auc"] == 0.5
    assert d.auc([(label, 1) for label in ("equivalent", "non_equivalent")])["pr_average_precision"] == 0.5


def test_ranking_denominators_and_no_positive():
    ranked = [dict(label=label) for label in ("non_equivalent", "equivalent", "equivalent")]
    r = d.rank_metrics(ranked)
    assert r["mrr"] == 0.5 and r["recall"] == {"1": 0, "3": 1, "5": None}
    assert d.rank_metrics([ranked[0]])["mrr"] is None
    assert d.distribution([None, 0, 1])["n"] == 2


def test_diagnostic_replay_and_conflicting_output_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "OUT", tmp_path)
    d.dump("result.json", {"a": 1})
    original = (tmp_path / "result.json").read_bytes()
    d.dump("result.json", {"a": 1})
    assert original == (tmp_path / "result.json").read_bytes()
    with pytest.raises(ValueError, match="replay differs"):
        d.dump("result.json", {"a": 2})


def test_frozen_labels_ids_sparse_collision_and_provenance():
    path = d.OUT / "FAILURE_CATALOG.json"
    if not path.exists():
        pytest.skip("diagnostic output not generated")
    manifest = json.loads((d.ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    pairs = {p["pair_id"]: p for p in manifest["pairs"]}
    rows = json.loads(path.read_bytes())["records"]
    assert len(rows) == 2 * len(pairs) == 436
    assert len({(r["condition"], r["pair"]["pair_id"]) for r in rows}) == 436
    for r in rows:
        assert r["pair"] == pairs[r["pair"]["pair_id"]]
        assert len(r["endpoint_provenance"]) == 2 and r["source_bearing_artifact"]
        if "REPRESENTATION_INDISTINGUISHABLE" in r["classes"]:
            assert r["pair"]["equivalence_label"] == "non_equivalent"
            assert r["primary"] == 1 and all(v["equal_multisets"] for v in r["views"].values())
        if "negative_exact_one" in r["classes"]:
            assert r["primary"] == 1.0


def test_protected_checkpoint_bytes():
    checkpoint = json.loads((d.OUT / "CHECKPOINT.json").read_bytes())
    for relative, expected in checkpoint["preserved_inventory"].items():
        assert d.admitted.pairs.sha((d.ROOT / relative).read_bytes()) == expected, relative


def test_retrieval_uses_only_judged_edges_and_stable_ties():
    report = json.loads((d.OUT / "RETRIEVAL_BIAS.json").read_bytes())
    manifest = json.loads((d.ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    pairs = {p["pair_id"]: p for p in manifest["pairs"]}
    for q in report["queries"]:
        assert q["mixed"] == (q["positive_n"] > 0 and q["negative_n"] > 0)
        for c in q["candidates"]:
            assert c["label"] == pairs[c["pair_id"]]["equivalence_label"]
        expected = sorted(q["candidates"], key=lambda c: (-c["score"], c["reference_graph_id"]))
        assert q["rankings"]["OSGF"]["order"] == [c["reference_graph_id"] for c in expected]


def test_root_attribution_has_actual_evidence_not_unrelated_pairs():
    report = json.loads((d.OUT / "ROOT_CAUSE_MATRIX.json").read_bytes())
    rows = {r["pair"]["pair_id"]: r for r in json.loads((d.OUT / "FAILURE_CATALOG.json").read_bytes())["records"] if r["condition"] == "B"}
    for cause in report["roots"]:
        assert cause["evidence"] and cause["status"]
        if "affected_pair_ids" not in cause:
            continue
        ids = cause["affected_pair_ids"]
        assert len(set(ids)) == cause["affected_pair_count"]
        for pair_id in ids:
            row = rows[pair_id]
            assert row["pair"]["left_graph_id"] in cause["affected_graph_ids"]
            assert row["pair"]["right_graph_id"] in cause["affected_graph_ids"]
            if cause["root_cause_id"] == "ROOT-EXTRACTION-01":
                assert "REPRESENTATION_INDISTINGUISHABLE" in row["classes"]


def test_synthetic_results_distinguish_no_effect_and_semantic_safeguards():
    cases = {c["case_id"]: c for c in json.loads((d.OUT / "MICRO_GRAPH_EXPERIMENTS.json").read_bytes())}
    for name in ("distinct_constant", "api_A_W_not_alias", "api_Nt_Zw_not_alias"):
        assert cases[name]["comparisons"]["B"]["score"] < 1
    context = cases["edge_context_alias"]["comparisons"]
    assert context["A"]["score"] == context["B"]["score"] == 1
    assert not context["A"]["canonical_edges_equal"] and context["B"]["canonical_edges_equal"]
    assert cases["value_merging"]["comparisons"]["B"]["set_score"] == 1
    assert cases["value_merging"]["comparisons"]["B"]["score"] < 1
