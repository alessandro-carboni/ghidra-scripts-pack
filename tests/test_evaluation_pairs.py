"""Step 10.4 numeric oracles, source-bound directionality and corruption tests."""

import copy
import json

import pytest

from scripts import evaluation_pairs as ep


def feature(value, count=1):
    return dict(descriptor=dict(value=value), count=count)


@pytest.mark.parametrize("q,r,set_score,multi", [([], [], None, None), ([feature("x")], [], 0, 0), ([feature("x", 2)], [feature("x", 5)], 1, 2 / 5), ([feature("x"), feature("y")], [feature("y"), feature("z")], 1 / 3, 1 / 3), ([feature("x", 2**64 - 1)], [feature("x", 2**64 - 1)], 1, 1)])
def test_independent_hand_computed_oracle(q, r, set_score, multi):
    answer = ep.oracle(q, r)
    assert answer == dict(comparable=set_score is not None, set_similarity=set_score, multiset_similarity=multi)
    assert ep.oracle(r, q) == answer


@pytest.mark.parametrize("features", [[feature("x", 0)], [feature("x", True)], [feature("x", -1)], [feature("x"), feature("x")]])
def test_invalid_feature_counts_and_duplicates(features):
    with pytest.raises(ValueError):
        ep.oracle(features, [])


@pytest.fixture(scope="module")
def inputs():
    if not ep.catalog.executable().is_file() or not (ep.CATALOG / "catalog.json").exists():
        pytest.skip("local Step10.3 artifacts unavailable; matrix CLI integration NOT RUN")
    catalog = json.loads((ep.CATALOG / "catalog.json").read_bytes())
    manifest = json.loads((ep.ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    return manifest, catalog["records"]


def test_full_cohort_and_label_independent_feature_inputs(inputs):
    manifest, records = inputs
    jobs = ep.pair_jobs(manifest, records, {})
    assert len(jobs) == len({j["record_id"] for j in jobs}) == 436
    assert sum(j["pair"]["equivalence_label"] == "equivalent" for j in jobs) == 302
    assert sum(j["pair"]["equivalence_label"] == "non_equivalent" for j in jobs) == 134
    assert all("equivalence_label" not in j["query"] for j in jobs)
    reversed_manifest = copy.deepcopy(manifest)
    reversed_manifest["pairs"].reverse()
    assert jobs == ep.pair_jobs(reversed_manifest, list(reversed(records)), {})


@pytest.mark.parametrize("attack", ["unknown", "contradiction", "cross_split", "missing_graph", "duplicate", "self"])
def test_bad_judgments_or_cohort_are_not_admitted(inputs, attack):
    manifest, records = copy.deepcopy(inputs)
    p = manifest["pairs"][0]
    if attack == "unknown":
        p["equivalence_label"] = "unknown"
    elif attack == "contradiction":
        p["ground_truth"]["label"] = "non_equivalent"
    elif attack == "cross_split":
        p["split"] = "invalid"
    elif attack == "missing_graph":
        p["left_graph_id"] = "not-present"
    elif attack == "duplicate":
        manifest["pairs"].append(copy.deepcopy(p))
    else:
        p["right_graph_id"] = p["left_graph_id"]
    with pytest.raises(ValueError):
        ep.pair_jobs(manifest, records, {})


@pytest.mark.parametrize("condition", ["A", "B"])
def test_real_comparison_replay_reverse_and_oracle(inputs, tmp_path, condition):
    jobs = ep.pair_jobs(*inputs, {})
    job = next(j for j in jobs if j["condition"] == condition)
    first = ep.score(job, tmp_path / "first")
    again = ep.score(job, tmp_path / "again")
    assert first == again and first["status"] == "success" and first["oracle"] == "PASS"
    relative = first["artifact"]["path"]
    assert (tmp_path / "first" / relative).read_bytes() == (tmp_path / "again" / relative).read_bytes()
    reverse = copy.deepcopy(job)
    reverse["query"], reverse["reference"] = job["reference"], job["query"]
    reverse["record_id"] = ep.sha(ep.serialize(reverse))
    other = ep.score(reverse, tmp_path / "reverse")
    assert other["status"] == "success"
    assert other["primary_score"] == first["primary_score"]
    assert other["query_graph_id"] == first["reference_graph_id"]
    for view in ep.VIEWS:
        assert other["views"][view]["set_similarity"] == first["views"][view]["set_similarity"]
        assert other["views"][view]["multiset_similarity"] == first["views"][view]["multiset_similarity"]
    _, qfp, qprov = ep.load_input(job["query"], ep.CATALOG)
    _, rfp, rprov = ep.load_input(job["reference"], ep.CATALOG)
    raw = json.loads((tmp_path / "first" / relative).read_bytes())
    qid, rid = ("query", "reference") if condition == "A" else (job["query"]["graph_id"], job["reference"]["graph_id"])
    for attack in ("version", "provenance", "score", "component", "role"):
        bad = copy.deepcopy(raw)
        if attack == "version":
            bad["schema_version"] = "invalid"
        elif attack == "provenance":
            bad["query"]["provenance"] = {}
        elif attack == "score":
            bad["aggregate_multiset_similarity"] = -1
        elif attack == "component":
            bad["aggregate_components"] = []
        else:
            bad["query"]["id"] = "wrong"
        with pytest.raises(ValueError):
            ep.check_result(bad, qfp, rfp, qprov, rprov, qid, rid, condition)


def test_failed_oracle_is_not_admitted_and_output_collision(inputs, tmp_path, monkeypatch):
    jobs = ep.pair_jobs(*inputs, {})[:2]
    expected = dict(identity={}, jobs=jobs)
    monkeypatch.setattr(ep, "check_result", lambda *a: (_ for _ in ()).throw(ValueError("oracle mismatch")))
    target = tmp_path / "matrix"
    result = ep.materialize(expected, target)
    assert result["status"] == "INCOMPLETE" and all(r["status"] == "failed" and r["artifact"] is None for r in result["records"])
    assert not any(result["paired_comparable_components"].values())
    with pytest.raises(ValueError, match="collision"):
        ep.materialize(expected, target)


def test_no_comparable_semantic_views_stay_null():
    fp = {k + "_view": [] for k in ep.VIEWS}
    result = dict(schema_version="0.1.0", query=dict(id="q", provenance={}), reference=dict(id="r", provenance={}), aggregate_requested=True, aggregate_components=[], aggregate_set_similarity=None, aggregate_multiset_similarity=None)
    result.update({k: dict(comparable=False, set_similarity=None, multiset_similarity=None) for k in ep.VIEWS})
    ep.check_result(result, fp, fp, {}, {}, "q", "r", "B")
    result["aggregate_multiset_similarity"] = 0
    with pytest.raises(ValueError):
        ep.check_result(result, fp, fp, {}, {}, "q", "r", "B")
