"""Independent metric and leakage checks; no malware-performance assertion."""

import copy

import pytest

from scripts import reference_benchmark as bench


def dataset():
    cases = []
    for ident, role, digest in [("q", "query", "1"), ("r", "reference", "2"), ("n", "reference", "3")]:
        cases.append(
            dict(
                id=ident,
                split="discovery",
                source_family="source-" + ident,
                near_duplicate_group="dup-" + ident,
                binary_sha256=digest * 64,
                query_artifact="q.json" if role == "query" else None,
                reference_id=ident if role == "reference" else None,
                operational_artifact=None,
                group="fixture",
                compiler="fixture",
                optimization="none",
                annotation_source="explicit fixture oracle",
            )
        )
    pairs = [dict(query="q", reference=r, positive=r == "r", hard_negative=r == "n", annotation_source="explicit fixture oracle") for r in ("r", "n")]
    return dict(schema_version=bench.SCHEMA, description="format fixture", cases=cases, pairs=pairs)


def test_explicit_labels_and_complete_gallery():
    data = dataset()
    assert len(bench.check_dataset(data)) == 3
    data["pairs"].pop()
    with pytest.raises(ValueError, match="gallery"):
        bench.check_dataset(data)


@pytest.mark.parametrize("key", ["source_family", "near_duplicate_group", "binary_sha256"])
def test_cross_partition_leakage(key):
    data = dataset()
    extra = copy.deepcopy(data["cases"][1])
    extra.update(id="heldout-reference", reference_id="new-reference", split="heldout", source_family="new", near_duplicate_group="new", binary_sha256="4" * 64)
    extra[key] = data["cases"][1][key]
    data["cases"].append(extra)
    with pytest.raises(ValueError, match="leakage"):
        bench.check_dataset(data)


def test_same_binary_rejected():
    data = dataset()
    data["cases"][1]["binary_sha256"] = data["cases"][0]["binary_sha256"]
    with pytest.raises(ValueError, match="identical binary"):
        bench.check_dataset(data)


def test_empty_dataset_cannot_pass():
    data = dataset()
    data["cases"] = []
    data["pairs"] = []
    with pytest.raises(ValueError, match="nonempty"):
        bench.check_dataset(data)


def test_threshold_discovery_only_and_missingness():
    rows = []
    for split in bench.SPLITS:
        for positive, score in [(True, 0.8), (False, 0.2)]:
            rows.append(dict(query=split, reference=str(positive), positive=positive, hard_negative=not positive, score=score, split=split, group="one", operational=None))
    first = bench.summarize(rows, "D")
    changed = copy.deepcopy(rows)
    for row in changed:
        if row["split"] == "heldout":
            row["score"] = 1 - row["score"]
    second = bench.summarize(changed, "D")
    assert first["discovery_threshold"] == second["discovery_threshold"] == 0.8
    assert first["splits"]["heldout"]["continuous"]["auc"] == 1
    assert second["splits"]["heldout"]["continuous"]["auc"] == 0
    for row in rows:
        row["score"] = None
    missing = bench.summarize(rows, "C")
    assert missing["discovery_threshold"] is None
    assert missing["splits"]["heldout"]["classification"] is None
    assert missing["splits"]["heldout"]["retrieval"]["mrr"] == 0
    assert missing["splits"]["heldout"]["comparable_pairs"] == 0


def test_existing_refinement_does_not_create_a_continuous_score():
    rows = [dict(query="q", reference="a", positive=False, hard_negative=True, score=0.9, operational=0.1, split="discovery", group="x"), dict(query="q", reference="b", positive=True, hard_negative=False, score=0.8, operational=0.95, split="discovery", group="x")]
    b, e = bench.summarize(rows, "B"), bench.summarize(rows, "E")
    assert b["splits"]["discovery"]["retrieval"]["mrr"] == 0.5
    assert e["splits"]["discovery"]["retrieval"]["mrr"] == 1
    assert b["splits"]["discovery"]["continuous"] == e["splits"]["discovery"]["continuous"]
