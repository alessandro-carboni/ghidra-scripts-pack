"""Source-bound synthetic format fixtures; never asserted to be malware binaries."""

import copy
import os
from pathlib import Path

import pytest

from scripts import graph_first as graph
from scripts import reference_library as lib

ENGINE = Path(__file__).resolve().parents[1] / "rust_engine/target/debug" / ("rust_engine.exe" if os.name == "nt" else "rust_engine")


@pytest.fixture
def fixture(tmp_path):
    if not ENGINE.is_file():
        pytest.skip("Rust engine required for source-validated library tests")
    sample = tmp_path / "benign-fixture.txt"
    sample.write_bytes(b"Explicit synthetic extraction fixture, not executable or malware.\n")
    typed = dict(model_version="0.12.0", metadata=dict(research_binary_sha256=lib.sha(sample.read_bytes())), nodes=[dict(id="fn:root", type="FUNCTION"), dict(id="api:1", type="API", normalized_name="VirtualAlloc")], edges=[dict(type="calls_api", source="fn:root", target="api:1", occurrences=1)], unresolved_calls=[])
    folder = tmp_path / "extracted"
    index = graph.extract(typed, ENGINE, folder)
    artifact = folder / index["records"][0]["fingerprint"]
    annotation = dict(
        sample=dict(sha256=lib.sha(sample.read_bytes()), executable_format="synthetic non-executable fixture", architecture="synthetic", source="pytest fixture source", acquisition_date="2026-11-11", authorization_or_provenance="locally authored format fixture", family_label_if_known=None),
        functional_region=dict(
            region_id="fixture-root", analyst_annotation="synthetic API observation", described_functionality="format validation only", annotation_source="test fixture construction", annotation_status="unreviewed", annotation_confidence_or_uncertainty="no binary functionality claim", classification="unknown"
        ),
        extraction_tool_version="test fixture + current Rust engine",
        provenance_reference="tests/test_reference_library.py",
    )
    root = tmp_path / "library"
    lib.init(root)
    return root, sample, artifact, annotation, typed


def register(fixture):
    root, sample, artifact, annotation, _ = fixture
    return lib.register(root, artifact, sample, annotation, ENGINE)


def test_registration_validation_duplicate_and_lock_cleanup(fixture):
    entry = register(fixture)
    root = fixture[0]
    assert lib.validate(root, ENGINE) == [entry]
    assert entry["functional_region"]["classification"] == "unknown"
    before = (root / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="duplicate"):
        register(fixture)
    assert (root / "manifest.json").read_bytes() == before
    assert not (root / "register.lock").exists()


def test_source_hash_and_schema_rejection(fixture):
    root, sample, artifact, annotation, _ = fixture
    bad = copy.deepcopy(annotation)
    bad["sample"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="source hash"):
        lib.register(root, artifact, sample, bad, ENGINE)
    with pytest.raises(ValueError, match="incompatible"):
        lib.graph_artifact(dict(schema_version="unknown/99"), ENGINE)
    bad = copy.deepcopy(annotation)
    bad["functional_region"]["classification"] = "documented_malicious_functionality"
    with pytest.raises(ValueError, match="verified"):
        lib.validate_annotation(bad)


def test_multiple_regions_ties_determinism_and_unavailable(fixture):
    entry = register(fixture)
    root, sample, artifact, annotation, _ = fixture
    second = copy.deepcopy(annotation)
    second["functional_region"]["region_id"] = "second-annotation"
    second["sample"]["family_label_if_known"] = "uncertain fixture grouping"
    lib.register(root, artifact, sample, second, ENGINE)
    query = graph.load(artifact)
    first = lib.search(query, root, ENGINE)
    assert graph.encoded(first) == graph.encoded(lib.search(query, root, ENGINE))
    assert first["candidate_count"] == first["tied_candidate_count"] == 2
    ids = [r["reference"] for r in first["candidates"]]
    assert ids == sorted(ids)
    assert all(r["score"] == 1 for r in first["candidates"])
    assert all("positive" not in r for r in first["candidates"])
    (root / entry["fingerprint"]["artifact"]["path"]).unlink()
    missing = lib.search(query, root, ENGINE)
    assert missing["candidate_count"] == 0
    assert len(missing["excluded_references"]) == 2
    assert {r["status"] for r in missing["excluded_references"]} == {"unavailable"}


def test_tampering_never_compared(fixture):
    entry = register(fixture)
    root = fixture[0]
    path = root / entry["fingerprint"]["artifact"]["path"]
    query = graph.load(path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="artifact hash"):
        lib.validate(root, ENGINE)
    result = lib.search(query, root, ENGINE)
    assert result["candidate_count"] == 0
    assert result["excluded_references"][0]["status"] == "invalid"


def test_distinct_samples_same_family_do_not_create_functional_labels(fixture, tmp_path):
    root, _, _, annotation, typed = fixture
    annotation["sample"]["family_label_if_known"] = "uncertain shared fixture family"
    first = register(fixture)
    second_sample = tmp_path / "second-format-fixture.txt"
    second_sample.write_bytes(b"distinct non-executable source fixture")
    second_annotation = copy.deepcopy(annotation)
    second_annotation["sample"]["sha256"] = lib.sha(second_sample.read_bytes())
    second_graph = copy.deepcopy(typed)
    second_graph["metadata"]["research_binary_sha256"] = second_annotation["sample"]["sha256"]
    folder = tmp_path / "second-extraction"
    index = graph.extract(second_graph, ENGINE, folder)
    second = lib.register(root, folder / index["records"][0]["fingerprint"], second_sample, second_annotation, ENGINE)
    assert first["reference_id"] != second["reference_id"]
    entries = lib.validate(root, ENGINE)
    assert len(entries) == 2
    assert all(e["functional_region"]["classification"] == "unknown" for e in entries)
    assert all("positive" not in e and "equivalent" not in e for e in entries)


def test_frozen_adapter_preserves_bytes(fixture, tmp_path):
    root, sample, artifact, annotation, _ = fixture
    fp = graph.load(artifact)
    path = tmp_path / "frozen.json"
    graph.write(path, dict(schema_version=lib.FROZEN, canonical=fp["canonical"], fingerprint=fp["baseline"], origin_graph=fp["seed_origin"]["graph"]))
    raw = path.read_bytes()
    entry = lib.register(root, path, sample, annotation, ENGINE)
    assert (root / entry["fingerprint"]["artifact"]["path"]).read_bytes() == raw
    assert lib.validate(root, ENGINE) == [entry]


@pytest.mark.parametrize("relative", ["../outside", "C:/outside", "artifacts/../../outside"])
def test_path_escape_rejected(tmp_path, relative):
    with pytest.raises(ValueError):
        lib.safe_path(tmp_path, relative)


def test_workflow_multiple_and_missing_seeds(fixture, tmp_path):
    register(fixture)
    root, _, _, _, typed = fixture
    typed = copy.deepcopy(typed)
    typed["nodes"].append(dict(id="fn:second", type="FUNCTION"))
    typed["edges"].append(dict(type="calls_api", source="fn:second", target="api:1", occurrences=1))
    result = lib.workflow(typed, root, ENGINE, tmp_path / "multi")
    assert result["eligible"]
    assert len(result["query_subgraphs"]) == 2
    assert result["executable_score"] is None
    typed["edges"] = []
    typed["nodes"] = [dict(id="fn:root", type="FUNCTION")]
    result = lib.workflow(typed, root, ENGINE, tmp_path / "none")
    assert result["status"] == "no_eligible_seed"
    assert result["query_subgraphs"] == []


@pytest.mark.parametrize("policy", lib.POLICIES)
def test_self_search_policies(fixture, policy):
    register(fixture)
    result = lib.search(graph.load(fixture[2]), fixture[0], ENGINE, policy)
    assert result["candidates"][0]["score"] == 1


def test_preregistered_benchmark_repeats_and_detects_mutation(fixture, tmp_path):
    from scripts import reference_benchmark as bench

    entry = register(fixture)
    root, _, _, _, typed = fixture
    typed = copy.deepcopy(typed)
    query_bytes = b"separate synthetic query provenance"
    query_hash = lib.sha(query_bytes)
    typed["metadata"]["research_binary_sha256"] = query_hash
    folder = tmp_path / "query"
    index = graph.extract(typed, ENGINE, folder)
    common = dict(split="discovery", source_family="fixture", near_duplicate_group="fixture", operational_artifact=None, group="format", compiler="none", optimization="none", annotation_source="synthetic construction, not scientific labels")
    cases = [dict(**common, id="q", binary_sha256=query_hash, query_artifact="query/" + index["records"][0]["fingerprint"], reference_id=None), dict(**common, id="r", binary_sha256=entry["sample"]["sha256"], query_artifact=None, reference_id=entry["reference_id"])]
    data = tmp_path / "dataset.json"
    graph.write(data, dict(schema_version=bench.SCHEMA, description="synthetic mechanics only", cases=cases, pairs=[dict(query="q", reference="r", positive=True, hard_negative=False, annotation_source="explicit synthetic identity")]))
    registration = tmp_path / "registration.json"
    bench.preregister(data, root, ENGINE, registration)
    first = bench.run(data, root, ENGINE, registration, tmp_path / "first")
    second = bench.run(data, root, ENGINE, registration, tmp_path / "second")
    assert graph.encoded(first) == graph.encoded(second)
    assert first["summary"]["D"]["splits"]["discovery"]["retrieval"]["mrr"] == 1
    assert first["summary"]["C"]["splits"]["discovery"]["comparable_pairs"] == 0
    assert first["summary"]["D"]["discovery_threshold"] is None
    data.write_bytes(data.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed"):
        bench.run(data, root, ENGINE, registration, tmp_path / "third")

    typed["nodes"] = [dict(id="fn:root", type="FUNCTION")]
    typed["edges"] = []
    graph.extract(typed, ENGINE, tmp_path / "no-seed")
    spec = graph.load(data)
    spec["cases"][0]["query_artifact"] = "no-seed/index.json"
    no_seed_data = tmp_path / "no-seed-dataset.json"
    graph.write(no_seed_data, spec)
    no_seed_registration = tmp_path / "no-seed-registration.json"
    bench.preregister(no_seed_data, root, ENGINE, no_seed_registration)
    missing = bench.run(no_seed_data, root, ENGINE, no_seed_registration, tmp_path / "missing")
    assert missing["seed_coverage"]["eligible_regions"] == 0
    assert missing["seed_coverage"]["query_regions"] == 1
    assert all(row["score"] is None for rows in missing["rows"].values() for row in rows)
