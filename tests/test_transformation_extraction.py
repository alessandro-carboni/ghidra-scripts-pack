import copy
import json
import subprocess

import pytest

from scripts import transformation_extraction as extraction


def typed():
    return dict(
        model_version="0.12.0",
        metadata=dict(research_binary_sha256="a" * 64, scope="complete_seeded_evidence_graph", truncated=False, node_count=2, edge_count=1),
        nodes=[dict(id="fn:1", type="FUNCTION"), dict(id="fn:2", type="FUNCTION")],
        edges=[dict(source="fn:1", target="fn:2", type="calls_function")],
        unresolved_calls=[],
    )


def test_valid_export_identity_does_not_invent_graph():
    document = typed()
    before = copy.deepcopy(document)
    assert extraction.validate_export(document, "a" * 64) is document
    assert extraction.select_anchor(document, {"_original": "fn:1"}, "original") == "fn:1"
    assert document == before


@pytest.mark.parametrize("change,status", [("hash", "invalid_exporter_output"), ("version", "invalid_exporter_output"), ("truncated", "incomplete_analysis"), ("counts", "incomplete_analysis"), ("edge", "invalid_exporter_output"), ("duplicate", "invalid_exporter_output")])
def test_reject_invalid_export(change, status):
    document = typed()
    if change == "hash":
        document["metadata"]["research_binary_sha256"] = "b" * 64
    elif change == "version":
        document["model_version"] = "99"
    elif change == "truncated":
        document["metadata"]["truncated"] = True
    elif change == "counts":
        document["metadata"]["node_count"] = 3
    elif change == "edge":
        document["edges"][0]["target"] = "fn:missing"
    else:
        document["nodes"][1]["id"] = "fn:1"
    with pytest.raises(extraction.ExtractionFailure) as result:
        extraction.validate_export(document, "a" * 64)
    assert result.value.status == status


@pytest.mark.parametrize("symbols,status", [({}, "missing_symbol"), ({"original": "fn:404"}, "missing_anchor"), ({"original": "fn:1", "_original": "fn:2"}, "missing_symbol")])
def test_missing_ambiguous_symbol_anchor(symbols, status):
    with pytest.raises(extraction.ExtractionFailure) as result:
        extraction.select_anchor(typed(), symbols, "original")
    assert result.value.status == status


def test_observation_does_not_infer_optimization_from_absence():
    generated = dict(generated_functions=["transformed", "helper"], transformed_function="transformed", original_function="original")
    document = typed()
    assert extraction.observe(document, {"transformed": "fn:1", "helper": "fn:2"}, generated, "function_splitting", [])["status"] == "observed"
    assert extraction.observe(document, {"transformed": "fn:1"}, generated, "function_splitting", [])["status"] == "partially_observed"
    assert extraction.observe(document, {}, generated, "function_splitting", [])["status"] == "unknown"
    for family in ("dead_branch", "instruction_reordering"):
        assert extraction.observe(document, {}, generated, family, [])["status"] == "not_observable"


@pytest.mark.parametrize("failure,status", [("timeout", "timeout"), ("process", "canonicalization_failed"), ("partial", "corrupted_graph")])
def test_canonical_timeout_partial_and_corrupt_are_not_valid_graphs(tmp_path, monkeypatch, failure, status):
    output = tmp_path / "canonical.json"

    def run(*args, **kwargs):
        output.write_text('{"partial": true}')
        if failure == "timeout":
            raise subprocess.TimeoutExpired("engine", 1)
        if failure == "process":
            raise subprocess.CalledProcessError(1, "engine")

    monkeypatch.setattr(extraction.subprocess, "run", run)
    with pytest.raises(extraction.ExtractionFailure) as result:
        extraction.canonicalize("engine", "typed.json", "fn:1", output)
    assert result.value.status == status


def test_registration_deterministic_and_conflicts_rejected(tmp_path):
    run = {"artifact_hashes": {}}
    path = tmp_path / "derived/graph.json"
    first = extraction.register_bytes(tmp_path, run, path, b'{"nodes":[]}\n')
    assert extraction.register_bytes(tmp_path, run, path, path.read_bytes()) == first
    with pytest.raises(ValueError, match="conflict"):
        extraction.register_bytes(tmp_path, run, path, b"tamper")


@pytest.mark.parametrize("failure,status", [("timeout", "timeout"), ("partial", "invalid_exporter_output"), ("process", "incomplete_analysis"), ("unavailable", "unavailable")])
def test_ghidra_failure_never_admits_partial_graph(tmp_path, monkeypatch, failure, status):
    run_dir = tmp_path / "datasets/osgf_transformations_v0_1/runs/test"
    run_dir.mkdir(parents=True)
    (run_dir / "generation.json").write_text(json.dumps({"e": {"original_function": "original", "transformed_function": "transformed"}}))
    binary = tmp_path / "program.exe"
    binary.write_bytes(b"mock input; PE validation is separately tested")
    tool = tmp_path / "tools"
    for relative in ("support/pyghidraRun.bat", "Ghidra/application.properties", "engine"):
        path = tool / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("application.version=12.0.4" if relative.endswith("properties") else "")
    exporter = tmp_path / "ghidra_scripts/export_research_graph.py"
    exporter.parent.mkdir()
    exporter.write_text("# test exporter")
    if failure == "unavailable":
        (tool / "engine").unlink()
    bundle = dict(
        runs=[dict(statuses={"build": "passed"}, artifact_hashes={}, experiment_configuration={"execution_limits": {"timeout_seconds": 1}})],
        graphs=[],
        executions=[dict(execution_id="e", transformation_id="t")],
        specifications=[dict(transformation_id="t", transformation_family="thunk")],
        builds=[dict(build_id="b", execution_id="e", architecture="x86", binary_artifact_reference="program.exe", binary_sha256=extraction.exact_hash(binary))],
    )
    monkeypatch.setattr(extraction, "load_run", lambda *args: bundle)
    monkeypatch.setattr(extraction, "verify_builds", lambda *args: None)
    monkeypatch.setattr(extraction, "persist", lambda path, value, root: value)

    def run(command, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        if failure == "process":
            raise subprocess.CalledProcessError(1, command)
        # Successful process without the full exporter outputs is still failure.
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(extraction.subprocess, "run", run)
    result = extraction.extract_run(run_dir, tool, tool / "engine", tmp_path)
    assert len(result["graphs"]) == 2
    assert all(g["extraction_status"] == status and g["canonical_graph_reference"] is None for g in result["graphs"])
    assert result["runs"][0]["statuses"]["extraction"] == "failed"


def test_real_extracted_run_reconstructs_with_existing_rust_engine():
    root = extraction.ROOT
    manifest = root / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9/manifest.json"
    engine = root / "rust_engine/target/debug/rust_engine.exe"
    if not manifest.exists() or not engine.exists():
        pytest.skip("Local real extraction/engine unavailable; not a synthetic replacement")
    bundle = json.loads(manifest.read_bytes())
    if not bundle["graphs"]:
        pytest.skip("Real Ghidra extraction has not yet completed")
    assert len(bundle["graphs"]) == 12
    assert all(g["extraction_status"] == "success" for g in bundle["graphs"])
    extraction.verify_builds(bundle)
    extraction.verify_graphs(bundle, engine)
    for graph in bundle["graphs"]:
        typed_document = json.loads((root / graph["typed_graph_reference"]).read_bytes())
        canonical = json.loads((root / graph["canonical_graph_reference"]).read_bytes())
        ids = {node["id"] for node in typed_document["nodes"]}
        assert all(node["id"] in ids for node in canonical["source_document"]["nodes"])
        assert graph["binary_sha256"] == typed_document["metadata"]["research_binary_sha256"]
