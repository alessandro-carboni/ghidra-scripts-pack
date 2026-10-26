"""Step 10.0 inventory and judged-neighborhood checks, not benchmark metrics."""

import copy
import json
import subprocess
import sys

import pytest

from scripts.evaluation_preflight import ROOT, AUDIT_DIR, build_audit, judged_galleries, serialize


def toy():
    graphs = [dict(graph_id=g, sample_id=g, split="discovery_train", canonical_digest=g) for g in "abcd"]

    def pair(left, right, label):
        return dict(pair_id=left + right, left_graph_id=left, right_graph_id=right, equivalence_label=label, split="discovery_train", validation_status="automatically_grounded", ground_truth={"label": label})

    return dict(graphs=graphs, samples=[dict(sample_id=g, sha256=g) for g in "abcd"], pairs=[pair("a", "b", "equivalent"), pair("a", "c", "non_equivalent"), pair("b", "d", "equivalent")])


def test_unjudged_pairs_are_not_negative_or_transitive_and_k_is_explicit():
    data = toy()
    before = copy.deepcopy(data)
    audit = judged_galleries(data)
    byid = {q["query_graph_id"]: q for q in audit["queries"]}
    assert [c["reference_graph_id"] for c in byid["a"]["candidates"]] == ["b", "c"]
    assert byid["a"]["gallery_size"] == 2
    assert not byid["c"]["eligible"]
    assert audit["summary"]["discovery_train"]["eligible_queries"] == 3
    assert audit["summary"]["discovery_train"]["candidates_at_least"] == {"1": 3, "3": 0, "5": 0}
    assert data == before
    data["pairs"].reverse()
    data["graphs"].reverse()
    assert serialize(judged_galleries(data)) == serialize(audit)


@pytest.mark.parametrize("attack", ["duplicate", "cross_split", "unknown", "contradictory", "self"])
def test_invalid_judgments_fail(attack):
    data = toy()
    if attack == "duplicate":
        p = copy.deepcopy(data["pairs"][0])
        p["pair_id"] = "reversed"
        p["left_graph_id"], p["right_graph_id"] = p["right_graph_id"], p["left_graph_id"]
        data["pairs"].append(p)
    elif attack == "cross_split":
        data["graphs"][0]["split"] = "held_out_test"
    elif attack == "unknown":
        data["pairs"][0]["equivalence_label"] = "unknown"
    elif attack == "contradictory":
        data["pairs"][0]["ground_truth"]["label"] = "non_equivalent"
    else:
        data["pairs"][0]["right_graph_id"] = "a"
    with pytest.raises(ValueError):
        judged_galleries(data)


def test_unadmitted_pairs_and_exclusion_sensitivities_are_not_relabels():
    data = toy()
    data["pairs"][0]["validation_status"] = "ambiguous"
    assert not judged_galleries(data)["queries"][0]["eligible"]
    data = toy()
    data["graphs"][1]["canonical_digest"] = "a"
    data["samples"][1]["sha256"] = "a"
    assert judged_galleries(data)["queries"][0]["eligible"]
    for scenario in ("equal_canonical_digest", "same_binary"):
        assert not judged_galleries(data, scenario)["queries"][0]["eligible"]
    assert data["pairs"][0]["equivalence_label"] == "equivalent"


def test_real_frozen_inputs_and_audit_reproduce_exactly():
    expected = (ROOT / AUDIT_DIR / "preliminary_audit.json").read_bytes()
    assert serialize(build_audit()) == expected
    data = json.loads(expected)
    assert len(data["frozen_input_inventory"]["scientific_files"]) == 161
    assert data["counts"]["pairs"] == 218
    assert sum(q["gallery_size"] for q in data["galleries"]["identity_only"]["queries"]) == 436
    assert data["galleries"]["identity_only"]["summary"]["validation"]["candidates_at_least"]["5"] == 4
    assert data["galleries"]["equal_canonical_digest"]["summary"]["validation"]["candidates_at_least"]["5"] == 0


@pytest.mark.parametrize("input_kind", ["typed", "local", "forged"])
def test_frozen_cli_rejects_noncanonical_inputs_without_output(tmp_path, input_kind):
    engine = ROOT / ("rust_engine/target/debug/rust_engine.exe" if sys.platform == "win32" else "rust_engine/target/debug/rust_engine")
    if not engine.is_file():
        pytest.skip("Rust executable unavailable; actual CLI probe NOT RUN")
    local_fixture = ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json"
    fixture = tmp_path / "canonical.json"
    subprocess.run([str(engine), "canonicalize-local-subgraph", str(local_fixture), str(fixture)], capture_output=True, check=True, timeout=120)
    canonical = json.loads(fixture.read_bytes())
    if input_kind == "typed":
        invalid = json.loads((ROOT / "rust_engine/tests/fixtures/seed_detection.json").read_bytes())
    elif input_kind == "local":
        invalid = canonical["source_document"]
    else:
        invalid = copy.deepcopy(canonical)
        invalid["nodes"][0]["id"] = "forged-no-normalization"
    source = tmp_path / "invalid.json"
    source.write_bytes(serialize(invalid))
    original = source.read_bytes()
    output = tmp_path / "invalid-fingerprint.json"
    result = subprocess.run([str(engine), "fingerprint-canonical", str(source), str(output)], capture_output=True, text=True, check=False)
    assert result.returncode != 0 and "canonical" in result.stderr.lower()
    assert not output.exists() and not output.with_name(output.name + ".provenance.json").exists()
    valid = tmp_path / "fixture-fingerprint.json"
    subprocess.run([str(engine), "fingerprint-canonical", str(fixture), str(valid)], capture_output=True, check=True)
    comparison = tmp_path / "invalid-comparison.json"
    result = subprocess.run([str(engine), "compare-fingerprints", "q", str(source), str(valid), "r", str(fixture), str(valid), str(comparison), "--aggregate"], capture_output=True, text=True, check=False)
    assert result.returncode != 0 and not comparison.exists()
    assert source.read_bytes() == original
    print(f"{input_kind}: fingerprint and comparison rejected noncanonical input; no result written")
