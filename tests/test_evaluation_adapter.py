"""Step 10.2 synthetic comparability gates; never load corpus scores or labels."""

import copy
import json
import subprocess
import sys

import pytest

from scripts import evaluation_adapter as adapter
from scripts.test_fingerprint_baseline import pointer


def recount(local):
    functions = sum(n["type"] == "FUNCTION" for n in local["nodes"])
    local["truncation"]["counts"] = dict(function_nodes=functions, evidence_nodes=len(local["nodes"]) - functions, total_nodes=len(local["nodes"]), edges=len(local["edges"]), unresolved_calls=len(local["unresolved_calls"]))


ROOT = adapter.ROOT
VIEWS = ["rooted_topology_view", "typed_evidence_view", "interaction_motif_view"]
ENGINE = ROOT / "rust_engine/target/debug" / ("rust_engine.exe" if sys.platform == "win32" else "rust_engine")


def invoke(engine, *args, success=True):
    result = subprocess.run([str(engine), *map(str, args)], capture_output=True, timeout=120)
    assert (result.returncode == 0) == success, result.stderr.decode(errors="replace")
    return result.stdout


@pytest.fixture(scope="module")
def engine():
    if not ENGINE.is_file():
        pytest.skip("build the frozen Rust engine first; research parity NOT RUN")
    adapter.prepare()
    subprocess.run(["cargo", "build", "--offline", "--locked", "--manifest-path", str(adapter.BUILD / "Cargo.toml")], check=True, capture_output=True, timeout=180)
    return adapter.executable()


@pytest.fixture
def local():
    return json.loads((ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json").read_bytes())


def extract(engine, tmp, local, condition="A", limits=()):
    path = tmp / "local.json"
    path.write_bytes(adapter.serialize(local))
    before = path.read_bytes()
    raw = invoke(engine, "extract", condition, path, *limits)
    assert path.read_bytes() == before
    return json.loads(raw), raw


def compare(engine, tmp, q, r):
    qp, rp = tmp / "query.json", tmp / "reference.json"
    qp.write_bytes(adapter.serialize(q))
    rp.write_bytes(adapter.serialize(r))
    raw = invoke(engine, "compare", qp, rp)
    assert raw == invoke(engine, "compare", qp, rp)
    return json.loads(raw)


def test_pinned_sources_and_unchanged_feature_algorithms():
    assert adapter.source_inventory() == json.loads((adapter.METHOD / "source_inventory.json").read_bytes())
    for module in ("fingerprint_motifs", "similarity_observability"):
        original = (ROOT / f"rust_engine/src/{module}.rs").read_text(encoding="utf-8").split("#[cfg(test)]\nmod tests", 1)[0]
        assert adapter.transformed(module) == original.replace("CanonicalSubgraph", "ResearchGraph").replace("OsgfFingerprint", "ResearchFingerprint")


@pytest.mark.parametrize("limits", [(), (0, 0), (1, 2)])
def test_B_matches_frozen_features_counts_provenance_and_budgets(engine, tmp_path, local, limits):
    b, _ = extract(engine, tmp_path, local, "B", limits)
    canonical, fingerprint = tmp_path / "canonical.json", tmp_path / "frozen.json"
    invoke(ENGINE, "canonicalize-local-subgraph", tmp_path / "local.json", canonical)
    flags = ("--max-topology-motifs", limits[0], "--max-interaction-motifs", limits[1]) if limits else ()
    invoke(ENGINE, "fingerprint-canonical", canonical, fingerprint, *flags)
    frozen = json.loads(fingerprint.read_bytes())
    for key in VIEWS + ["observability_view", "config", "motif_truncation", "provenance_index", "canonical_coverage", "source_coverage_totals"]:
        assert b["fingerprint"][key] == frozen[key], key
    origins = json.loads(fingerprint.with_name(fingerprint.name + ".provenance.json").read_bytes())
    for key in ("features", "source_document", "canonical_source_coverage"):
        assert b["provenance"][key] == origins[key]


@pytest.mark.parametrize("limits", [(), (0, 0), (1, 2)])
def test_noop_parity_and_identical_metric_algorithm(engine, tmp_path, local, limits):
    sections = {n["id"] for n in local["nodes"] if n["type"] == "SECTION"}
    local["nodes"] = [n for n in local["nodes"] if n["id"] not in sections]
    local["edges"] = [e for e in local["edges"] if e["target"] not in sections]
    recount(local)
    for n in local["nodes"]:
        if n["type"] == "API":
            n["normalized_name"] = n["normalized_name"].lower()
        if n["type"] == "CONSTANT":
            n.pop("category", None)
            n.pop("symbolic_names", None)
    a, _ = extract(engine, tmp_path, local, "A", limits)
    b, _ = extract(engine, tmp_path, local, "B", limits)
    for key in VIEWS + ["observability_view", "motif_truncation"]:
        assert a["fingerprint"][key] == b["fingerprint"][key]
    for bundle in (a, b):
        result = compare(engine, tmp_path, bundle, bundle)
        assert result["aggregate_multiset_similarity"] == result["aggregate_set_similarity"] == 1.0
        for name in ("rooted_topology", "typed_evidence", "interaction_motif"):
            assert not result[name]["missing_from_query"] and not result[name]["missing_from_reference"]


@pytest.mark.parametrize("condition", ["A", "B"])
def test_relocation_permutation_determinism_and_unknown_targets(engine, tmp_path, local, condition):
    original, raw = extract(engine, tmp_path, local, condition)
    assert raw == extract(engine, tmp_path, local, condition)[1]
    moved = json.loads(json.dumps(local).replace("004010", "00f010").replace("004020", "001020").replace("004030", "002030"))
    for key in ("nodes", "edges", "unresolved_calls"):
        moved[key].reverse()
    changed, _ = extract(engine, tmp_path, moved, condition)
    assert original["fingerprint"] == changed["fingerprint"]
    assert original["provenance"]["source_document"] != changed["provenance"]["source_document"]
    assert all("target" not in u for u in original["graph"]["unresolved_calls"])
    for occurrences in original["provenance"]["features"].values():
        for occurrence in occurrences:
            for origin in occurrence["origins"]:
                for ref in origin["source_references"]:
                    for path in ref["property_paths"]:
                        pointer(original["provenance"]["source_document"], path)


def test_API_collision_is_visible_only_in_A_and_counts_preserved(engine, tmp_path, local):
    original = copy.deepcopy(local)
    node = next(n for n in local["nodes"] if n.get("normalized_name") == "WriteProcessMemory")
    node["name"] = "KERNEL32.dll!__imp__WriteProcessMemory@20"
    for condition, equal in [("A", False), ("B", True)]:
        baseline, _ = extract(engine, tmp_path, original, condition)
        changed, _ = extract(engine, tmp_path, local, condition)
        assert (baseline["fingerprint"]["typed_evidence_view"] == changed["fingerprint"]["typed_evidence_view"]) == equal
    duplicate = copy.deepcopy(node)
    duplicate["id"] = "api:duplicate"
    duplicate["name"] = "writeprocessmemory"
    local["nodes"].append(duplicate)
    local["edges"].append(dict(type="calls_api", source=local["anchor_function_id"], target=duplicate["id"], occurrences=3))
    recount(local)
    for condition in ("A", "B"):
        bundle, _ = extract(engine, tmp_path, local, condition)
        counts = [f["count"] for f in bundle["fingerprint"]["typed_evidence_view"]]
        assert 3 in counts
        ledger = bundle["graph"]["coverage_ledger"]
        assert ledger["source_nodes"] == len(local["nodes"])
        apis = [n for n in bundle["graph"]["nodes"] if n["kind"] == "API"]
        assert len(apis) == (3 if condition == "A" else 2)


@pytest.mark.parametrize("condition", ["A", "B"])
def test_exact_strings_constants_and_count_sensitivity(engine, tmp_path, local, condition):
    first, _ = extract(engine, tmp_path, local, condition)
    string = next(n for n in local["nodes"] if n["type"] == "STRING")
    string["value"] = "  MiXeD\t\u00e8\n"
    constant = next(n for n in local["nodes"] if n["type"] == "CONSTANT")
    constant["value"] = 65
    second, _ = extract(engine, tmp_path, local, condition)
    assert {n["facts"]["normalized"] for n in second["graph"]["nodes"] if n["kind"] == "STRING"} == {string["value"]}
    assert {n["facts"]["literal"] for n in second["graph"]["nodes"] if n["kind"] == "CONSTANT"} == {65}
    assert first["fingerprint"]["typed_evidence_view"] != second["fingerprint"]["typed_evidence_view"]
    edge = next(e for e in local["edges"] if e["type"] == "calls_api")
    edge["occurrences"] = 7
    third, _ = extract(engine, tmp_path, local, condition)
    result = compare(engine, tmp_path, second, third)
    assert result["typed_evidence"]["set_similarity"] == 1.0
    assert result["typed_evidence"]["multiset_similarity"] < 1.0


@pytest.mark.parametrize("attack", ["condition", "count", "origin", "input", "version"])
def test_forgery_rejected_with_no_result(engine, tmp_path, local, attack):
    bundle, _ = extract(engine, tmp_path, local)
    if attack == "condition":
        bundle["graph"]["condition"] = "B"
    elif attack == "count":
        bundle["fingerprint"]["typed_evidence_view"][0]["count"] += 1
    elif attack == "origin":
        bundle["provenance"]["features"] = {}
    elif attack == "input":
        bundle["input_json"] += " "
    else:
        bundle["schema_version"] = "0.1.0"
    path = tmp_path / "forged.json"
    path.write_bytes(adapter.serialize(bundle))
    assert invoke(engine, "validate", path, success=False) == b""


@pytest.mark.parametrize("condition", ["A", "B"])
def test_blank_one_sided_views_and_motif_limits(engine, tmp_path, local, condition):
    full, _ = extract(engine, tmp_path, local, condition)
    empty = copy.deepcopy(local)
    empty["nodes"] = [n for n in empty["nodes"] if n["type"] == "FUNCTION"]
    empty["edges"] = [e for e in empty["edges"] if e["type"] == "calls_function"]
    empty["unresolved_calls"] = []
    recount(empty)
    bare, _ = extract(engine, tmp_path, empty, condition)
    for q, r, score in [(bare, bare, None), (bare, full, 0.0)]:
        result = compare(engine, tmp_path, q, r)
        assert result["typed_evidence"]["set_similarity"] == score
        assert result["typed_evidence"]["multiset_similarity"] == score
    limited, _ = extract(engine, tmp_path, local, condition, (0, 0))
    assert any(m["truncated"] for m in limited["fingerprint"]["motif_truncation"].values())
    assert limited["fingerprint"]["interaction_motif_view"] == []
    assert full["fingerprint"]["typed_evidence_view"] == limited["fingerprint"]["typed_evidence_view"]


def test_metric_oracle_and_nontrivial_B_frozen_comparison(engine, tmp_path, local):
    other = copy.deepcopy(local)
    next(n for n in other["nodes"] if n["type"] == "STRING")["value"] = "different literal"
    next(e for e in other["edges"] if e["type"] == "calls_api")["occurrences"] = 9
    for condition in ("A", "B"):
        q, _ = extract(engine, tmp_path, local, condition)
        r, _ = extract(engine, tmp_path, other, condition)
        result = compare(engine, tmp_path, q, r)
        for key in VIEWS:

            def counts(bundle):
                return {json.dumps(f["descriptor"], sort_keys=True): f["count"] for f in bundle["fingerprint"][key]}

            left, right = counts(q), counts(r)
            union = left.keys() | right.keys()
            view = result[key.removesuffix("_view")]
            expected_set = len(left.keys() & right.keys()) / len(union) if union else None
            den = sum(max(left.get(k, 0), right.get(k, 0)) for k in union)
            expected_multi = sum(min(left.get(k, 0), right.get(k, 0)) for k in union) / den if den else None
            assert view["set_similarity"] == expected_set
            assert view["multiset_similarity"] == expected_multi
        if condition == "B":
            for name, source in [("q", local), ("r", other)]:
                lp, cp, fp = (tmp_path / (name + suffix + ".json") for suffix in ("local", "canonical", "fp"))
                lp.write_bytes(adapter.serialize(source))
                invoke(ENGINE, "canonicalize-local-subgraph", lp, cp)
                invoke(ENGINE, "fingerprint-canonical", cp, fp)
            output = tmp_path / "frozen-comparison.json"
            invoke(ENGINE, "compare-fingerprints", "query", tmp_path / "qcanonical.json", tmp_path / "qfp.json", "reference", tmp_path / "rcanonical.json", tmp_path / "rfp.json", output, "--aggregate")
            frozen = json.loads(output.read_bytes())
            for key in [k.removesuffix("_view") for k in VIEWS] + ["aggregate_set_similarity", "aggregate_multiset_similarity", "aggregate_components", "observability_warnings"]:
                assert result[key] == frozen[key]


def test_lexical_semantic_confound_is_explicit_and_not_inferred(engine, tmp_path, local):
    q_a, _ = extract(engine, tmp_path, local, "A")
    q_b, _ = extract(engine, tmp_path, local, "B")
    next(n for n in local["nodes"] if n["type"] == "SECTION")["name"] = ".text"
    next(n for n in local["nodes"] if n["type"] == "CONSTANT")["symbolic_names"].append("UNRECOGNIZED_ALIAS")
    r_a, _ = extract(engine, tmp_path, local, "A")
    r_b, _ = extract(engine, tmp_path, local, "B")
    assert q_a["fingerprint"]["typed_evidence_view"] != r_a["fingerprint"]["typed_evidence_view"]
    assert q_b["fingerprint"]["typed_evidence_view"] == r_b["fingerprint"]["typed_evidence_view"]
    assert q_a["fingerprint"]["rooted_topology_view"] == r_a["fingerprint"]["rooted_topology_view"]


def test_research_output_cannot_enter_frozen_CLI_or_mix_conditions(engine, tmp_path, local):
    a, _ = extract(engine, tmp_path, local, "A")
    b, _ = extract(engine, tmp_path, local, "B")
    ap, bp = tmp_path / "a.json", tmp_path / "b.json"
    ap.write_bytes(adapter.serialize(a))
    bp.write_bytes(adapter.serialize(b))
    assert invoke(engine, "compare", ap, bp, success=False) == b""
    graph = tmp_path / "research-graph.json"
    graph.write_bytes(adapter.serialize(a["graph"]))
    output = tmp_path / "forbidden.json"
    invoke(ENGINE, "fingerprint-canonical", graph, output, success=False)
    assert not output.exists()
    invoke(engine, "extract", "unknown", tmp_path / "local.json", success=False)


def test_raw_section_missing_is_not_literal_unknown_and_malformed_fails(engine, tmp_path, local):
    section = next(n for n in local["nodes"] if n["type"] == "SECTION")
    section.pop("name")
    missing, _ = extract(engine, tmp_path, local)
    section["name"] = "unknown"
    literal, _ = extract(engine, tmp_path, local)
    assert missing["fingerprint"]["typed_evidence_view"] != literal["fingerprint"]["typed_evidence_view"]
    section["name"] = 42
    path = tmp_path / "malformed.json"
    path.write_bytes(adapter.serialize(local))
    assert invoke(engine, "extract", "A", path, success=False) == b""


@pytest.mark.parametrize("left,right", [("CreateFileA", "CreateFileW"), ("NtOpenFile", "ZwOpenFile")])
def test_semantically_distinct_api_names_are_never_conflated(engine, tmp_path, local, left, right):
    node = next(n for n in local["nodes"] if n["type"] == "API")
    for condition in ("A", "B"):
        node["name"] = left
        a, _ = extract(engine, tmp_path, local, condition)
        node["name"] = right
        b, _ = extract(engine, tmp_path, local, condition)
        assert a["fingerprint"]["typed_evidence_view"] != b["fingerprint"]["typed_evidence_view"]
