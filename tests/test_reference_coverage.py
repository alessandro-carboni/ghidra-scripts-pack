"""Independent reference-denominator oracles and source-bound coverage regressions."""

import copy
from fractions import Fraction
import itertools
import os
from pathlib import Path
import subprocess

import pytest

from scripts import graph_first as graph
from scripts import reference_coverage as rc

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "rust_engine/target/debug" / ("rust_engine.exe" if os.name == "nt" else "rust_engine")


def features(**counts):
    return [dict(descriptor=dict(value=k), count=v) for k, v in counts.items()]


def test_reference_denominator_examples_directionality_and_query_extras():
    q, r = features(a=1, b=1), features(a=1, b=1, c=1)
    assert rc.coverage(q, r)["set"] == float(Fraction(2, 3))
    assert rc.coverage(r, q)["set"] == 1
    assert rc.coverage(features(a=1, b=1, c=1, d=1), features(a=1, b=1, c=1, d=1, e=1))["set"] == 0.8
    assert rc.coverage(features(a=1, b=1, extra=99), r)["set"] == float(Fraction(2, 3))
    assert graph.jaccard(features(a=1, b=1, extra=99), r)["set_similarity"] == 0.5


def test_empty_reference_disjoint_and_identical():
    assert rc.coverage(features(a=1), [])["set"] is None
    assert rc.coverage([], [])["multiset"] is None
    assert rc.coverage([], features(a=1))["set"] == 0
    assert rc.coverage(features(b=1), features(a=1))["multiset"] == 0
    assert rc.coverage(features(a=9), features(a=9))["multiset"] == 1


def test_exhaustive_small_count_oracle_and_large_exact_totals():
    for qa, qb, ra, rb in itertools.product(range(4), repeat=4):
        q = [dict(descriptor=n, count=c) for n, c in (("a", qa), ("b", qb)) if c]
        r = [dict(descriptor=n, count=c) for n, c in (("a", ra), ("b", rb)) if c]
        result = rc.coverage(q, r)
        numerator = min(qa, ra) + min(qb, rb)
        expected = float(Fraction(numerator, ra + rb)) if ra + rb else None
        assert result["multiset"] == expected
        assert result["exact"]["multiset"] == dict(numerator=numerator, denominator=ra + rb)
    large = 2**64 - 1
    result = rc.coverage(features(a=large, b=large), features(a=large, b=large))
    assert result["exact"]["multiset"]["denominator"] == 2 * large
    assert result["multiset"] == 1


@pytest.mark.parametrize("invalid", [True, 0, -1, 1.5, float("inf")])
def test_invalid_counts_rejected(invalid):
    with pytest.raises(ValueError, match="positive integer"):
        rc.coverage(features(a=invalid), features(a=1))


def test_duplicate_descriptors_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        rc.coverage(features(a=1) + features(a=2), [])


@pytest.fixture
def make(tmp_path):
    if not ENGINE.is_file():
        pytest.skip("Rust engine unavailable; source-bound cases run in canonical-baseline CI")
    counter = itertools.count()

    def build(apis=("VirtualAlloc",), string=False, section=False, category=False, child=False, api_owner="fn:root", occurrences=1, unresolved=False, detached_section=False):
        nodes = [dict(id="fn:root", type="FUNCTION")]
        edges = []
        if child:
            nodes.append(dict(id="fn:child", type="FUNCTION"))
            edges.append(dict(type="calls_function", source="fn:root", target="fn:child", occurrences=1))
        for i, name in enumerate(apis):
            ident = f"api:{i}"
            nodes.append(dict(id=ident, type="API", normalized_name=name))
            edges.append(dict(type="calls_api", source="fn:root" if i == 0 else api_owner, target=ident, occurrences=occurrences))
        if string:
            nodes.append(dict(id="str:1", type="STRING", value="controlled literal"))
            edges.append(dict(type="references_string", source="fn:root", target="str:1", reference_count=1))
            if category:
                nodes.append(dict(id="strcat:1", type="STRING_CATEGORY", category="powershell"))
                edges.append(dict(type="has_string_category", source="str:1", target="strcat:1"))
        if section or detached_section:
            nodes.append(dict(id="sec:1", type="SECTION", name=".text", suspicious=False, read=True, write=False, execute=True, initialized=True))
            if section:
                edges.append(dict(type="belongs_to_section", source="fn:root", target="sec:1"))
        calls = []
        if unresolved:
            calls.append(dict(indicator="unresolved_call", reason="no_resolved_function_or_api_target", caller="fn:root", callee=None, callsite="00401001", direct=False, indirect=True, unresolved=True, occurrences=1))
        typed = dict(model_version="0.12.0", nodes=nodes, edges=edges, unresolved_calls=calls)
        folder = tmp_path / str(next(counter))
        index = graph.extract(typed, ENGINE, folder)
        root = next(r for r in index["records"] if r["anchor"] == "fn:root")
        return graph.load(folder / root["fingerprint"])

    return build


def test_real_projection_two_of_three_apis_and_four_of_five(make):
    q = make(apis=("VirtualAlloc", "VirtualProtect"), string=True, section=True)
    r = make(apis=("VirtualAlloc", "VirtualProtect", "WriteProcessMemory"), string=True, section=True)
    result = rc.compare(q, r, ENGINE)
    assert result["evidence_value_coverage"]["per_family"]["apis"]["set"] == float(Fraction(2, 3))
    assert result["reference_coverage"]["set"] == 0.8
    assert result["reference_coverage"]["multiset"] == 0.8
    assert result["reference_coverage"]["exact"]["set"] == dict(numerator=4, denominator=5)
    missing = result["missing_reference_evidence"]["evidence_values"]["apis"]
    assert len(missing) == 1 and missing[0]["descriptor"]["value"]["canonical_value"] == "writeprocessmemory"
    assert missing[0]["provenance"][0]["origins"]


def test_structural_attachment_is_not_value_presence(make):
    q = make(apis=("VirtualAlloc", "VirtualProtect"), child=True)
    r = make(apis=("VirtualAlloc", "VirtualProtect"), child=True, api_owner="fn:child")
    result = rc.compare(q, r, ENGINE)
    assert result["reference_coverage"]["set"] == 1
    assert result["relation_aware_coverage"]["per_view"]["typed_evidence"]["set"] < 1
    assert result["relation_aware_coverage"]["overall_if_defined"] is None


def test_derived_categories_seed_and_motifs_not_independent_votes(make):
    fp = make(string=True, category=True)
    result = rc.compare(fp, fp, ENGINE)
    assert result["reference_coverage"]["reference_distinct"] == 2
    assert result["evidence_value_coverage"]["per_family"]["string_categories"]["reference_distinct"] == 1
    assert result["relation_aware_coverage"]["per_view"]["co_observations"]["reference_distinct"] > 0
    assert result["evidence_support"]["accounting"]["reference"]["unique_normalized_base_values"] == 2


def test_section_is_scoped_and_unattached_property_does_not_become_observation(make):
    q = make(detached_section=True)
    r = make(section=True)
    result = rc.compare(q, r, ENGINE)
    assert result["evidence_value_coverage"]["per_family"]["sections"]["set"] == 0
    assert rc.compare(q, q, ENGINE)["evidence_value_coverage"]["per_family"]["sections"]["set"] is None


def test_repeated_occurrences_deficits_and_query_surplus(make):
    q, r = make(occurrences=2), make(occurrences=5)
    result = rc.compare(q, r, ENGINE)
    assert result["reference_coverage"]["set"] == 1
    assert result["reference_coverage"]["multiset"] == 0.4
    deficit = result["missing_reference_evidence"]["evidence_values"]["apis"][0]
    assert deficit["count"] == 3 and not deficit["descriptor_absent"]
    assert deficit["qualification"].startswith("observed_count_deficit")
    reverse = rc.compare(r, q, ENGINE)
    assert reverse["reference_coverage"]["multiset"] == 1
    assert reverse["additional_query_evidence"]["evidence_values"]["apis"][0]["count"] == 3


def test_unresolved_does_not_invent_api_and_existing_jaccard_unchanged(make):
    q = make(unresolved=True)
    r = make(apis=("VirtualAlloc", "VirtualProtect"))
    before = graph.compare(q, r, ENGINE)
    result = rc.compare(q, r, ENGINE)
    assert result["reference_coverage"]["set"] == 0.5
    assert result["missing_reference_evidence"]["evidence_values"]["apis"][0]["qualification"] == "observed_absent_with_incomplete_observability"
    assert graph.encoded(result["symmetric_similarity"]["original_baseline"]) == graph.encoded(before["baseline_comparison"])
    assert graph.encoded(result["symmetric_similarity"]["existing_graph_first"]) == graph.encoded(before["graph_similarity"])
    assert graph.encoded(before) == graph.encoded(graph.compare(q, r, ENGINE))


def test_determinism_reconstruction_tamper_and_cli(make, tmp_path):
    q = make(string=True)
    result = rc.compare(q, q, ENGINE)
    assert graph.encoded(result) == graph.encoded(rc.compare(q, q, ENGINE))
    rc.validate_result(result, ENGINE)
    wrong_type = copy.deepcopy(result)
    wrong_type["reference_coverage"]["set"] = True
    with pytest.raises(ValueError, match="reconstruction"):
        rc.validate_result(wrong_type, ENGINE)
    wrong_version = dict(result, schema_version="unknown")
    with pytest.raises(ValueError, match="schema"):
        rc.validate_result(wrong_version, ENGINE)
    bad = copy.deepcopy(q)
    bad["canonical"]["provenance_map"][next(iter(bad["canonical"]["provenance_map"]))] = []
    with pytest.raises(ValueError, match="reconstruction"):
        rc.compare(bad, q, ENGINE)
    result["reference_coverage"]["set"] = 0.4
    with pytest.raises(ValueError, match="reconstruction"):
        rc.validate_result(result, ENGINE)
    path, output = tmp_path / "fp.json", tmp_path / "result.json"
    graph.write(path, q)
    import sys

    command = [sys.executable, str(ROOT / "scripts/reference_coverage.py"), "compare", str(path), str(path), "--engine", str(ENGINE), "--output", str(output)]
    p = subprocess.run(command, capture_output=True, check=False)
    assert p.returncode == 0, p.stderr
    original = output.read_bytes()
    p = subprocess.run(command, capture_output=True, check=False)
    assert p.returncode != 0 and output.read_bytes() == original


def test_truncated_query_is_qualified_and_never_imputed(make, tmp_path):
    reference = make(apis=("VirtualAlloc", "VirtualProtect"))
    typed = reference["seed_origin"]["graph"]
    report, folder = tmp_path / "report.json", tmp_path / "truncated"
    graph.write(report, dict(typed_graph=typed))
    graph.command(ENGINE, "export-local-subgraphs", report, folder, "--max-evidence-nodes", 0)
    manifest = graph.load(folder / "manifest.json")
    local = graph.load(folder / manifest["subgraphs"][0]["file"])
    query = graph.fingerprint(local, ENGINE, typed)
    result = rc.compare(query, reference, ENGINE)
    assert result["reference_coverage"]["set"] == 0
    assert result["evidence_support"]["legacy"]["query"]["local_truncation"]["truncated"]
    assert all(m["qualification"] == "observed_absent_with_incomplete_observability" for m in result["missing_reference_evidence"]["evidence_values"]["apis"])


def test_existing_contextual_constants_projection(make):
    local = graph.load(ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json")
    fp = graph.fingerprint(local, ENGINE)
    result = rc.compare(fp, fp, ENGINE)
    constants = result["evidence_value_coverage"]["per_family"]["contextual_constants"]
    assert constants["reference_distinct"] == 1 and constants["set"] == 1
