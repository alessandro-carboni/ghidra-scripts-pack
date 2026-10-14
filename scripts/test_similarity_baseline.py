"""Acceptance suite for OSGF Baseline Similarity v0.1."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import unittest

from test_similarity_cli import ROOT, SimilarityCLI

VIEWS = ("rooted_topology", "typed_evidence", "interaction_motif")
FIXTURE = ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json"
GOLDEN = ROOT / "rust_engine/tests/fixtures/similarity_v0_1_golden.json"


def recount(raw):
    functions = sum(n["type"] == "FUNCTION" for n in raw["nodes"])
    raw["truncation"]["counts"] = dict(function_nodes=functions, evidence_nodes=len(raw["nodes"]) - functions, total_nodes=len(raw["nodes"]), edges=len(raw["edges"]), unresolved_calls=len(raw["unresolved_calls"]))
    return raw


def clear_unresolved(raw):
    raw["unresolved_calls"] = []
    for node in raw["nodes"]:
        if node["type"] == "VISIBILITY_INDICATOR":
            node["unresolved_indirect_callsites"] = []
    return recount(raw)


def semantic_result(result):
    """Provenance changes with source relocation/reordering; scientific results do not."""

    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if "provenance" not in k}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    return {key: strip(result[key]) for key in (*VIEWS, "aggregate_set_similarity", "aggregate_multiset_similarity", "aggregate_components")}


class SimilarityAcceptance(SimilarityCLI):
    def setUp(self):
        super().setUp()
        self.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.serial = 0
        self.base = (self.canonical, self.fingerprint)

    def build(self, raw, *flags):
        self.serial += 1
        local = self.directory / f"local-{self.serial}.json"
        canonical = self.directory / f"canonical-{self.serial}.json"
        fingerprint = self.directory / f"fingerprint-{self.serial}.json"
        local.write_text(json.dumps(recount(copy.deepcopy(raw))), encoding="utf-8")
        self.run_engine("canonicalize-local-subgraph", local, canonical)
        self.run_engine("fingerprint-canonical", canonical, fingerprint, *flags)
        return canonical, fingerprint

    def pair(self, query, reference, aggregate=True):
        self.serial += 1
        output = self.directory / f"comparison-{self.serial}.json"
        self.run_engine("compare-fingerprints", "query", *query, "reference", *reference, output, *(("--aggregate",) if aggregate else ()))
        payload = output.read_bytes()
        result = json.loads(payload)
        # Independent Python oracle checks all numerical metrics and match partitions.
        q, r = (json.loads(paths[1].read_text(encoding="utf-8")) for paths in (query, reference))
        for name in VIEWS:

            def key(f):
                return json.dumps(f["descriptor"], sort_keys=True)

            qm = {key(f): f["count"] for f in q[name + "_view"]}
            rm = {key(f): f["count"] for f in r[name + "_view"]}
            union, common = qm.keys() | rm.keys(), qm.keys() & rm.keys()
            view = result[name]
            self.assertEqual(view["comparable"], bool(union))
            if union:
                self.assertAlmostEqual(view["set_similarity"], len(common) / len(union))
                self.assertAlmostEqual(view["multiset_similarity"], sum(min(qm.get(k, 0), rm.get(k, 0)) for k in union) / sum(max(qm.get(k, 0), rm.get(k, 0)) for k in union))
            else:
                self.assertIsNone(view["set_similarity"])
                self.assertIsNone(view["multiset_similarity"])
            self.assertEqual({key(f) for f in view["matched"]}, common)
            self.assertEqual({key(f) for f in view["missing_from_query"]}, rm.keys() - qm.keys())
            self.assertEqual({key(f) for f in view["missing_from_reference"]}, qm.keys() - rm.keys())
            for match in view["matched"]:
                self.assertEqual(match["matched_count"], min(qm[key(match)], rm[key(match)]))
                self.assertEqual(sum(o["multiplicity"] for o in match["query_provenance"]), match["query_count"])
                self.assertEqual(sum(o["multiplicity"] for o in match["reference_provenance"]), match["reference_count"])
        return result, payload

    def test_identical_and_frozen_contract(self):
        result, payload = self.pair(self.base, self.base)
        for name in VIEWS:
            self.assertEqual(result[name]["set_similarity"], 1)
            self.assertEqual(result[name]["multiset_similarity"], 1)
        frozen = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(result["schema_version"], frozen["schema_version"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), frozen["identical_result_sha256"])

    def test_relocated_equivalent_input(self):
        relocated = json.loads(json.dumps(self.raw).replace("004010", "00f010").replace("004020", "001020").replace("004030", "002030"))
        baseline, _ = self.pair(self.base, self.base)
        moved, _ = self.pair(self.base, self.build(relocated))
        self.assertEqual(semantic_result(baseline), semantic_result(moved))
        self.assertNotEqual(baseline["reference"]["provenance"]["source_document"], moved["reference"]["provenance"]["source_document"])

    def test_reordered_source_preserves_science(self):
        raw = copy.deepcopy(self.raw)
        for key in ("nodes", "edges", "unresolved_calls"):
            raw[key].reverse()
        baseline, _ = self.pair(self.base, self.base)
        reordered, _ = self.pair(self.base, self.build(raw))
        self.assertEqual(semantic_result(baseline), semantic_result(reordered))

    def test_repeated_runs_are_byte_identical(self):
        for aggregate in (False, True):
            first, payload = self.pair(self.base, self.base, aggregate)
            for _ in range(3):
                repeated, data = self.pair(self.base, self.base, aggregate)
                self.assertEqual(first, repeated)
                self.assertEqual(payload, data)

    def test_same_structure_different_evidence_partial_overlap(self):
        raw = copy.deepcopy(self.raw)
        next(n for n in raw["nodes"] if n["type"] == "STRING")["value"] = "a distinct literal"
        result, _ = self.pair(self.base, self.build(raw))
        self.assertEqual(result["rooted_topology"]["set_similarity"], 1)
        self.assertGreater(result["typed_evidence"]["set_similarity"], 0)
        self.assertLess(result["typed_evidence"]["set_similarity"], 1)
        self.assertEqual(len(result["typed_evidence"]["missing_from_query"]), 1)
        self.assertEqual(len(result["typed_evidence"]["missing_from_reference"]), 1)

    def test_extra_evidence(self):
        raw = copy.deepcopy(self.raw)
        raw["nodes"].append(dict(id="api:extra", type="API", normalized_name="CloseHandle"))
        raw["edges"].append(dict(type="calls_api", source=raw["anchor_function_id"], target="api:extra"))
        result, _ = self.pair(self.base, self.build(raw))
        self.assertEqual(result["rooted_topology"]["set_similarity"], 1)
        self.assertEqual(len(result["typed_evidence"]["missing_from_query"]), 1)
        self.assertFalse(result["typed_evidence"]["missing_from_reference"])

    def test_same_evidence_different_topology(self):
        raw = copy.deepcopy(self.raw)
        raw["edges"].append(dict(type="calls_function", source=raw["anchor_function_id"], target=raw["anchor_function_id"]))
        result, _ = self.pair(self.base, self.build(raw))
        self.assertEqual(result["typed_evidence"]["set_similarity"], 1)
        self.assertLess(result["rooted_topology"]["set_similarity"], 1)
        self.assertLess(result["interaction_motif"]["set_similarity"], 1)

    def minimal(self, api=None):
        raw = copy.deepcopy(self.raw)
        anchor = raw["anchor_function_id"]
        raw["nodes"] = [dict(id=anchor, type="FUNCTION")]
        raw["edges"] = []
        raw["unresolved_calls"] = []
        raw["function_selection"] = dict(anchor_function_id=anchor, function_ids=[anchor], caller_distances={anchor: 0}, callee_distances={anchor: 0})
        raw["truncation"]["effective_depth"] = dict(caller_depth=0, callee_depth=0)
        if api:
            raw["nodes"].append(dict(id="api:other", type="API", normalized_name=api))
            raw["edges"].append(dict(type="calls_api", source=anchor, target="api:other"))
        return recount(raw)

    def test_unrelated_evidence_does_not_erase_shared_root_features(self):
        result, _ = self.pair(self.base, self.build(self.minimal("GetTickCount")))
        self.assertEqual(result["typed_evidence"]["set_similarity"], 0)
        self.assertEqual(result["interaction_motif"]["set_similarity"], 0)
        self.assertGreater(result["rooted_topology"]["set_similarity"], 0)
        self.assertLess(result["aggregate_set_similarity"], 1)

    def test_empty_views_excluded_from_aggregate(self):
        minimal = self.build(self.minimal())
        result, _ = self.pair(minimal, minimal)
        for name in ("typed_evidence", "interaction_motif"):
            self.assertFalse(result[name]["comparable"])
            self.assertIsNone(result[name]["set_similarity"])
        self.assertEqual(result["aggregate_components"], ["rooted_topology"])
        self.assertEqual(result["aggregate_set_similarity"], 1)
        one_sided, _ = self.pair(minimal, self.base)
        self.assertEqual(one_sided["typed_evidence"]["set_similarity"], 0)

    def test_count_only_changes(self):
        raw = copy.deepcopy(self.raw)
        for edge in raw["edges"]:
            if edge["type"] in ("calls_api", "calls_function"):
                edge["occurrences"] = 17
        result, _ = self.pair(self.base, self.build(raw))
        for name in VIEWS:
            self.assertEqual(result[name]["set_similarity"], 1)
        self.assertLess(result["typed_evidence"]["multiset_similarity"], 1)
        self.assertLess(result["rooted_topology"]["multiset_similarity"], 1)
        self.assertEqual(result["interaction_motif"]["multiset_similarity"], 1)

    def test_degraded_observability_does_not_penalize_similarity(self):
        resolved = self.build(clear_unresolved(copy.deepcopy(self.raw)))
        result, _ = self.pair(self.base, resolved)
        self.assertEqual(result["aggregate_set_similarity"], 1)
        self.assertEqual(result["aggregate_multiset_similarity"], 1)
        self.assertTrue(result["observability"]["query_possibly_incomplete"])
        self.assertFalse(result["observability"]["reference_possibly_incomplete"])
        self.assertTrue(result["observability"]["reference"]["indirect_calls"])

    def test_missing_qualification_and_no_fabricated_targets(self):
        raw = clear_unresolved(copy.deepcopy(self.raw))
        next(n for n in raw["nodes"] if n["type"] == "STRING")["value"] = "different"
        result, _ = self.pair(self.base, self.build(raw))
        for name in ("typed_evidence", "interaction_motif"):
            for feature in result[name]["missing_from_query"]:
                self.assertEqual(feature["qualification"], "observed_absent_with_incomplete_observability")
                self.assertTrue(feature["warnings"])
            for feature in result[name]["missing_from_reference"]:
                self.assertEqual(feature["qualification"], "observed_absent")
                self.assertFalse(feature["warnings"])
        for feature in result["observability"]["query"]["unresolved_calls"]:
            self.assertNotIn("target", feature["descriptor"])
            self.assertNotIn("callee", feature["descriptor"])
        # All semantic matches/missing descriptors were checked against actual input features by pair().

    def test_motif_truncation_qualifies_missing_evidence(self):
        clean = clear_unresolved(copy.deepcopy(self.raw))
        complete = self.build(clean)
        limited = self.build(clean, "--max-interaction-motifs", "1", "--max-topology-motifs", "0")
        result, _ = self.pair(limited, complete)
        self.assertFalse(result["observability"]["reference_possibly_incomplete"])
        for name in ("rooted_topology", "interaction_motif"):
            self.assertFalse(result[name]["comparison_complete"])
            self.assertTrue(result[name]["warnings"])
            self.assertTrue(result[name]["missing_from_query"])
            self.assertTrue(all(f["qualification"] == "observed_absent_with_incomplete_observability" for f in result[name]["missing_from_query"]))
        identical, _ = self.pair(limited, limited)
        self.assertEqual(identical["aggregate_set_similarity"], 1)
        self.assertFalse(identical["interaction_motif"]["comparison_complete"])

    def test_local_truncation_alone_qualifies_missing_feature(self):
        clean = clear_unresolved(copy.deepcopy(self.raw))
        complete = self.build(clean)
        clean["edges"] = [e for e in clean["edges"] if e["target"] != "api:virtualalloc"]
        limit = len(clean["edges"])
        clean["extraction_config"]["max_edges"] = limit
        clean["truncation"].update(truncated=True, reason="resource_limit", limits_reached=[dict(kind="edges", configured_limit=limit)])
        result, _ = self.pair(self.build(clean), complete)
        obs = result["observability"]
        self.assertFalse(obs["query"]["unresolved_calls"])
        self.assertTrue(obs["query_possibly_incomplete"])
        self.assertFalse(obs["reference_possibly_incomplete"])
        self.assertTrue(any("local graph truncated" in w for w in obs["warnings"]))
        missing = result["typed_evidence"]["missing_from_query"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["qualification"], "observed_absent_with_incomplete_observability")

    def test_resolved_provenance_points_into_correct_source(self):
        result, _ = self.pair(self.base, self.base)
        for side in ("query", "reference"):
            source = result[side]["provenance"]["source_document"]
            for name in VIEWS:
                for feature in result[name]["matched"]:
                    for occurrence in feature[side + "_provenance"]:
                        self.assertTrue(occurrence["origins"])
                        for origin in occurrence["origins"]:
                            self.assertTrue(origin["source_references"] or origin["source_metadata_paths"])
                            for ref in origin["source_references"]:
                                self.assertLess(ref["index"], len(source[ref["collection"]]))
                                for path in ref["property_paths"]:
                                    value = source
                                    for token in path.split("/")[1:]:
                                        token = token.replace("~1", "/").replace("~0", "~")
                                        value = value[int(token)] if isinstance(value, list) else value[token]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    SimilarityAcceptance.engine = args.engine.resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SimilarityAcceptance)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
