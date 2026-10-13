"""CLI acceptance suite for OSGF Fingerprint Baseline v0.1; standard library only."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOCAL_FIXTURE = ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json"
GOLDEN = ROOT / "rust_engine/tests/fixtures/fingerprint_v0_1_digests.json"
SEMANTIC_FIELDS = ("schema_version", "canonicalization_version", "rooted_topology_view", "typed_evidence_view", "interaction_motif_view")


def sha256(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def pointer(value, path):
    for token in path.split("/")[1:]:
        key = token.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


class FingerprintAcceptance(unittest.TestCase):
    engine = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="osgf-acceptance-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.local = json.loads(LOCAL_FIXTURE.read_text(encoding="utf-8"))

    def run_engine(self, *arguments, success=True):
        result = subprocess.run([str(self.engine), *map(str, arguments)], capture_output=True, text=True, timeout=120, check=False)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def canonical(self, local=None):
        path = self.directory / "local.json"
        output = self.directory / "canonical.json"
        path.write_text(json.dumps(self.local if local is None else local), encoding="utf-8")
        self.run_engine("canonicalize-local-subgraph", path, output)
        return json.loads(output.read_text(encoding="utf-8"))

    def fingerprint(self, canonical, *flags):
        path = self.directory / "canonical.json"
        output = self.directory / "fingerprint.json"
        path.write_text(json.dumps(canonical), encoding="utf-8")
        self.run_engine("fingerprint-canonical", path, output, *flags)
        return output.read_bytes(), json.loads(output.read_text(encoding="utf-8")), json.loads(Path(str(output) + ".provenance.json").read_text(encoding="utf-8"))

    def test_frozen_digests_match_independent_hashlib(self):
        _, f, _ = self.fingerprint(self.canonical())
        expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual({key: f[key] for key in expected}, expected)
        self.assertEqual(f["semantic_digest"], sha256({key: f[key] for key in SEMANTIC_FIELDS}))
        self.assertEqual(f["fingerprint_digest"], sha256({key: value for key, value in f.items() if key != "fingerprint_digest"}))

    def test_repeatability_and_permuted_canonical_input(self):
        canonical = self.canonical()
        first, _, _ = self.fingerprint(canonical)
        self.assertEqual(first, self.fingerprint(canonical)[0])
        for key in ("nodes", "edges", "unresolved_calls"):
            canonical[key].reverse()
        canonical = dict(reversed(list(canonical.items())))
        self.assertEqual(first, self.fingerprint(canonical)[0])

    def test_nonuniform_relocation_preserves_complete_fingerprint(self):
        first, baseline, origins = self.fingerprint(self.canonical())
        relocated = json.loads(json.dumps(self.local).replace("004010", "00f010").replace("004020", "001020").replace("004030", "002030"))
        other, moved, moved_origins = self.fingerprint(self.canonical(relocated))
        self.assertEqual(first, other)
        self.assertEqual(baseline["fingerprint_digest"], moved["fingerprint_digest"])
        self.assertNotEqual(origins["source_document"], moved_origins["source_document"])

    def test_semantic_change_changes_semantic_digest(self):
        _, baseline, _ = self.fingerprint(self.canonical())
        next(n for n in self.local["nodes"] if n["type"] == "STRING")["value"] = "a different literal"
        _, changed, _ = self.fingerprint(self.canonical())
        self.assertNotEqual(baseline["semantic_digest"], changed["semantic_digest"])

    def test_observability_changes_are_separate_from_semantics(self):
        _, baseline, _ = self.fingerprint(self.canonical())
        next(n for n in self.local["nodes"] if n["type"] == "VISIBILITY_INDICATOR")["dynamic_dispatch_callsites"] = ["004010aa"]
        self.local["unresolved_calls"][0]["occurrences"] = 7
        _, changed, _ = self.fingerprint(self.canonical())
        for key in SEMANTIC_FIELDS:
            self.assertEqual(baseline[key], changed[key])
        self.assertEqual(baseline["semantic_digest"], changed["semantic_digest"])
        self.assertNotEqual(baseline["observability_view"], changed["observability_view"])
        self.assertNotEqual(baseline["fingerprint_digest"], changed["fingerprint_digest"])

    def test_every_feature_is_traceable_with_complete_coverage(self):
        canonical = self.canonical()
        _, f, sidecar = self.fingerprint(canonical)
        self.assertEqual(sidecar["fingerprint_digest"], f["fingerprint_digest"])
        features = [feature for name in ("rooted_topology_view", "typed_evidence_view", "interaction_motif_view", "observability_view") for feature in f[name]]
        self.assertEqual(set(sidecar["features"]), {feature["id"] for feature in features})
        for feature in features:
            occurrences = sidecar["features"][feature["id"]]
            self.assertEqual(sum(o["multiplicity"] for o in occurrences), feature["count"])
            for occurrence in occurrences:
                for origin in occurrence["origins"]:
                    self.assertTrue(origin["source_references"] or origin["source_metadata_paths"])
                    for ref in origin["source_references"]:
                        self.assertLess(ref["index"], len(sidecar["source_document"][ref["collection"]]))
                        for path in ref["property_paths"]:
                            pointer(sidecar["source_document"], path)
                    for path in origin["source_metadata_paths"]:
                        pointer(sidecar["source_document"], path)
        expected = {element["id"] for key in ("nodes", "edges", "unresolved_calls") for element in canonical[key]}
        expected.update(("@local_graph_truncation", "@coverage_ledger"))
        self.assertEqual(set(f["canonical_coverage"]), expected)
        self.assertTrue(all(e["status"] == "represented" for e in f["canonical_coverage"].values()))

    def test_limits_are_explicit_and_reproducible(self):
        canonical = self.canonical()
        first, f, _ = self.fingerprint(canonical, "--max-topology-motifs", "0", "--max-interaction-motifs", "1")
        self.assertEqual(f["motif_truncation"]["topology"]["retained"], 0)
        self.assertTrue(f["motif_truncation"]["topology"]["truncated"])
        self.assertEqual(f["motif_truncation"]["interaction"]["retained"], 1)
        self.assertTrue(f["motif_truncation"]["interaction"]["truncated"])
        self.assertEqual(first, self.fingerprint(canonical, "--max-topology-motifs", "0", "--max-interaction-motifs", "1")[0])

    def test_user_structural_count_fix_is_preserved(self):
        _, baseline, _ = self.fingerprint(self.canonical())
        for edge in self.local["edges"]:
            if edge["type"] in ("calls_function", "references_string", "calls_api"):
                edge["occurrences"] = 1000
        _, changed, _ = self.fingerprint(self.canonical())
        for view, kinds in (("rooted_topology_view", {"rooted_path", "rooted_fork"}), ("typed_evidence_view", {"category_chain"}), ("interaction_motif_view", {"call_evidence", "call_category_chain"})):

            def select(f):
                return [v for v in f[view] if v["descriptor"]["kind"] in kinds]

            self.assertEqual(select(baseline), select(changed))

    def test_no_scoring_or_fabricated_unresolved_targets(self):
        _, f, _ = self.fingerprint(self.canonical())

        def visit(value):
            if isinstance(value, dict):
                self.assertTrue(set(value).isdisjoint({"score", "capability", "capabilities", "malware_probability"}))
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(f)
        for feature in f["observability_view"]:
            self.assertNotIn("target", feature["descriptor"])
            self.assertNotIn("callee", feature["descriptor"])

    def test_invalid_canonical_sources_do_not_create_outputs(self):
        canonical = self.canonical()
        for mutation in ("duplicate", "digest", "endpoint", "provenance"):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(canonical)
                if mutation == "duplicate":
                    bad["nodes"].append(bad["nodes"][0])
                elif mutation == "digest":
                    bad["canonical_digest"] = "sha256:invalid"
                elif mutation == "endpoint":
                    bad["edges"][0]["target"] = "missing"
                else:
                    next(iter(bad["provenance_map"].values()))[0]["index"] = 99999
                path = self.directory / "bad.json"
                path.write_text(json.dumps(bad), encoding="utf-8")
                output = self.directory / f"{mutation}.json"
                self.run_engine("fingerprint-canonical", path, output, success=False)
                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + ".provenance.json").exists())

    def test_source_path_cannot_be_overwritten(self):
        canonical = self.canonical()
        path = self.directory / "canonical.json"
        before = path.read_bytes()
        self.run_engine("fingerprint-canonical", path, path, success=False)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(json.loads(before), canonical)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, default=ROOT / "rust_engine/target/debug/rust_engine.exe")
    parser.add_argument("--canonical-dir", type=Path)
    args = parser.parse_args()
    FingerprintAcceptance.engine = args.engine.resolve()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FingerprintAcceptance))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.canonical_dir:
        sources = sorted(args.canonical_dir.glob("seed_fn_*.json"))
        if not sources:
            raise SystemExit("No canonical documents found")
        with tempfile.TemporaryDirectory(prefix="osgf-real-") as folder:
            for source in sources:
                output = Path(folder) / source.name
                command = [str(FingerprintAcceptance.engine), "fingerprint-canonical", str(source), str(output)]
                result = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
                if result.returncode:
                    raise SystemExit(result.stdout + result.stderr)
                first = output.read_bytes()
                repeat = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
                if repeat.returncode:
                    raise SystemExit(repeat.stdout + repeat.stderr)
                assert first == output.read_bytes(), source.name
                document = json.loads(first)
                sidecar = json.loads(Path(str(output) + ".provenance.json").read_text(encoding="utf-8"))
                assert sidecar["fingerprint_digest"] == document["fingerprint_digest"]
                assert set(sidecar["features"]) == set(document["provenance_index"])
                print(f"REAL PASS {source.name}: deterministic bytes, {len(document['provenance_index'])} features, provenance verified", flush=True)
        print(f"REAL EXECUTION PASS: {len(sources)} canonical Notepad subgraphs (two runs each)", flush=True)


if __name__ == "__main__":
    main()
