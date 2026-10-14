"""CLI contract checks, also included in test_similarity_baseline.py."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SimilarityCLI(unittest.TestCase):
    engine = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="osgf-similarity-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.canonical = self.directory / "canonical.json"
        self.fingerprint = self.directory / "fingerprint.json"
        self.output = self.directory / "result.json"
        self.run_engine("canonicalize-local-subgraph", ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json", self.canonical)
        self.run_engine("fingerprint-canonical", self.canonical, self.fingerprint)

    def run_engine(self, *args, success=True):
        result = subprocess.run([str(self.engine), *map(str, args)], capture_output=True, text=True, timeout=120, check=False)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def compare(self, output=None, success=True):
        return self.run_engine("compare-fingerprints", "query", self.canonical, self.fingerprint, "reference", self.canonical, self.fingerprint, output or self.output, success=success)

    def test_complete_result_and_console_diagnostics(self):
        result = self.compare()
        print("\nDEMO: fingerprint identiche con unresolved osservate\n" + result.stdout, flush=True)
        data = json.loads(self.output.read_text(encoding="utf-8"))
        for name in ("rooted_topology", "typed_evidence", "interaction_motif"):
            self.assertEqual(data[name]["set_similarity"], 1)
            self.assertEqual(data[name]["multiset_similarity"], 1)
            self.assertTrue(data[name]["matched"])
        self.assertTrue(data["observability"]["possibly_incomplete"])
        self.assertEqual(data["observability"]["differences"], [])
        self.assertIsNone(data["aggregate_set_similarity"])
        self.assertEqual(data["query"]["id"], "query")

    def test_invalid_versions_and_tampered_counts_produce_no_output(self):
        original = self.fingerprint.read_text(encoding="utf-8")
        for change in ("version", "count"):
            data = json.loads(original)
            if change == "version":
                data["canonicalization_version"] = "999"
            else:
                data["typed_evidence_view"][0]["count"] += 1
            self.fingerprint.write_text(json.dumps(data), encoding="utf-8")
            result = self.compare(success=False)
            self.assertFalse(self.output.exists())
            print(f"REJECTED {change}: {result.stderr.strip()}", flush=True)

    def test_existing_output_and_sources_are_protected(self):
        for target in (self.canonical, self.fingerprint):
            original = target.read_bytes()
            self.compare(target, success=False)
            self.assertEqual(target.read_bytes(), original)
        self.compare()
        original = self.output.read_bytes()
        self.compare(success=False)
        self.assertEqual(self.output.read_bytes(), original)

    def test_usage_rejects_missing_arguments(self):
        result = self.run_engine("compare-fingerprints", success=False)
        self.assertIn("usage:", result.stderr)

    def test_optional_aggregate_and_invalid_flags(self):
        base = ("compare-fingerprints", "query", self.canonical, self.fingerprint, "reference", self.canonical, self.fingerprint, self.output)
        for flags in (("--unknown",), ("--aggregate", "--aggregate")):
            self.run_engine(*base, *flags, success=False)
            self.assertFalse(self.output.exists())
        result = self.run_engine(*base, "--aggregate")
        data = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertTrue(data["aggregate_requested"])
        self.assertEqual(data["aggregate_set_similarity"], 1)
        self.assertEqual(data["aggregate_multiset_similarity"], 1)
        self.assertEqual(data["aggregate_components"], ["rooted_topology", "typed_evidence", "interaction_motif"])
        self.assertIn("not a malware probability", result.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    SimilarityCLI.engine = args.engine.resolve()
    unittest.main(argv=[__file__], verbosity=2)
