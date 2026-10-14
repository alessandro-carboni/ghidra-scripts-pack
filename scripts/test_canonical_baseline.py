"""Terminal acceptance tests for Canonicalization Baseline v0.1 (standard library only)."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json"
SCIENTIFIC_FIELDS = (
    "schema_version",
    "canonicalization_version",
    "graph_version",
    "source_local_subgraph_schema_version",
    "nodes",
    "edges",
    "unresolved_calls",
    "local_graph_truncation",
)


def scientific(document):
    return {key: document[key] for key in SCIENTIFIC_FIELDS}


class CanonicalAcceptance(unittest.TestCase):
    engine = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="canonical-baseline-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def invoke(self, source, expect_success=True):
        input_path = self.directory / "local.json"
        output_path = self.directory / "canonical.json"
        input_path.write_text(json.dumps(source), encoding="utf-8")
        output_path.unlink(missing_ok=True)
        result = subprocess.run(
            [str(self.engine), "canonicalize-local-subgraph", str(input_path), str(output_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if not expect_success:
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output_path.exists(), result.stdout + result.stderr)
            return None
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return output_path.read_bytes(), json.loads(output_path.read_text(encoding="utf-8"))

    def test_frozen_digest_and_independent_sha256(self):
        _, document = self.invoke(self.source)
        expected = FIXTURE.with_suffix(".sha256").read_text().strip()
        self.assertEqual(document["canonical_digest"], expected)
        payload = json.dumps(scientific(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(document["canonical_digest"], "sha256:" + hashlib.sha256(payload.encode()).hexdigest())

    def test_byte_repeatability_and_json_permutations(self):
        baseline, _ = self.invoke(self.source)
        self.assertEqual(baseline, self.invoke(self.source)[0])
        self.source = dict(reversed(list(self.source.items())))
        for key in ("nodes", "edges", "unresolved_calls"):
            self.source[key].reverse()
        for edge in self.source["edges"]:
            for key in ("callsites", "reference_sites", "use_sites", "context_apis"):
                if key in edge:
                    edge[key].reverse()
        self.assertEqual(baseline, self.invoke(self.source)[0])

    def test_nonuniform_relocation_preserves_science_but_updates_provenance(self):
        _, baseline = self.invoke(self.source)
        text = json.dumps(self.source).replace("004010", "00f010").replace("004020", "001020").replace("004030", "002030")
        _, moved = self.invoke(json.loads(text))
        self.assertEqual(scientific(baseline), scientific(moved))
        self.assertEqual(baseline["canonical_digest"], moved["canonical_digest"])
        self.assertNotEqual(baseline["source_document"], moved["source_document"])

    def test_complete_coverage_and_resolvable_provenance(self):
        _, document = self.invoke(self.source)
        ledger = document["coverage_ledger"]
        expected = {(key, i) for key in ("nodes", "edges", "unresolved_calls") for i in range(len(self.source[key]))}
        actual = {(e["source"]["collection"], e["source"]["index"]) for e in ledger["entries"]}
        self.assertEqual(expected, actual)
        self.assertEqual(ledger["represented"], len(expected))
        self.assertEqual(ledger["excluded"], 0)
        for references in document["provenance_map"].values():
            for reference in references:
                for pointer in reference["property_paths"]:
                    value = document["source_document"]
                    for token in pointer.split("/")[1:]:
                        key = token.replace("~1", "/").replace("~0", "~")
                        value = value[int(key)] if isinstance(value, list) else value[key]

    def test_no_score_capability_or_invented_target(self):
        _, document = self.invoke(self.source)
        text = json.dumps(scientific(document))
        for forbidden in ('"score"', '"capability"', '"capabilities"', '"callsite"', "fn:004010"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(sum(n["facts"].get("role") == "ANCHOR" for n in document["nodes"]), 1)
        for call in document["unresolved_calls"]:
            self.assertNotIn("callee", call)
            self.assertNotIn("target", call)

    def test_semantic_change_changes_digest(self):
        _, baseline = self.invoke(self.source)
        next(n for n in self.source["nodes"] if n["type"] == "STRING")["value"] = "different literal"
        _, changed = self.invoke(self.source)
        self.assertNotEqual(baseline["canonical_digest"], changed["canonical_digest"])

    def test_invalid_sources_are_rejected_without_output(self):
        for mutation in ("endpoint", "duplicate", "invented_target", "counts"):
            with self.subTest(mutation=mutation):
                source = copy.deepcopy(self.source)
                if mutation == "endpoint":
                    source["edges"][0]["target"] = "fn:missing"
                elif mutation == "duplicate":
                    source["nodes"].append(source["nodes"][0])
                elif mutation == "invented_target":
                    source["unresolved_calls"][0]["callee"] = source["anchor_function_id"]
                else:
                    source["truncation"]["counts"]["total_nodes"] += 1
                self.invoke(source, expect_success=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, default=ROOT / "rust_engine/target/debug/rust_engine.exe")
    parser.add_argument("--real-source-dir", type=Path)
    options = parser.parse_args()
    CanonicalAcceptance.engine = options.engine.resolve()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CanonicalAcceptance))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if options.real_source_dir:
        sources = sorted(options.real_source_dir.glob("seed_fn_*.json"))
        if not sources:
            raise SystemExit("No real local-subgraph documents found")
        with tempfile.TemporaryDirectory(prefix="canonical-notepad-") as directory:
            for source in sources:
                output = Path(directory) / source.name
                subprocess.run([str(CanonicalAcceptance.engine), "canonicalize-local-subgraph", str(source), str(output)], check=True, timeout=60)
                document = json.loads(output.read_text(encoding="utf-8"))
                ledger = document["coverage_ledger"]
                assert ledger["represented"] + ledger["excluded"] == len(ledger["entries"])
        print(f"REAL EXECUTION PASS: {len(sources)} local subgraphs", flush=True)


if __name__ == "__main__":
    main()
