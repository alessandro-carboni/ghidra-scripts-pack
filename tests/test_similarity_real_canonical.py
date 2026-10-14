"""Failure-path checks for the local smoke validator, without the real dataset."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import test_similarity_real_canonical as smoke


def valid_result():
    result = {name: dict(comparable=True, set_similarity=1.0, multiset_similarity=1.0, missing_from_query=[], missing_from_reference=[]) for name in smoke.VIEWS}
    result.update(aggregate_requested=True, aggregate_components=list(smoke.VIEWS), aggregate_set_similarity=1.0, aggregate_multiset_similarity=1.0, observability_warnings=["unresolved calls"])
    return result


class RealCanonicalSmokeTests(unittest.TestCase):
    def test_observability_warnings_do_not_excuse_bad_scores_or_missing_features(self):
        baseline = valid_result()
        self.assertEqual(smoke.validate_result(baseline), (list(smoke.VIEWS), True))
        for field, value in (("set_similarity", 0.9), ("multiset_similarity", 0.9), ("missing_from_query", [{}]), ("missing_from_reference", [{}])):
            with self.subTest(field=field):
                bad = copy.deepcopy(baseline)
                bad["typed_evidence"][field] = value
                with self.assertRaises(ValueError):
                    smoke.validate_result(bad)

    def test_incorrect_aggregate_is_rejected(self):
        for field, value in (("aggregate_requested", False), ("aggregate_set_similarity", 0), ("aggregate_multiset_similarity", None), ("aggregate_components", ["observability"])):
            with self.subTest(field=field):
                bad = valid_result()
                bad[field] = value
                with self.assertRaises(ValueError):
                    smoke.validate_result(bad)

    def test_all_unavailable_views_require_null_aggregates(self):
        result = valid_result()
        for name in smoke.VIEWS:
            result[name].update(comparable=False, set_similarity=None, multiset_similarity=None)
        result.update(aggregate_components=[], aggregate_set_similarity=None, aggregate_multiset_similarity=None)
        self.assertEqual(smoke.validate_result(result), ([], True))
        result["aggregate_set_similarity"] = 1
        with self.assertRaises(ValueError):
            smoke.validate_result(result)

    def test_missing_or_empty_directory_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as folder:
            for directory, expected in ((Path(folder) / "missing", "does not exist"), (Path(folder), "no seed_fn_*.json")):
                result = subprocess.run([sys.executable, smoke.__file__, "--engine", sys.executable, "--canonical-dir", str(directory)], capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_engine_failure_is_not_swallowed(self):
        with patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "source validation error")):
            with self.assertRaisesRegex(ValueError, "source validation error"):
                smoke.run_engine(Path("engine"), "compare-fingerprints")

    def test_semantically_equal_but_different_rerun_bytes_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / "seed_fn_test.json").write_text("{}", encoding="utf-8")
            repeats = []

            def fake_engine(engine, command, *args):
                if command == "compare-fingerprints":
                    repeats.append(True)
                    Path(args[-2]).write_text(json.dumps(valid_result(), indent=len(repeats)), encoding="utf-8")

            with patch.object(smoke, "run_engine", side_effect=fake_engine):
                with self.assertRaisesRegex(ValueError, "bytes differ"):
                    smoke.validate_directory(Path(sys.executable), directory)
            self.assertEqual(len(repeats), 2)
