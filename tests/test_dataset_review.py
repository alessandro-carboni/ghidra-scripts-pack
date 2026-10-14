import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.dataset_review import freeze, prepare, validate_decisions


class DatasetReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((Path(__file__).resolve().parents[1] / "datasets/osgf_pairs_v0_1/manifest.json").read_text())

    def packet(self, directory):
        prepare(self.data, directory)
        return json.loads((directory / "review_packet.json").read_text())

    def accepted(self, packet):
        decisions = copy.deepcopy(packet)
        for record in decisions["records"]:
            record.update(reviewer="SYNTHETIC TEST REVIEWER - NOT A REAL REVIEW", decision="accept", validation_status="manually_verified", notes="Test fixture only", reason="Exercise revision validation")
        return decisions

    def test_pending_or_incomplete_review_cannot_freeze(self):
        with tempfile.TemporaryDirectory() as temp:
            packet = self.packet(Path(temp))
            with self.assertRaises(ValueError):
                validate_decisions(self.data, packet, packet)
            decisions = self.accepted(packet)
            decisions["records"].pop()
            with self.assertRaisesRegex(ValueError, "missing"):
                validate_decisions(self.data, packet, decisions)

    def test_changed_labels_and_missing_reviewers_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            packet = self.packet(Path(temp))
            decisions = self.accepted(packet)
            changed = copy.deepcopy(self.data)
            changed["pairs"][0]["equivalence_label"] = "changed"
            with self.assertRaisesRegex(ValueError, "changed"):
                validate_decisions(changed, packet, decisions)
            decisions["records"][0]["reviewer"] = ""
            with self.assertRaisesRegex(ValueError, "reviewer"):
                validate_decisions(self.data, packet, decisions)

    def test_freezes_are_append_only_with_explicit_revision(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            packet = self.packet(directory)
            (directory / "review_decisions.json").write_text(json.dumps(self.accepted(packet)))
            first = directory / "freeze-001.json"
            second = directory / "freeze-002.json"
            freeze(self.data, directory, first)
            original = first.read_bytes()
            with self.assertRaisesRegex(ValueError, "overwrite"):
                freeze(self.data, directory, first)
            with self.assertRaisesRegex(ValueError, "revision"):
                freeze(self.data, directory, second)
            freeze(self.data, directory, second, first, "Explicit test-only revision")
            self.assertEqual(first.read_bytes(), original)
            self.assertTrue(json.loads(second.read_text())["supersedes_sha256"])

    def test_ambiguous_held_out_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            packet = self.packet(Path(temp))
            decisions = self.accepted(packet)
            pairs = {p["pair_id"]: p for p in self.data["pairs"]}
            record = next(r for r in decisions["records"] if pairs[r["pair_id"]]["split"] == "held_out_test")
            record.update(decision="ambiguous", validation_status="ambiguous")
            with self.assertRaisesRegex(ValueError, "held_out|held-out"):
                validate_decisions(self.data, packet, decisions)
