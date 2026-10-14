import copy
import json
from pathlib import Path
import unittest

from scripts.dataset_splits import apply_splits, family_holdout, validate_leakage

ROOT = Path(__file__).resolve().parents[1] / "datasets/osgf_pairs_v0_1"


class DatasetSplitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((ROOT / "manifest.json").read_text())
        cls.config = json.loads((ROOT / "split_config.json").read_text())

    def test_assignment_is_reproducible_and_order_independent(self):
        data = copy.deepcopy(self.data)
        apply_splits(data, self.config)
        before = {p["pair_id"]: p["split"] for p in data["pairs"]}
        for collection in ("pairs", "graphs", "routines", "builds"):
            data[collection].reverse()
        apply_splits(data, self.config)
        self.assertEqual(before, {p["pair_id"]: p["split"] for p in data["pairs"]})
        self.assertEqual(set(before.values()), {"discovery_train", "validation", "held_out_test"})

    def test_pair_and_graph_leakage_rejected(self):
        for collection in ("pairs", "graphs"):
            data = copy.deepcopy(self.data)
            record = data[collection][0]
            record["split"] = "held_out_test" if record["split"] != "held_out_test" else "validation"
            with self.assertRaises(ValueError):
                validate_leakage(data, self.config)

    def test_near_duplicate_artifacts_must_stay_together(self):
        config = copy.deepcopy(self.config)
        config["artifact_splits"]["memory"] = "validation"
        with self.assertRaisesRegex(ValueError, "leakage"):
            apply_splits(copy.deepcopy(self.data), config)

    def test_family_holdout_preserves_source_split(self):
        pairs = {p["pair_id"]: p for p in self.data["pairs"]}
        result = family_holdout(self.data, "transparent_wrapper")
        for split, ids in result["pair_ids"].items():
            self.assertTrue(ids)
            for pair_id in ids:
                self.assertEqual(pairs[pair_id]["split"], split)
                self.assertEqual(pairs[pair_id]["transformation_family"] == "transparent_wrapper", split == "held_out_test")

    def test_reversed_duplicate_rejected(self):
        data = copy.deepcopy(self.data)
        pair = copy.deepcopy(data["pairs"][0])
        pair["pair_id"] = "duplicate"
        pair["left_graph_id"], pair["right_graph_id"] = pair["right_graph_id"], pair["left_graph_id"]
        data["pairs"].append(pair)
        with self.assertRaisesRegex(ValueError, "reversed"):
            validate_leakage(data, self.config)
