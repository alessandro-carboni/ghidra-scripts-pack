import copy
import json
from pathlib import Path
import unittest

from scripts.dataset_manifest import validate

ROOT = Path(__file__).resolve().parents[1]


class DatasetNegativesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_text())

    def test_categories_and_real_counterexamples(self):
        negatives = [p for p in self.data["pairs"] if p["equivalence_label"] == "non_equivalent"]
        self.assertGreaterEqual(len(negatives), 40)
        self.assertEqual({p["difficulty"] for p in negatives}, {"easy", "hard"})
        self.assertTrue({"similar_api_different_structure", "similar_topology_different_evidence", "benign_lookalike", "same_binary_different_routine", "different_behavior", "similar_constants_different_behavior"}.issubset({p["negative_category"] for p in negatives}))
        validate(self.data, ROOT)
        for pair in negatives:
            truth = pair["ground_truth"]
            self.assertEqual(truth["method"], "behavior_counterexample")
            self.assertEqual(pair["left_sample_id"], pair["right_sample_id"])
            case = truth["case"]
            self.assertEqual(truth["input_bytes"], [(j * 17 + case * 13) % 127 for j in range(case * 7)])

    def test_forged_and_equal_outputs_rejected(self):
        for equal in (False, True):
            data = copy.deepcopy(self.data)
            pair = next(p for p in data["pairs"] if p["equivalence_label"] == "non_equivalent")
            pair["ground_truth"]["right_result"] = pair["ground_truth"]["left_result"] if equal else 999999
            with self.assertRaises(ValueError):
                validate(data)

    def test_similarity_cannot_be_label_source(self):
        data = copy.deepcopy(self.data)
        pair = next(p for p in data["pairs"] if p["equivalence_label"] == "non_equivalent")
        pair["ground_truth"]["method"] = "low_similarity"
        with self.assertRaisesRegex(ValueError, "independent"):
            validate(data)

    def test_api_category_has_extracted_typed_evidence(self):
        graphs = {g["graph_id"]: g for g in self.data["graphs"]}
        pair = next(p for p in self.data["pairs"] if p.get("negative_category") == "similar_topology_different_evidence")
        documents = [json.loads((ROOT / graphs[pair[side + "_graph_id"]]["path"]).read_text()) for side in ("left", "right")]
        api_nodes = [{json.dumps(n["facts"], sort_keys=True) for n in doc["nodes"] if n["kind"] == "API"} for doc in documents]
        self.assertTrue(all(api_nodes), "API evidence must actually be extracted")
        self.assertNotEqual(*api_nodes)
