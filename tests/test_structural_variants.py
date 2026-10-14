import copy
import json
from pathlib import Path
import unittest

from scripts.validate_structural_variants import validate


class StructuralVariantsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((Path(__file__).resolve().parents[1] / "datasets/osgf_pairs_v0_1/variants.json").read_text())

    def test_all_families_and_oracles(self):
        self.assertEqual(validate(self.data)["oracle_checks"], 36864)

    def test_corrupt_output_rejected(self):
        data = copy.deepcopy(self.data)
        row = data["builds"][0]["behavior"][0].split()
        row[2] = str(int(row[2]) + 1)
        data["builds"][0]["behavior"][0] = " ".join(row)
        with self.assertRaisesRegex(AssertionError, "oracle mismatch"):
            validate(data)

    def test_missing_cases_rejected(self):
        data = copy.deepcopy(self.data)
        data["builds"][0]["behavior"].pop()
        with self.assertRaisesRegex(AssertionError, "Incomplete"):
            validate(data)
