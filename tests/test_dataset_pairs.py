import copy
import unittest

from scripts.generate_dataset_pairs import same_source_pairs
from tests.test_dataset_manifest import fixture


class SameSourcePairsTests(unittest.TestCase):
    def configured(self):
        data = fixture()
        data["routines"][0]["body_sha256"] = "body"
        for i, build in enumerate(data["builds"]):
            build.update(compiler="gcc" if i == 0 else "msvc", compiler_version="1", optimization="O0" if i == 0 else "O2", architecture="x86")
        return data

    def test_generation_is_unique_deterministic_and_reorder_invariant(self):
        data = self.configured()
        result = same_source_pairs(data)
        self.assertEqual(len(result), 1)
        data["graphs"].reverse()
        self.assertEqual(result, same_source_pairs(data))
        self.assertEqual(result[0]["ground_truth"]["routine_body_sha256"], "body")

    def test_same_name_is_not_enough_and_architecture_must_match(self):
        for field, value in (("source_hash", "different"), ("architecture", "arm64")):
            with self.subTest(field=field):
                data = self.configured()
                data["builds"][1][field] = value
                self.assertEqual(same_source_pairs(data), [])
        data = self.configured()
        data["builds"][1].update({key: data["builds"][0][key] for key in ("compiler", "compiler_version", "optimization")})
        self.assertEqual(same_source_pairs(data), [])

    def test_all_available_configurations_are_paired_once(self):
        data = self.configured()
        for collection, key in (("builds", "build_id"), ("samples", "sample_id"), ("graphs", "graph_id")):
            record = copy.deepcopy(data[collection][0])
            record[key] = "c"
            if collection == "builds":
                record["optimization"] = "O3"
            elif collection == "samples":
                record["build_id"] = "c"
            else:
                record["sample_id"] = "c"
            data[collection].append(record)
        pairs = same_source_pairs(data)
        self.assertEqual(len(pairs), 3)
        self.assertEqual(len({p["pair_id"] for p in pairs}), 3)
