import copy
import unittest

from scripts.dataset_manifest import validate


def fixture():
    routines = [dict(routine_id="r", source_group_id="g", body_sha256="body")]
    builds = [dict(build_id=b, build_hash=b, source_hash="source", behavior=["r 0 3"]) for b in ("a", "b")]
    samples = [dict(sample_id=b, build_id=b, sha256=b, architecture="x86") for b in ("a", "b")]
    graphs = [dict(graph_id=b, sample_id=b, routine_id="r", source_group_id="g", variant="original") for b in ("a", "b")]
    pair = dict(
        pair_id="p",
        source_group_id="g",
        left_sample_id="a",
        right_sample_id="b",
        left_graph_id="a",
        right_graph_id="b",
        equivalence_label="equivalent",
        pair_category="same_source",
        transformation_family="compiler_variation",
        transformation_parameters={},
        left_build_id="a",
        right_build_id="b",
        architecture="x86",
        validation_status="automatically_grounded",
        ground_truth=dict(method="same_controlled_source", label="equivalent", source_hash="source", routine_body_sha256="body"),
        split="discovery_train",
        notes="",
    )
    return dict(schema_version="0.1.0", routines=routines, builds=builds, samples=samples, graphs=graphs, pairs=[pair])


class DatasetManifestTests(unittest.TestCase):
    def test_valid_manifest(self):
        self.assertEqual(validate(fixture())["pairs"], 1)

    def test_reversed_pair_rejected(self):
        data = fixture()
        other = copy.deepcopy(data["pairs"][0])
        other.update(pair_id="second", left_graph_id="b", right_graph_id="a", left_sample_id="b", right_sample_id="a", left_build_id="b", right_build_id="a")
        data["pairs"].append(other)
        with self.assertRaisesRegex(ValueError, "reversed"):
            validate(data)

    def test_invalid_fields_and_missing_references(self):
        for field, value in (("pair_id", ""), ("left_sample_id", "missing"), ("left_graph_id", "missing"), ("equivalence_label", ""), ("transformation_family", "unknown"), ("split", "")):
            with self.subTest(field=field):
                data = fixture()
                data["pairs"][0][field] = value
                with self.assertRaises(ValueError):
                    validate(data)

    def test_contradictory_ground_truth_and_unverified_counterexample(self):
        data = fixture()
        data["pairs"][0]["ground_truth"]["label"] = "non_equivalent"
        with self.assertRaisesRegex(ValueError, "contradictory"):
            validate(data)
        data = fixture()
        data["pairs"][0].update(equivalence_label="non_equivalent", ground_truth=dict(method="behavior_counterexample", label="non_equivalent", case=0, left_result=3, right_result=9))
        with self.assertRaisesRegex(ValueError, "transcript"):
            validate(data)

    def test_same_source_requires_same_hash_and_no_similarity_labels(self):
        data = fixture()
        data["builds"][1]["source_hash"] = "changed"
        with self.assertRaisesRegex(ValueError, "source artifacts"):
            validate(data)
        data = fixture()
        data["pairs"][0]["ground_truth"]["method"] = "osgf_similarity"
        with self.assertRaisesRegex(ValueError, "independent"):
            validate(data)
