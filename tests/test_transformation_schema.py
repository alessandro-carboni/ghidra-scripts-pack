import copy
import json
from pathlib import Path

import pytest

from scripts.transformation_schema import COLLECTIONS, FROZEN, ID_FIELDS, SCHEMAS, check_schema, schema_documents, serialize, stable_id, validate_bundle, validate_record


def example(schema):
    if "const" in schema:
        return schema["const"]
    if "anyOf" in schema:
        return example(schema["anyOf"][0])
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "object":
        return {key: example(value) for key, value in schema.get("properties", {}).items()}
    if kind == "array":
        return []
    if kind == "integer":
        return schema.get("minimum", 0)
    if kind == "boolean":
        return False
    if kind == "string":
        if schema.get("pattern", "").startswith("^sha256:"):
            return "sha256:" + "a" * 64
        return "a" * 64 if "pattern" in schema else "artifacts/example.json" if "format" in schema else "example"
    return None


def fixture():
    reference = example(FROZEN)
    records = {kind: example(schema) for kind, schema in SCHEMAS.items()}
    for kind, record in records.items():
        record[ID_FIELDS[kind]] = kind + "-1"
    records["execution"].update(transformation_id="specification-1", generation_status="generated")
    records["build"].update(execution_id="execution-1", build_status="success", attempt_count=1)
    records["behavior"].update(build_id="build-1", proof_reference="specification-1", validation_status="passed", output_comparison="equal", tested_cases=[dict(case_id=0, input_bytes=[], original_result=0, transformed_result=0, oracle_result=0)])
    records["graph"].update(build_id="build-1", execution_id="execution-1", extraction_status="success")
    records["mapping"].update(transformation_id="specification-1", execution_id="execution-1", original_element_references=["original"], transformed_element_references=["variant"])
    records["run"].update(transformation_ids=["specification-1"], execution_ids=["execution-1"], build_ids=["build-1"], graph_ids=["graph-1"], mapping_ids=["mapping-1"])
    bundle = dict(schema_version="0.1.0", frozen_dataset_reference=reference, **{collection: [records[kind]] for collection, kind in COLLECTIONS.items()})
    return bundle, reference


def test_all_contracts_and_versioned_schema_documents():
    bundle, reference = fixture()
    assert len(validate_bundle(bundle, reference)) == 7
    directory = Path(__file__).resolve().parents[1] / "datasets/osgf_transformations_v0_1/schema"
    for name, schema in schema_documents().items():
        assert (directory / name).read_bytes() == serialize(schema)
        assert schema["$schema"].endswith("/2020-12/schema")
    check_schema(bundle, schema_documents()["manifest.schema.json"])


@pytest.mark.parametrize("kind", SCHEMAS)
def test_every_required_field_is_required_and_no_unknown_science(kind):
    bundle, _ = fixture()
    collection = next(c for c, k in COLLECTIONS.items() if k == kind)
    valid = bundle[collection][0]
    for field in valid:
        bad = copy.deepcopy(valid)
        del bad[field]
        with pytest.raises(ValueError):
            validate_record(bad)
    valid["invented_scientific_field"] = 1
    with pytest.raises(ValueError, match="unknown scientific"):
        validate_record(valid)


@pytest.mark.parametrize("change", ["version", "hash", "duplicate", "reference", "frozen", "state", "provenance", "oracle", "mapping", "path", "machine_path"])
def test_fail_closed(change):
    bundle, reference = fixture()
    if change == "version":
        bundle["executions"][0]["schema_version"] = "9.9.9"
    elif change == "hash":
        bundle["specifications"][0]["source_sha256"] = "not-a-hash"
    elif change == "duplicate":
        item = copy.deepcopy(bundle["specifications"][0])
        item["equivalence_rationale"] = "same ID, different record"
        bundle["specifications"].append(item)
    elif change == "reference":
        bundle["builds"][0]["execution_id"] = "missing"
    elif change == "frozen":
        reference["manifest_file_sha256"] = "b" * 64
        bundle["frozen_dataset_reference"] = dict(reference, manifest_file_sha256="c" * 64)
    elif change == "state":
        bundle["runs"][0]["statuses"]["extraction"] = "passed"
    elif change == "provenance":
        bundle["builds"][0]["binary_sha256"] = None
    elif change == "oracle":
        bundle["behaviors"][0]["tested_cases"][0]["oracle_result"] = None
    elif change == "mapping":
        bundle["mappings"][0]["transformed_element_references"] = ["a", "b"]
    elif change == "path":
        bundle["specifications"][0]["source_artifact"] = "../outside.c"
    elif change == "machine_path":
        bundle["executions"][0]["generation_diagnostics"] = ["C:/Users/private/source.c"]
    with pytest.raises(ValueError):
        validate_bundle(bundle, reference)


@pytest.mark.parametrize("kind,left,right", [("one_to_one", ["a"], ["b"]), ("one_to_many", ["a"], ["b", "c"]), ("many_to_one", ["a", "b"], ["c"]), ("unmatched", [], ["b"]), ("unknown", ["a"], []), ("ambiguous", ["a"], ["b", "c"])])
def test_explicit_mapping_cardinalities(kind, left, right):
    bundle, _ = fixture()
    record = bundle["mappings"][0]
    record.update(mapping_kind=kind, original_element_references=left, transformed_element_references=right)
    validate_record(record)
    record["validation_status"] = "verified"
    with pytest.raises(ValueError):
        validate_record(record)


def test_key_reordering_determinism_and_nonfinite_rejection():
    bundle, reference = fixture()
    reordered = json.loads(json.dumps(bundle, sort_keys=True))
    assert serialize(bundle) == serialize(reordered)
    assert stable_id("run", bundle) == stable_id("run", reordered)
    validate_bundle(reordered, reference)
    with pytest.raises(ValueError):
        serialize({"not_scientific": float("nan")})
