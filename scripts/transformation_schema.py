"""Step 9 v0.1 data contracts; strict stdlib validation of the emitted JSON Schema subset."""

import hashlib
import json
from pathlib import Path
import re

try:
    from .step9_preflight import FREEZE, FROZEN_DIGEST, safe_path
except ImportError:
    from step9_preflight import FREEZE, FROZEN_DIGEST, safe_path

VERSION = "0.1.0"
FAMILIES = ("transparent_wrapper", "thunk", "function_splitting", "dead_branch", "harmless_strand", "instruction_reordering")
TEXT = {"type": "string", "minLength": 1}
HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
PATH = {"type": "string", "format": "repository-path"}
OBJECT = {"type": "object"}
BOOL = {"type": "boolean"}
NATURAL = {"type": "integer", "minimum": 0}


def array(item=TEXT):
    return {"type": "array", "items": item, "uniqueItems": True}


def enum(*values):
    return {"type": "string", "enum": list(values)}


def closed(**fields):
    return {"type": "object", "properties": fields, "required": sorted(fields), "additionalProperties": False}


def nullable(schema):
    return {"anyOf": [schema, {"type": "null"}]}


CONTRACT = closed(kind=enum("pure_bytes", "stable_os_bytes"), min_length={"const": 0}, max_length={"const": 255}, trailing_nul={"const": True}, result_bits={"const": 32}, preconditions=array())
FROZEN = closed(path={"const": FREEZE}, scientific_digest={"const": FROZEN_DIGEST}, manifest_file_sha256=HASH)
EXPECTED = closed(claim=enum("equivalent_under_contract", "unknown", "not_applicable"), scope=TEXT, verified={"const": False})
EVIDENCE = closed(artifact_id=TEXT, artifact_path=PATH, artifact_sha256=HASH, reference=TEXT)
OBSERVATION = closed(status=enum("observed", "partially_observed", "optimized_away", "not_observable", "unknown"), evidence=array(EVIDENCE), limitations=array())


def record(kind, **fields):
    return closed(record_type={"const": kind}, schema_version={"const": VERSION}, **fields)


SCHEMAS = {
    "specification": record(
        "specification",
        transformation_id=TEXT,
        transformation_family=enum(*FAMILIES),
        source_routine_id=TEXT,
        source_group_id=TEXT,
        source_artifact=PATH,
        source_sha256=HASH,
        input_contract=CONTRACT,
        parameters=OBJECT,
        deterministic_seed=NATURAL,
        expected_equivalence=EXPECTED,
        equivalence_rationale=TEXT,
        preconditions=array(),
        expected_source_effects=array(),
        expected_graph_effects=array(),
        generator_version={"const": VERSION},
    ),
    "execution": record(
        "execution",
        execution_id=TEXT,
        transformation_id=TEXT,
        requested_parameters=OBJECT,
        applied_parameters=nullable(OBJECT),
        generation_status=enum("planned", "generated", "rejected", "unsupported", "failed"),
        original_source_sha256=HASH,
        generated_source_sha256=nullable(HASH),
        generated_source_path=nullable(PATH),
        generation_diagnostics=array(),
    ),
    "build": record(
        "build",
        build_id=TEXT,
        execution_id=TEXT,
        compiler=enum("gcc", "msvc", "clang"),
        compiler_version=nullable(TEXT),
        optimization=enum("O0", "O2", "O3"),
        architecture=nullable(enum("x86", "x86_64", "arm64")),
        compiler_flags={"type": "array", "items": TEXT},
        source_sha256=HASH,
        binary_sha256=nullable(HASH),
        binary_artifact_reference=nullable(PATH),
        build_status=enum("planned", "success", "unsupported", "unavailable", "compile_failed", "validation_failed", "artifact_access_failed"),
        build_diagnostics=array(),
        attempt_count=NATURAL,
    ),
    "behavior": record(
        "behavior",
        behavior_id=TEXT,
        build_id=TEXT,
        original_routine=TEXT,
        transformed_routine=TEXT,
        input_contract=CONTRACT,
        oracle_version={"const": VERSION},
        tested_cases=array(closed(case_id=NATURAL, input_bytes={"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 255}}, original_result=NATURAL, transformed_result=NATURAL, oracle_result=nullable(NATURAL))),
        original_outputs_digest=nullable(HASH),
        transformed_outputs_digest=nullable(HASH),
        output_comparison=enum("equal", "different", "unknown"),
        mismatch_witnesses=array(OBJECT),
        side_effect_observations=closed(status=enum("source_proven_pure", "observed", "unknown"), evidence=array()),
        validation_status=enum("pending", "passed", "failed", "unsupported"),
        proof_reference=TEXT,
        limitations=array(),
    ),
    "graph": record(
        "graph",
        graph_id=TEXT,
        execution_id=TEXT,
        build_id=TEXT,
        binary_sha256=HASH,
        ghidra_version=TEXT,
        exporter_version=HASH,
        extraction_configuration=closed(caller_depth=NATURAL, callee_depth=NATURAL),
        typed_graph_reference=nullable(PATH),
        typed_graph_sha256=nullable(HASH),
        canonical_graph_reference=nullable(PATH),
        canonical_graph_sha256=nullable(HASH),
        canonical_digest=nullable({"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}),
        anchor_identity=nullable(TEXT),
        extraction_status=enum("pending", "success", "missing_symbol", "missing_anchor", "invalid_exporter_output", "incomplete_analysis", "unsupported_architecture", "timeout", "corrupted_graph", "canonicalization_failed", "unavailable"),
        observability_metadata=OBSERVATION,
        truncation_metadata=nullable(OBJECT),
        diagnostics=array(),
    ),
    "mapping": record(
        "mapping",
        mapping_id=TEXT,
        transformation_id=TEXT,
        execution_id=TEXT,
        original_element_references=array(),
        transformed_element_references=array(),
        mapping_level=enum("source", "generated_function", "binary_function", "typed_graph", "canonical_subgraph"),
        mapping_kind=enum("one_to_one", "one_to_many", "many_to_one", "unmatched", "unknown", "ambiguous"),
        expected_mapping=TEXT,
        observed_mapping=nullable(TEXT),
        supporting_evidence=array(EVIDENCE),
        observation_completeness=enum("complete", "incomplete", "unknown"),
        validation_status=enum("expected", "verified", "unmatched", "unknown", "ambiguous", "rejected"),
        limitations=array(),
    ),
    "run": record(
        "run",
        run_id=TEXT,
        experiment_configuration=OBJECT,
        generator_version={"const": VERSION},
        frozen_dataset_reference=FROZEN,
        frozen_manifest_digest=HASH,
        transformation_ids=array(),
        execution_ids=array(),
        build_ids=array(),
        graph_ids=array(),
        mapping_ids=array(),
        statuses=closed(generation=enum("pending", "passed", "failed", "partial"), build=enum("pending", "passed", "failed", "partial"), extraction=enum("pending", "passed", "failed", "partial"), mapping=enum("pending", "passed", "failed", "partial"), validation=enum("pending", "passed", "failed", "blocked")),
        artifact_hashes={"type": "object", "additionalProperties": HASH},
        report_references=array(PATH),
    ),
}
COLLECTIONS = {"specifications": "specification", "executions": "execution", "builds": "build", "behaviors": "behavior", "graphs": "graph", "mappings": "mapping", "runs": "run"}
ID_FIELDS = {"specification": "transformation_id", "execution": "execution_id", "build": "build_id", "behavior": "behavior_id", "graph": "graph_id", "mapping": "mapping_id", "run": "run_id"}
MANIFEST_SCHEMA = closed(schema_version={"const": VERSION}, frozen_dataset_reference=FROZEN, **{name: array(schema) for name, kind in COLLECTIONS.items() for schema in [SCHEMAS[kind]]})


def check_schema(value, schema, location="document"):
    """Only the standard JSON Schema keywords emitted above are needed."""
    if "anyOf" in schema:
        for choice in schema["anyOf"]:
            try:
                check_schema(value, choice, location)
                return
            except ValueError:
                pass
        raise ValueError(location + ": no allowed type")
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        raise ValueError(location + ": unsupported constant/version")
    expected = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
    if expected and type(value) is not types[expected]:
        raise ValueError(location + ": wrong type")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(location + ": unknown enum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or ("pattern" in schema and re.fullmatch(schema["pattern"], value) is None):
            raise ValueError(location + ": malformed string/hash")
        if schema.get("format") == "repository-path":
            safe_path(Path.cwd(), value)
    if type(value) is int and (value < schema.get("minimum", value) or value > schema.get("maximum", value)):
        raise ValueError(location + ": out of bounds")
    if isinstance(value, list):
        if schema.get("uniqueItems") and len({serialize(item) for item in value}) != len(value):
            raise ValueError(location + ": duplicate array entry")
        for index, child in enumerate(value):
            check_schema(child, schema.get("items", {}), f"{location}[{index}]")
    if isinstance(value, dict):
        fields = schema.get("properties", {})
        if set(schema.get("required", [])) - value.keys():
            raise ValueError(location + ": missing required fields")
        for key, child in value.items():
            if key in fields:
                check_schema(child, fields[key], location + "." + key)
            elif schema.get("additionalProperties") is False:
                raise ValueError(location + ": unknown scientific field " + key)
            elif isinstance(schema.get("additionalProperties"), dict):
                check_schema(child, schema["additionalProperties"], location + "." + key)


def serialize(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def stable_id(kind, value):
    return kind + ":" + hashlib.sha256(serialize(value)).hexdigest()[:24]


def portable(value):
    if isinstance(value, str) and (re.search(r"(?i)[a-z]:[/\\]|/(?:home|Users)/|\\\\", value)):
        raise ValueError("machine-specific path in metadata")
    if isinstance(value, dict):
        for key, child in value.items():
            portable(key)
            portable(child)
    if isinstance(value, list):
        for child in value:
            portable(child)


def validate_record(value):
    kind = value.get("record_type")
    if kind not in SCHEMAS:
        raise ValueError("unknown record type")
    check_schema(value, SCHEMAS[kind])
    portable(value)
    if kind == "execution":
        generated = value["generation_status"] == "generated"
        if generated != all(value[k] is not None for k in ("generated_source_path", "generated_source_sha256", "applied_parameters")):
            raise ValueError("generation state/evidence mismatch")
        if not generated and value["generation_status"] != "planned" and not value["generation_diagnostics"]:
            raise ValueError("generation failure without diagnostics")
    if kind == "build":
        if value["build_status"] == "success" and (not all(value[k] for k in ("compiler_version", "architecture", "binary_sha256", "binary_artifact_reference")) or value["attempt_count"] not in (1, 2, 3)):
            raise ValueError("successful build without provenance")
        if value["build_status"] not in ("planned", "success") and not value["build_diagnostics"]:
            raise ValueError("build failure without diagnostics")
    if kind == "behavior" and value["validation_status"] == "passed":
        cases = value["tested_cases"]
        if not cases or len({c["case_id"] for c in cases}) != len(cases) or value["output_comparison"] != "equal" or value["mismatch_witnesses"] or not value["original_outputs_digest"] or value["original_outputs_digest"] != value["transformed_outputs_digest"]:
            raise ValueError("behavior PASS without matching observations")
        if any(c["original_result"] != c["transformed_result"] or c["oracle_result"] is None or c["oracle_result"] != c["original_result"] for c in cases):
            raise ValueError("behavior PASS contradicts oracle")
    if kind == "graph" and value["extraction_status"] == "success":
        if not all(value[k] is not None for k in ("typed_graph_reference", "typed_graph_sha256", "canonical_graph_reference", "canonical_graph_sha256", "canonical_digest", "anchor_identity", "truncation_metadata")):
            raise ValueError("extraction PASS without artifacts")
    if kind == "mapping":
        left, right = len(value["original_element_references"]), len(value["transformed_element_references"])
        cardinality = value["mapping_kind"]
        good = {"one_to_one": left == right == 1, "one_to_many": left == 1 and right > 1, "many_to_one": left > 1 and right == 1, "unmatched": bool(left) != bool(right), "unknown": left + right > 0, "ambiguous": left + right > 1}
        if not good[cardinality]:
            raise ValueError("invalid mapping cardinality")
        if value["validation_status"] == "verified" and (not value["supporting_evidence"] or not value["observed_mapping"] or cardinality in ("unknown", "ambiguous", "unmatched")):
            raise ValueError("verified mapping lacks evidence")
    if kind == "run":
        for path in value["artifact_hashes"]:
            safe_path(Path.cwd(), path)
        statuses = value["statuses"]
        stages = ("generation", "build", "extraction", "mapping", "validation")
        for index, stage in enumerate(stages):
            if statuses[stage] == "passed" and any(statuses[previous] != "passed" for previous in stages[:index]):
                raise ValueError("invalid phase state transition")
    return value


def validate_bundle(bundle, frozen_reference):
    check_schema(bundle, MANIFEST_SCHEMA)
    portable(bundle)
    if bundle["frozen_dataset_reference"] != frozen_reference:
        raise ValueError("frozen dataset reference mismatch")
    indices = {}
    all_ids = set()
    for collection, kind in COLLECTIONS.items():
        records = {}
        for value in bundle[collection]:
            validate_record(value)
            identity = value[ID_FIELDS[kind]]
            if identity in all_ids:
                raise ValueError("duplicate ID")
            all_ids.add(identity)
            records[identity] = value
        indices[kind] = records

    def ref(kind, identity):
        if identity not in indices[kind]:
            raise ValueError("dangling " + kind + " reference: " + identity)
        return indices[kind][identity]

    for execution in bundle["executions"]:
        specification = ref("specification", execution["transformation_id"])
        if execution["original_source_sha256"] != specification["source_sha256"] or execution["requested_parameters"] != specification["parameters"]:
            raise ValueError("execution source/parameters mismatch")
    for build in bundle["builds"]:
        execution = ref("execution", build["execution_id"])
        if execution["generation_status"] != "generated" or build["source_sha256"] != execution["generated_source_sha256"]:
            raise ValueError("build references ungenerated/different source")
    for behavior in bundle["behaviors"]:
        build = ref("build", behavior["build_id"])
        execution = ref("execution", build["execution_id"])
        specification = ref("specification", execution["transformation_id"])
        if behavior["proof_reference"] != specification["transformation_id"] or behavior["input_contract"] != specification["input_contract"]:
            raise ValueError("behavior proof/contract mismatch")
    for build in bundle["builds"]:
        if build["build_status"] == "success" and not any(b["build_id"] == build["build_id"] and b["validation_status"] == "passed" for b in bundle["behaviors"]):
            raise ValueError("successful build lacks independent behavior validation")
    for graph in bundle["graphs"]:
        build = ref("build", graph["build_id"])
        if build["build_status"] != "success" or graph["binary_sha256"] != build["binary_sha256"] or graph["execution_id"] != build["execution_id"]:
            raise ValueError("graph source/build provenance mismatch")
    for mapping in bundle["mappings"]:
        execution = ref("execution", mapping["execution_id"])
        if mapping["transformation_id"] != execution["transformation_id"]:
            raise ValueError("mapping transformation mismatch")
    for run in bundle["runs"]:
        if run["frozen_dataset_reference"] != frozen_reference:
            raise ValueError("run frozen reference mismatch")
        for kind, field in (("specification", "transformation_ids"), ("execution", "execution_ids"), ("build", "build_ids"), ("graph", "graph_ids"), ("mapping", "mapping_ids")):
            if set(run[field]) != set(indices[kind]):
                raise ValueError("run reference inventory incomplete")
            for identity in run[field]:
                ref(kind, identity)
    return indices


def schema_documents():
    meta = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
    return {
        "transformation.schema.json": dict(meta, anyOf=[SCHEMAS[k] for k in ("specification", "execution", "build", "behavior", "graph")]),
        "experiment.schema.json": dict(meta, **SCHEMAS["run"]),
        "mapping.schema.json": dict(meta, **SCHEMAS["mapping"]),
        "manifest.schema.json": dict(meta, **MANIFEST_SCHEMA),
    }
