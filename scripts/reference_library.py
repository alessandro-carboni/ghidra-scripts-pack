"""Versioned, source-validated reference manifests. No database, sample execution or labels inferred from scores."""

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re

try:
    from . import graph_first as graph
    from . import reference_coverage as coverage
    from . import graph_first_evaluation as evaluation
except ImportError:
    import graph_first as graph
    import reference_coverage as coverage
    import graph_first_evaluation as evaluation

SCHEMA = "osgf.reference-library/0.1.0"
ENTRY = "osgf.reference-entry/0.1.0"
FROZEN = "osgf.frozen-reference/0.1.0"
LABELS = {"documented_malicious_functionality", "malware_associated_functionality", "generic_functionality", "benign_reference", "unknown"}
POLICIES = ("baseline_set", "graph_first_set", "reference_set", "reference_multiset", "relation_typed_set")
DEFINITIONS = dict(
    baseline_set="Mean comparable frozen semantic-view set Jaccard; intersection/union per view",
    graph_first_set="Mean comparable existing graph-first view set Jaccard, including co-observations",
    reference_set="Distinct matched base-evidence values / distinct reference base-evidence values",
    reference_multiset="Sum min(query count, reference count) / sum reference counts for base-evidence values",
    relation_typed_set="Matched distinct typed-evidence descriptors / distinct reference typed-evidence descriptors",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def keys(value, expected):
    graph.require(isinstance(value, dict) and set(value) == set(expected.split()), "incorrect object fields: " + expected)


def text(value):
    graph.require(isinstance(value, str) and bool(value.strip()), "nonempty text required")


def hash_value(value):
    graph.require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None, "invalid SHA-256")


def safe_path(root, relative):
    root = Path(root).absolute()
    p = Path(relative)
    graph.require(not p.is_absolute() and p.parts and all(v not in {"..", "."} for v in p.parts) and ":" not in relative, "unsafe artifact path")
    candidate = root / p
    graph.require(candidate.resolve().is_relative_to(root.resolve()), "artifact escapes library")
    for part in (root, *(root.joinpath(*p.parts[:i]) for i in range(1, len(p.parts) + 1))):
        if part.exists() or part.is_symlink():
            stat = part.lstat()
            graph.require(not part.is_symlink() and not (getattr(stat, "st_file_attributes", 0) & 0x400), "redirected library path rejected")
    return candidate


def init(root):
    root = Path(root)
    graph.require(not root.exists(), "new library directory required")
    root.mkdir(parents=True)
    (root / "artifacts").mkdir()
    (root / "entries").mkdir()
    graph.write(root / "manifest.json", dict(schema_version=SCHEMA, entries=[]))


def manifest(root):
    value = graph.load(safe_path(root, "manifest.json"))
    keys(value, "schema_version entries")
    graph.require(value["schema_version"] == SCHEMA and isinstance(value["entries"], list), "unsupported library schema")
    ids = []
    for row in value["entries"]:
        keys(row, "reference_id path sha256")
        graph.require(re.fullmatch(r"reference:[0-9a-f]{64}", row["reference_id"]) is not None, "invalid reference ID")
        hash_value(row["sha256"])
        graph.require(row["path"] == "entries/" + row["sha256"] + ".json", "entry is not content-addressed")
        ids.append(row["reference_id"])
    graph.require(ids == sorted(set(ids)), "duplicate or unordered reference IDs")
    return value


def validate_annotation(annotation):
    keys(annotation, "sample functional_region extraction_tool_version provenance_reference")
    sample = annotation["sample"]
    keys(sample, "sha256 executable_format architecture source acquisition_date authorization_or_provenance family_label_if_known")
    hash_value(sample["sha256"])
    for k in ("executable_format", "architecture", "source", "authorization_or_provenance"):
        text(sample[k])
    graph.require(date.fromisoformat(sample["acquisition_date"]).isoformat() == sample["acquisition_date"], "invalid acquisition date")
    graph.require(sample["family_label_if_known"] is None or isinstance(sample["family_label_if_known"], str), "invalid family attribution")
    region = annotation["functional_region"]
    keys(region, "region_id analyst_annotation described_functionality annotation_source annotation_status annotation_confidence_or_uncertainty classification")
    for k in ("region_id", "analyst_annotation", "described_functionality", "annotation_source", "annotation_confidence_or_uncertainty"):
        text(region[k])
    graph.require(region["classification"] in LABELS, "unsupported region classification")
    graph.require(region["annotation_status"] in {"verified", "qualified", "unreviewed"}, "unsupported annotation status")
    if region["classification"] == "documented_malicious_functionality":
        graph.require(region["annotation_status"] == "verified", "documented functionality requires verified annotation")
    text(annotation["extraction_tool_version"])
    text(annotation["provenance_reference"])


def graph_artifact(document, engine):
    if document.get("schema_version") == graph.SCHEMA:
        graph.validate(document, engine)
        return document, "stored_graph_first; no migration"
    if document.get("schema_version") == FROZEN:
        keys(document, "schema_version canonical fingerprint origin_graph")
        derived = graph.fingerprint(document["canonical"]["source_document"], engine, document["origin_graph"])
        graph.require(graph.encoded(derived["canonical"]) == graph.encoded(document["canonical"]), "invalid canonical binding")
        graph.require(graph.encoded(derived["baseline"]) == graph.encoded(document["fingerprint"]), "invalid frozen fingerprint binding")
        return derived, "explicit_transient_adapter: frozen-v0.1 to graph-first projection; stored artifact unchanged"
    raise ValueError("incompatible representation schema")


def identity(sample, region, fp, schema):
    return "reference:" + sha(graph.encoded(dict(sample=sample["sha256"], region=region["region_id"], canonical=fp["canonical"]["canonical_digest"], fingerprint=fp["semantic_digest"], stored_schema=schema)))


def bind_sample(fp, sample):
    origin = fp["seed_origin"]
    graph.require(origin is not None, "library requires source-bound automatically detected seeds")
    observed = origin["graph"].get("metadata", {}).get("research_binary_sha256")
    graph.require(observed == sample["sha256"], "sample hash differs from extraction provenance")


def seed_record(fp):
    origin = fp["seed_origin"]
    return dict(detected_seed_id=fp["canonical"]["seed_id"], trigger_evidence=origin["seed"], extraction_configuration=fp["canonical"]["source_document"]["extraction_config"])


def store(root, folder, raw):
    digest = sha(raw)
    relative = folder + "/" + digest + ".json"
    path = safe_path(root, relative)
    if path.exists():
        graph.require(path.read_bytes() == raw, "content-address collision")
    else:
        with path.open("xb") as stream:
            stream.write(raw)
    return dict(path=relative, sha256=digest)


def register(root, artifact_path, sample_path, annotation, engine, operational_path=None, operational_engine=None):
    validate_annotation(annotation)
    graph.require(sha(Path(sample_path).read_bytes()) == annotation["sample"]["sha256"], "sample source hash mismatch")
    raw = Path(artifact_path).read_bytes()
    document = json.loads(raw)
    fp, adapter = graph_artifact(document, engine)
    bind_sample(fp, annotation["sample"])
    ident = identity(annotation["sample"], annotation["functional_region"], fp, document["schema_version"])
    op_raw = None
    if operational_path:
        result = graph.compare(fp, fp, engine)
        graph.operational(result, operational_path, operational_path, operational_engine)
        op_raw = Path(operational_path).read_bytes()
    lock = safe_path(root, "register.lock")
    handle = lock.open("xb")
    try:
        with handle:
            current = manifest(root)
            graph.require(ident not in {r["reference_id"] for r in current["entries"]}, "duplicate reference ID; replacement refused")
            artifact = store(root, "artifacts", raw)
            optional = store(root, "artifacts", op_raw) if op_raw is not None else None
            entry = dict(
                reference_id=ident,
                reference_schema_version=ENTRY,
                sample=annotation["sample"],
                functional_region=annotation["functional_region"],
                seed=seed_record(fp),
                fingerprint=dict(schema_version=document["schema_version"], canonical_digest=fp["canonical"]["canonical_digest"], fingerprint_digest=fp["semantic_digest"], artifact=artifact, optional_operational_artifact=optional, adapter=adapter),
                integrity=dict(extraction_tool_version=annotation["extraction_tool_version"], provenance_reference=annotation["provenance_reference"], sample_sha256_verified_at_registration=True),
            )
            location = store(root, "entries", graph.encoded(entry))
            current["entries"].append(dict(reference_id=ident, **location))
            current["entries"].sort(key=lambda row: row["reference_id"])
            temporary = safe_path(root, "manifest.pending.json")
            graph.write(temporary, current)
            os.replace(temporary, safe_path(root, "manifest.json"))
    finally:
        lock.unlink()
    return entry


def read_entry(root, row, engine, operational_engine=None):
    raw = safe_path(root, row["path"]).read_bytes()
    graph.require(sha(raw) == row["sha256"], "entry hash mismatch")
    entry = json.loads(raw)
    keys(entry, "reference_id reference_schema_version sample functional_region seed fingerprint integrity")
    graph.require(entry["reference_schema_version"] == ENTRY and entry["reference_id"] == row["reference_id"], "incorrect entry schema/identity")
    keys(entry["integrity"], "extraction_tool_version provenance_reference sample_sha256_verified_at_registration")
    graph.require(entry["integrity"]["sample_sha256_verified_at_registration"] is True, "unverified source hash")
    validate_annotation({k: entry[k] for k in ("sample", "functional_region")} | {k: entry["integrity"][k] for k in ("extraction_tool_version", "provenance_reference")})
    binding = entry["fingerprint"]
    keys(binding, "schema_version canonical_digest fingerprint_digest artifact optional_operational_artifact adapter")
    for artifact in (binding["artifact"], binding["optional_operational_artifact"]):
        if artifact is not None:
            keys(artifact, "path sha256")
            hash_value(artifact["sha256"])
            graph.require(artifact["path"] == "artifacts/" + artifact["sha256"] + ".json", "artifact is not content-addressed")
            graph.require(sha(safe_path(root, artifact["path"]).read_bytes()) == artifact["sha256"], "artifact hash mismatch")
    doc = graph.load(safe_path(root, binding["artifact"]["path"]))
    fp, adapter = graph_artifact(doc, engine)
    bind_sample(fp, entry["sample"])
    graph.require(binding["schema_version"] == doc["schema_version"] and binding["canonical_digest"] == fp["canonical"]["canonical_digest"] and binding["fingerprint_digest"] == fp["semantic_digest"] and binding["adapter"] == adapter, "fingerprint binding mismatch")
    graph.require(graph.encoded(entry["seed"]) == graph.encoded(seed_record(fp)), "seed provenance mismatch")
    graph.require(entry["reference_id"] == identity(entry["sample"], entry["functional_region"], fp, doc["schema_version"]), "reference ID mismatch")
    if binding["optional_operational_artifact"] is not None and operational_engine:
        op = safe_path(root, binding["optional_operational_artifact"]["path"])
        graph.operational(graph.compare(fp, fp, engine), op, op, operational_engine)
    return entry, fp


def validate(root, engine, operational_engine=None):
    return [read_entry(root, r, engine, operational_engine)[0] for r in manifest(root)["entries"]]


def score(result, policy):
    if policy == "baseline_set":
        return result["symmetric_similarity"]["original_baseline"]["aggregate_set_similarity"]
    if policy == "graph_first_set":
        return result["symmetric_similarity"]["existing_graph_first"]["set_similarity"]
    if policy == "relation_typed_set":
        return result["relation_aware_coverage"]["per_view"]["typed_evidence"]["set"]
    return result["reference_coverage"]["set" if policy == "reference_set" else "multiset"]


def search(query, root, engine, policy="reference_set", query_operational=None, operational_engine=None):
    graph.require(policy in POLICIES, "unknown ranking policy")
    graph.validate(query, engine)
    available, issues = [], []
    for row in manifest(root)["entries"]:
        try:
            # Optional semantic incompatibility must not erase valid graph evidence.
            # Byte-integrity failures still reject the entry; operational binding is
            # checked separately below when both sides and the engine are supplied.
            entry, fp = read_entry(root, row, engine)
            available.append((entry, fp))
        except (OSError, ValueError, KeyError, TypeError) as error:
            issues.append(dict(reference_id=row["reference_id"], status="unavailable" if isinstance(error, OSError) else "incompatible" if "incompatible" in str(error) else "invalid", reason=str(error)))
    # Reuse the existing authoritative exhaustive graph-first search.
    legacy = graph.search(query, [(e["reference_id"], f) for e, f in available], engine)
    by_id = {row["reference_id"]: row["result"] for row in legacy["candidates"]}
    rows = []
    for entry, fp in available:
        result = coverage.compare(query, fp, engine)
        auxiliary = dict(status="unavailable", score=None, reason="optional operational evidence not supplied on both sides")
        op = entry["fingerprint"]["optional_operational_artifact"]
        if query_operational and op and operational_engine:
            try:
                compared = graph.operational(by_id[entry["reference_id"]], query_operational, safe_path(root, op["path"]), operational_engine)["operational_evidence"]["comparison"]
                auxiliary = dict(status="available", score=compared["operational"]["set_similarity"], comparison=compared)
            except (ValueError, OSError) as error:
                auxiliary = dict(status="incompatible", score=None, reason=str(error))
        rows.append(dict(reference=entry["reference_id"], reference_metadata=entry, score=score(result, policy), coverage=result, operational_evidence=auxiliary))
    rows = evaluation.rank(rows, "B")
    usable = [r["score"] for r in rows if r["score"] is not None]
    return dict(
        schema_version="osgf.library-ranking/0.1.0",
        policy=policy + "/0.1.0",
        score_definition=DEFINITIONS[policy],
        query_identity=query["canonical"]["seed_id"],
        candidate_count=len(rows),
        catalog_count=len(manifest(root)["entries"]),
        comparable_count=len(usable),
        tied_candidate_count=sum(usable.count(s) > 1 for s in usable),
        tie_break="score descending, null last, reference ID ascending",
        candidates=[dict(rank=i + 1, **row) for i, row in enumerate(rows)],
        excluded_references=issues,
        interpretation="Reference evidence correspondence; not a malware verdict or behavioral-equivalence proof",
    )


def workflow(typed_graph, root, engine, output, policy="reference_set", operational_by_anchor=None, operational_engine=None):
    output = Path(output)
    graph.require(not output.exists(), "fresh workflow output required")
    output.mkdir(parents=True)
    index = graph.extract(typed_graph, engine, output / "extraction")
    results = []
    for record in index["records"]:
        fp = graph.load(output / "extraction" / record["fingerprint"])
        results.append(dict(seed_id=record["seed_id"], anchor=record["anchor"], ranking=search(fp, root, engine, policy, (operational_by_anchor or {}).get(record["anchor"]), operational_engine)))
    result = dict(
        schema_version="osgf.reference-workflow/0.1.0", eligible=index["eligible"], status="compared" if index["eligible"] else "no_eligible_seed", extraction=index, query_subgraphs=results, executable_score=None, interpretation="Each seed is compared independently; no executable-level similarity or verdict"
    )
    graph.write(output / "results.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("init", "register", "validate", "list", "inspect", "search", "workflow"))
    p.add_argument("--library", type=Path, required=True)
    p.add_argument("--engine", type=Path)
    p.add_argument("--artifact", type=Path)
    p.add_argument("--sample", type=Path)
    p.add_argument("--annotation", type=Path)
    p.add_argument("--reference-id")
    p.add_argument("--query", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--policy", choices=POLICIES, default="reference_set")
    p.add_argument("--operational", type=Path)
    p.add_argument("--operational-engine", type=Path)
    args = p.parse_args()
    if args.output:
        graph.require(not args.output.exists(), "refuse existing output")
    if args.action == "init":
        init(args.library)
        print("LIBRARY INITIALIZED")
        return
    graph.require(args.engine is not None, "engine required")
    if args.action == "register":
        graph.require(all((args.artifact, args.sample, args.annotation)), "artifact, source sample and annotation required")
        result = register(args.library, args.artifact, args.sample, graph.load(args.annotation), args.engine, args.operational, args.operational_engine)
    elif args.action in {"validate", "list", "inspect"}:
        result = validate(args.library, args.engine, args.operational_engine)
        if args.action == "inspect":
            result = [e for e in result if e["reference_id"] == args.reference_id]
            graph.require(len(result) == 1, "reference not found")
    else:
        graph.require(args.query and args.output, "query and new output required")
        if args.action == "workflow":
            workflow(graph.load(args.query), args.library, args.engine, args.output, args.policy)
            print("WORKFLOW WRITTEN", args.output)
            return
        graph.require(not args.output.exists(), "refuse existing output")
        result = search(graph.load(args.query), args.library, args.engine, args.policy, args.operational, args.operational_engine)
    if args.output:
        graph.write(args.output, result)
    else:
        print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
