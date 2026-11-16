"""Inherit frozen source components; family holdouts are filtered views, never new splits."""

import json
from pathlib import Path

try:
    from .dataset_splits import validate_leakage
    from .step9_preflight import DATA, ROOT, exact_hash, safe_path
    from .transformation_build import persist
    from .transformation_extraction import register_bytes
    from .transformation_harness import load_run
    from .transformation_schema import FAMILIES, VERSION, array, check_schema, closed, enum, serialize, stable_id
except ImportError:
    from dataset_splits import validate_leakage
    from step9_preflight import DATA, ROOT, exact_hash, safe_path
    from transformation_build import persist
    from transformation_extraction import register_bytes
    from transformation_harness import load_run
    from transformation_schema import FAMILIES, VERSION, array, check_schema, closed, enum, serialize, stable_id

ROLES = {"discovery_train": "discovery", "validation": "validation", "held_out_test": "held_out_evaluation"}
POLICY_SCHEMA = closed(schema_version={"const": VERSION}, policy={"const": "frozen-component-inheritance-v1"}, family_holdouts=array(enum(*FAMILIES)), held_out_usage={"const": "evaluation_only_no_parameter_selection"})
DEFAULT_POLICY = dict(schema_version=VERSION, policy="frozen-component-inheritance-v1", family_holdouts=list(FAMILIES), held_out_usage="evaluation_only_no_parameter_selection")


def component_map(manifest):
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    parent = {name: name for name in routines}

    def find(name):
        while parent[name] != name:
            name = parent[name]
        return name

    keys = {}
    config = manifest["split_protocol"]["configuration"]
    for name, routine in sorted(routines.items()):
        associations = [(field, routine[field]) for field in ("artifact_group", "source_group_id", "source_path", "body_sha256")]
        associations += [("source_hash", build["source_hash"]) for build in manifest["builds"] if build["source_path"] == routine["source_path"]]
        associations += [("near_duplicate", index) for index, group in enumerate(config["near_duplicate_groups"]) if routine["source_group_id"] in group]
        for key in associations:
            if key in keys:
                parent[find(name)] = find(keys[key])
            else:
                keys[key] = name
    groups = {}
    for name in routines:
        groups.setdefault(find(name), []).append(name)
    result = {}
    for members in groups.values():
        splits = {config["artifact_splits"][routines[name]["artifact_group"]] for name in members}
        if len(splits) != 1:
            raise ValueError("Frozen source component crosses splits")
        identity = stable_id("source-component", sorted(members))
        result.update({name: identity for name in members})
    return result


def validate_memberships(records, near_duplicate_groups):
    memberships = {}
    identities = set()
    for record in records:
        if record["execution_id"] in identities:
            raise ValueError("Duplicate transformation execution")
        identities.add(record["execution_id"])
        split = record["source_split"]
        if split not in ROLES or record["experimental_role"] != ROLES[split]:
            raise ValueError("Held-out contamination or incorrect experimental role")
        keys = [(field, record[field]) for field in ("source_routine_id", "source_group_id", "source_artifact", "source_sha256", "routine_body_sha256", "inherited_component")]
        keys += [("near_duplicate", index) for index, group in enumerate(near_duplicate_groups) if record["source_group_id"] in group]
        for key in keys:
            memberships.setdefault(key, set()).add(split)
            if len(memberships[key]) != 1:
                raise ValueError("Source/artifact/body/near-duplicate leakage")


def validate_pairs(pairs, graph_splits):
    seen = set()
    for pair in pairs:
        key = tuple(sorted((pair["original_graph_id"], pair["transformed_graph_id"])))
        if len(set(key)) != 2 or key in seen:
            raise ValueError("Duplicate/reversed/self pair")
        seen.add(key)
        if any(graph not in graph_splits for graph in key):
            raise ValueError("Dangling graph split reference")
        if any(graph_splits[graph] != pair["source_split"] for graph in key):
            raise ValueError("Cross-split graph reference")


def family_view(records, family):
    selected = {split: sorted(r["execution_id"] for r in records if r["source_split"] == split and ((r["transformation_family"] == family) if split == "held_out_test" else (r["transformation_family"] != family))) for split in ROLES}
    missing = [split for split, values in selected.items() if not values]
    return dict(family=family, status="unsupported" if missing else "supported", execution_ids=selected, missing_partitions=missing, policy="Exclude family from discovery/validation; evaluate it only on compatible inherited held-out sources.")


def derive_split_report(bundle, run_dir, policy=DEFAULT_POLICY, root=ROOT):
    check_schema(policy, POLICY_SCHEMA)
    root, run_dir = Path(root).resolve(), Path(run_dir).resolve()
    frozen = json.loads((root / DATA / "manifest.json").read_bytes())
    config = frozen["split_protocol"]["configuration"]
    validate_leakage(frozen, config)
    components = component_map(frozen)
    routines = {r["routine_id"]: r for r in frozen["routines"]}
    specifications = {s["transformation_id"]: s for s in bundle["specifications"]}
    generated = json.loads((run_dir / "generation.json").read_bytes())
    records = []
    seen = set()
    for execution in sorted(bundle["executions"], key=lambda e: e["execution_id"]):
        specification = specifications[execution["transformation_id"]]
        routine = routines[specification["source_routine_id"]]
        metadata = generated[execution["execution_id"]]
        expected = (routine["source_group_id"], routine["source_path"], exact_hash(safe_path(root, routine["source_path"])))
        if (specification["source_group_id"], specification["source_artifact"], specification["source_sha256"]) != expected:
            raise ValueError("Tampered frozen source group/artifact/hash")
        split = config["artifact_splits"][routine["artifact_group"]]
        if metadata["source_split"] != split or metadata["routine_body_sha256"] != routine["body_sha256"]:
            raise ValueError("Tampered inherited split/body")
        identity = (specification["source_routine_id"], specification["transformation_family"], serialize(specification["parameters"]), specification["deterministic_seed"])
        if identity in seen:
            raise ValueError("Duplicate transformation")
        seen.add(identity)
        records.append(
            dict(
                execution_id=execution["execution_id"],
                transformation_id=execution["transformation_id"],
                source_routine_id=routine["routine_id"],
                source_group_id=expected[0],
                source_artifact=expected[1],
                source_sha256=expected[2],
                routine_body_sha256=routine["body_sha256"],
                source_split=split,
                inherited_component=components[routine["routine_id"]],
                transformation_family=specification["transformation_family"],
                experimental_role=ROLES[split],
                generation_status=execution["generation_status"],
            )
        )
    validate_memberships(records, config["near_duplicate_groups"])
    splits = {r["execution_id"]: r["source_split"] for r in records}
    graph_splits = {g["graph_id"]: splits[g["execution_id"]] for g in bundle["graphs"]}
    pairs = []
    for build in bundle["builds"]:
        graphs = [g for g in bundle["graphs"] if g["build_id"] == build["build_id"] and g["extraction_status"] == "success"]
        if len(graphs) == 2:
            original = next(g for g in graphs if g["canonical_graph_reference"].endswith("/original.canonical.json"))
            transformed = next(g for g in graphs if g["canonical_graph_reference"].endswith("/transformed.canonical.json"))
            pairs.append(dict(original_graph_id=original["graph_id"], transformed_graph_id=transformed["graph_id"], source_split=splits[build["execution_id"]]))
    pairs.sort(key=serialize)
    validate_pairs(pairs, graph_splits)
    return dict(
        schema_version=VERSION, frozen_dataset_reference=bundle["frozen_dataset_reference"], policy=policy, records=records, graph_splits=dict(sorted(graph_splits.items())), pairs=pairs, family_holdouts=[family_view(records, family) for family in sorted(policy["family_holdouts"])], leakage_validation_status="passed"
    )


def validate_split_report(bundle, run_dir, report, root=ROOT):
    expected = derive_split_report(bundle, run_dir, report["policy"], root)
    validate_memberships(report["records"], json.loads((Path(root) / DATA / "manifest.json").read_bytes())["split_protocol"]["configuration"]["near_duplicate_groups"])
    validate_pairs(report["pairs"], report["graph_splits"])
    if report != expected:
        raise ValueError("Split provenance differs from frozen inheritance")
    return report


def validate_splits(run_dir, policy=DEFAULT_POLICY, root=ROOT):
    run_dir, root = Path(run_dir).resolve(), Path(root).resolve()
    bundle = load_run(run_dir, root)
    if bundle["runs"][0]["statuses"]["mapping"] != "passed":
        raise ValueError("Split admission requires verified mappings")
    report = derive_split_report(bundle, run_dir, policy, root)
    validate_split_report(bundle, run_dir, report, root)
    register_bytes(root, bundle["runs"][0], run_dir / "splits.json", serialize(report))
    persist(run_dir, bundle, root)
    print("SPLITS VERIFIED:", len(report["records"]), "executions;", len(report["pairs"]), "pairs;", {split: sum(r["source_split"] == split for r in report["records"]) for split in ROLES}, flush=True)
    print("FAMILY HOLDOUTS:", {v["family"]: v["status"] for v in report["family_holdouts"]}, flush=True)
    return report
