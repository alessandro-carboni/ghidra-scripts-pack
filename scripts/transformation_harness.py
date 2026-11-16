"""Isolated deterministic transformation experiments; later phases are enabled only when implemented."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

try:
    from .step9_preflight import DATA, ROOT, frozen_baseline, repository_state, safe_path
    from .transformation_families import PURE, default_parameters, generate as generate_family
    from .transformation_schema import CONTRACT, FAMILIES, FROZEN, VERSION, array, check_schema, closed, enum, serialize, stable_id, validate_bundle
except ImportError:
    from step9_preflight import DATA, ROOT, frozen_baseline, repository_state, safe_path
    from transformation_families import PURE, default_parameters, generate as generate_family
    from transformation_schema import CONTRACT, FAMILIES, FROZEN, VERSION, array, check_schema, closed, enum, serialize, stable_id, validate_bundle

RUNS = "datasets/osgf_transformations_v0_1/runs"
CONFIG_SCHEMA = closed(
    schema_version={"const": VERSION},
    frozen_dataset_reference=FROZEN,
    selected_source_routines=array(),
    transformations=array(closed(family=enum(*FAMILIES), parameters={"type": "object"}, deterministic_seed={"type": "integer", "minimum": 0, "maximum": 2**32 - 1})),
    compiler_matrix=array(closed(compiler=enum("gcc", "msvc", "clang"), optimization=enum("O0", "O2", "O3"))),
    input_contract=CONTRACT,
    execution_limits=closed(max_variants={"type": "integer", "minimum": 1, "maximum": 64}, max_builds={"type": "integer", "minimum": 1, "maximum": 320}, timeout_seconds={"type": "integer", "minimum": 1, "maximum": 3600}),
    output_policy=closed(root={"const": RUNS}, existing=enum("verify", "reject")),
)


def frozen_reference(baseline):
    return dict(path=baseline["freeze_reference"], scientific_digest=baseline["freeze_scientific_digest"], manifest_file_sha256=baseline["manifest_file_sha256"])


def default_config(baseline):
    return dict(
        schema_version=VERSION,
        frozen_dataset_reference=frozen_reference(baseline),
        selected_source_routines=["sum_array"],
        transformations=[dict(family=family, parameters=default_parameters(family), deterministic_seed=9) for family in FAMILIES],
        compiler_matrix=[dict(compiler="gcc", optimization="O0")],
        input_contract=dict(kind="pure_bytes", min_length=0, max_length=255, trailing_nul=True, result_bits=32, preconditions=["Readable nonvolatile buffer; no concurrent mutation; no externally observable effects."]),
        execution_limits=dict(max_variants=24, max_builds=120, timeout_seconds=600),
        output_policy=dict(root=RUNS, existing="verify"),
    )


def harness_source(generated):
    original, target = generated["original_function"], generated["transformed_function"]
    main = f"""
int main(void) {{
 unsigned n,s,j; unsigned char p[256];
 for(n=0;n<=255;n++) for(s=0;s<4;s++) {{
  for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+s*31+n)%127);
  p[n]=0;
  printf("original %u %u\\n",n*4+s,{original}(p,n));
  printf("transformed %u %u\\n",n*4+s,{target}(p,n));
 }}
 return 0;
}}
"""
    return (generated["source"] + main).replace("\n", "\r\n").encode("utf-8")


def plan(configuration, root=ROOT):
    check_schema(configuration, CONFIG_SCHEMA)
    baseline = frozen_baseline(root)
    reference = frozen_reference(baseline)
    if configuration["frozen_dataset_reference"] != reference:
        raise ValueError("configuration frozen reference mismatch")
    config = json.loads(serialize(configuration))
    for field in ("selected_source_routines", "transformations", "compiler_matrix"):
        if not config[field]:
            raise ValueError("empty experiment selection: " + field)
        config[field] = sorted(config[field], key=serialize)
    count = len(config["selected_source_routines"]) * len(config["transformations"])
    if count > config["execution_limits"]["max_variants"] or count * len(config["compiler_matrix"]) > config["execution_limits"]["max_builds"]:
        raise ValueError("experiment execution limit exceeded")
    manifest = json.loads((Path(root) / DATA / "manifest.json").read_bytes())
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    run_id = stable_id("run", dict(configuration=config, generator_version=VERSION))
    run_path = RUNS + "/" + run_id.replace(":", "-")
    bundle = dict(schema_version=VERSION, frozen_dataset_reference=reference, specifications=[], executions=[], builds=[], behaviors=[], graphs=[], mappings=[], runs=[])
    artifacts = {}
    generated_metadata = {}
    for name in config["selected_source_routines"]:
        if name not in routines or name not in PURE:
            raise ValueError("missing/unsupported original pure source routine: " + name)
        routine = routines[name]
        if routine.get("variant", "original") != "original" or routine["body_sha256"] != hashlib.sha256(PURE[name].encode()).hexdigest():
            raise ValueError("source implementation differs from frozen routine body")
        path = safe_path(root, routine["source_path"])
        source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        source_builds = [b for b in manifest["builds"] if b["source_path"] == routine["source_path"]]
        if not source_builds or any(b["source_hash"] != source_hash for b in source_builds):
            raise ValueError("source bytes differ from compiled provenance")
        splits = {g["split"] for g in manifest["graphs"] if g["routine_id"] == name}
        if len(splits) != 1:
            raise ValueError("original source split missing/ambiguous")
        for requested in config["transformations"]:
            parameters, family, seed = requested["parameters"], requested["family"], requested["deterministic_seed"]
            generated = generate_family(routine, family, parameters, seed, config["input_contract"])
            spec_id = stable_id("transformation", dict(routine=name, source_hash=source_hash, family=family, parameters=parameters, seed=seed, contract=config["input_contract"], version=VERSION))
            execution_id = stable_id("execution", dict(transformation_id=spec_id, run_id=run_id))
            rationale = " ".join(generated["proof_obligations"]) if generated["status"] == "generated" else "No equivalence claim: " + " ".join(generated["diagnostics"])
            specification = dict(
                record_type="specification",
                schema_version=VERSION,
                transformation_id=spec_id,
                transformation_family=family,
                source_routine_id=name,
                source_group_id=routine["source_group_id"],
                source_artifact=routine["source_path"],
                source_sha256=source_hash,
                input_contract=config["input_contract"],
                parameters=parameters,
                deterministic_seed=seed,
                expected_equivalence=dict(claim="equivalent_under_contract" if generated["status"] == "generated" else "unknown", scope="Only the declared finite-length input contract and source proof.", verified=False),
                equivalence_rationale=rationale,
                preconditions=config["input_contract"]["preconditions"],
                expected_source_effects=generated.get("expected_source_effects", []),
                expected_graph_effects=generated.get("expected_graph_effects", []),
                generator_version=VERSION,
            )
            relative = run_path + "/sources/" + execution_id.replace(":", "-") + ".c"
            raw = harness_source(generated) if generated["status"] == "generated" else None
            execution = dict(
                record_type="execution",
                schema_version=VERSION,
                execution_id=execution_id,
                transformation_id=spec_id,
                requested_parameters=parameters,
                applied_parameters=parameters if raw else None,
                generation_status=generated["status"],
                original_source_sha256=source_hash,
                generated_source_sha256=hashlib.sha256(raw).hexdigest() if raw else None,
                generated_source_path=relative if raw else None,
                generation_diagnostics=generated["diagnostics"],
            )
            if raw:
                artifacts[relative] = raw
            generated_metadata[execution_id] = dict(generated, source=None, source_split=next(iter(splits)), source_group_id=routine["source_group_id"], source_artifact=routine["source_path"], routine_body_sha256=routine["body_sha256"])
            bundle["specifications"].append(specification)
            bundle["executions"].append(execution)
    run = dict(
        record_type="run",
        schema_version=VERSION,
        run_id=run_id,
        experiment_configuration=config,
        generator_version=VERSION,
        frozen_dataset_reference=reference,
        frozen_manifest_digest=baseline["manifest_scientific_digest"],
        transformation_ids=sorted(s["transformation_id"] for s in bundle["specifications"]),
        execution_ids=sorted(e["execution_id"] for e in bundle["executions"]),
        build_ids=[],
        graph_ids=[],
        mapping_ids=[],
        statuses=dict(generation="passed" if all(e["generation_status"] == "generated" for e in bundle["executions"]) else "partial", build="pending", extraction="pending", mapping="pending", validation="pending"),
        artifact_hashes={path: hashlib.sha256(raw).hexdigest() for path, raw in artifacts.items()},
        report_references=[],
    )
    bundle["specifications"].sort(key=lambda s: s["transformation_id"])
    bundle["executions"].sort(key=lambda e: e["execution_id"])
    bundle["runs"] = [run]
    validate_bundle(bundle, reference)
    return dict(run_id=run_id, run_path=run_path, bundle=bundle, generated_metadata=generated_metadata), artifacts


def load_run(run_dir, root=ROOT):
    root = Path(root).resolve()
    run_dir = Path(run_dir).resolve()
    if not run_dir.is_relative_to(safe_path(root, RUNS).resolve()) or run_dir == safe_path(root, RUNS).resolve():
        raise ValueError("run directory outside isolated Step 9 runs")
    reference = frozen_reference(frozen_baseline(root))
    bundle = json.loads((run_dir / "manifest.json").read_bytes())
    validate_bundle(bundle, reference)
    if len(bundle["runs"]) != 1 or run_dir.name != bundle["runs"][0]["run_id"].replace(":", "-"):
        raise ValueError("run directory identity mismatch")
    expected, artifacts = plan(bundle["runs"][0]["experiment_configuration"], root)
    run = bundle["runs"][0]
    expected_run = expected["bundle"]["runs"][0]
    if any(run[key] != expected_run[key] for key in ("run_id", "generator_version", "frozen_manifest_digest")) or run["statuses"]["generation"] != expected_run["statuses"]["generation"]:
        raise ValueError("run scientific identity/frozen digest mismatch")
    if any(bundle[key] != expected["bundle"][key] for key in ("specifications", "executions")):
        raise ValueError("run generation contract changed")
    if run["statuses"]["build"] == "passed":
        requested = {(e["execution_id"], c["compiler"], c["optimization"]) for e in bundle["executions"] if e["generation_status"] == "generated" for c in run["experiment_configuration"]["compiler_matrix"]}
        admitted = {(b["execution_id"], b["compiler"], b["optimization"]) for b in bundle["builds"] if b["build_status"] == "success"}
        if not requested or admitted != requested or len(bundle["builds"]) != len(requested):
            raise ValueError("build PASS without complete requested matrix")
    if run["statuses"]["extraction"] == "passed" and (len(bundle["graphs"]) != 2 * len(bundle["builds"]) or any(g["extraction_status"] != "success" for g in bundle["graphs"])):
        raise ValueError("extraction PASS without complete graph coverage")
    for build in bundle["builds"]:
        identity = dict(execution_id=build["execution_id"], configuration=dict(compiler=build["compiler"], optimization=build["optimization"]), compiler_version=build["compiler_version"], source_sha256=build["source_sha256"])
        if build["build_id"] != stable_id("build", identity):
            raise ValueError("build scientific identity mismatch")
    required_artifacts = [(b["binary_artifact_reference"], b["binary_sha256"]) for b in bundle["builds"] if b["build_status"] == "success"]
    required_artifacts += [(g[field + "_reference"], g[field + "_sha256"]) for g in bundle["graphs"] for field in ("typed_graph", "canonical_graph") if g[field + "_reference"] is not None]
    required_artifacts += [(e["artifact_path"], e["artifact_sha256"]) for m in bundle["mappings"] for e in m["supporting_evidence"]]
    if any(run["artifact_hashes"].get(path) != digest for path, digest in required_artifacts):
        raise ValueError("scientific artifact omitted from hash inventory")
    metadata_path = run_dir.relative_to(root).as_posix() + "/generation.json"
    artifacts[metadata_path] = serialize(expected["generated_metadata"])
    for relative, raw in artifacts.items():
        if bundle["runs"][0]["artifact_hashes"].get(relative) != hashlib.sha256(raw).hexdigest():
            raise ValueError("missing/tampered generated artifact hash")
    for relative, expected in bundle["runs"][0]["artifact_hashes"].items():
        path = safe_path(root, relative)
        if not path.resolve().is_relative_to(run_dir) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("run artifact hash/location mismatch")
    return bundle


def generate_run(configuration, root=ROOT, publish=os.rename):
    root = Path(root).resolve()
    planned, artifacts = plan(configuration, root)
    destination = safe_path(root, planned["run_path"])
    if destination.exists():
        if configuration["output_policy"]["existing"] == "reject":
            raise ValueError("run already exists")
        existing = load_run(destination, root)
        if existing["runs"][0]["experiment_configuration"] != planned["bundle"]["runs"][0]["experiment_configuration"]:
            raise ValueError("run identity/configuration collision")
        if (destination / "generation.json").read_bytes() != serialize(planned["generated_metadata"]):
            raise ValueError("existing generation metadata conflict")
        for relative, expected in artifacts.items():
            if safe_path(root, relative).read_bytes() != expected:
                raise ValueError("existing source conflict")
        return destination, existing
    parent = safe_path(root, RUNS)
    parent.mkdir(parents=True, exist_ok=True)
    staging_parent = safe_path(root, RUNS + "/.staging")
    staging_parent.mkdir(exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="generation-", dir=staging_parent))
    # Failed/interrupted stages are deliberately retained for diagnosis, never counted as runs.
    for relative, raw in artifacts.items():
        staged = stage / Path(relative).relative_to(planned["run_path"])
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(raw)
        if staged.read_bytes() != raw:
            raise ValueError("partial source write")
    metadata = serialize(planned["generated_metadata"])
    (stage / "generation.json").write_bytes(metadata)
    planned["bundle"]["runs"][0]["artifact_hashes"][planned["run_path"] + "/generation.json"] = hashlib.sha256(metadata).hexdigest()
    (stage / "manifest.json").write_bytes(serialize(planned["bundle"]))
    validate_bundle(json.loads((stage / "manifest.json").read_bytes()), planned["bundle"]["frozen_dataset_reference"])
    if destination.exists():
        raise ValueError("run publication collision")
    publish(stage, destination)
    return destination, load_run(destination, root)


def run_pipeline(configuration, ghidra_dir, engine, policy, fresh_replay=False):
    try:
        from .transformation_build import build_run
        from .transformation_extraction import extract_run
        from .transformation_mapping import map_run
        from .validate_transformation_harness import validate_run
        from .transformation_report import report_run
        from .replay_transformation_harness import replay_run
    except ImportError:
        from transformation_build import build_run
        from transformation_extraction import extract_run
        from transformation_mapping import map_run
        from validate_transformation_harness import validate_run
        from transformation_report import report_run
        from replay_transformation_harness import replay_run
    path, bundle = generate_run(configuration)
    if bundle["runs"][0]["statuses"]["generation"] != "passed":
        report_run(path, engine)
        raise ValueError("Generation incomplete; later phases not run")
    for name, action in (("build", lambda: build_run(path)), ("extraction", lambda: extract_run(path, ghidra_dir, engine)), ("mapping", lambda: map_run(path, engine=engine))):
        bundle = action()
        if bundle["runs"][0]["statuses"][name] != "passed":
            report_run(path, engine)
            raise ValueError(name + " incomplete; later phases not run")
    validate_run(path, engine, policy)
    if fresh_replay:
        replay_run(path, ghidra_dir, engine)
    return report_run(path, engine)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generation = commands.add_parser("generate")
    generation.add_argument("--config", type=Path, required=True)
    building = commands.add_parser("build")
    building.add_argument("--run", type=Path, required=True)
    extracting = commands.add_parser("extract")
    extracting.add_argument("--run", type=Path, required=True)
    extracting.add_argument("--ghidra-dir", type=Path, required=True)
    extracting.add_argument("--engine", type=Path, required=True)
    mapping = commands.add_parser("map")
    mapping.add_argument("--run", type=Path, required=True)
    mapping.add_argument("--engine", type=Path)
    validation = commands.add_parser("validate")
    validation.add_argument("--run", type=Path, required=True)
    validation.add_argument("--split-policy", type=Path, default=ROOT / "datasets/osgf_transformations_v0_1/config/split_policy.json")
    validation.add_argument("--engine", type=Path)
    reporting = commands.add_parser("report")
    reporting.add_argument("--run", type=Path, required=True)
    reporting.add_argument("--engine", type=Path)
    running = commands.add_parser("run")
    running.add_argument("--config", type=Path, required=True)
    running.add_argument("--ghidra-dir", type=Path, required=True)
    running.add_argument("--engine", type=Path, required=True)
    running.add_argument("--split-policy", type=Path, default=ROOT / "datasets/osgf_transformations_v0_1/config/split_policy.json")
    running.add_argument("--fresh-replay", action="store_true")
    # No placeholders masquerade as implemented phases: unsupported subcommands fail argparse.
    args = parser.parse_args()
    repository_state()
    if args.command == "generate":
        path, bundle = generate_run(json.loads(args.config.read_bytes()))
        counts = {status: sum(e["generation_status"] == status for e in bundle["executions"]) for status in ("generated", "unsupported", "failed")}
        print("GENERATION:", bundle["runs"][0]["run_id"], path.relative_to(ROOT).as_posix(), counts, flush=True)
        if bundle["runs"][0]["statuses"]["generation"] != "passed":
            raise SystemExit(1)
    elif args.command == "build":
        try:
            from .transformation_build import build_run
        except ImportError:
            from transformation_build import build_run
        bundle = build_run(args.run)
        print("BUILD SUMMARY:", {status: sum(b["build_status"] == status for b in bundle["builds"]) for status in sorted({b["build_status"] for b in bundle["builds"]})}, flush=True)
        if bundle["runs"][0]["statuses"]["build"] != "passed":
            raise SystemExit(1)
    elif args.command == "extract":
        try:
            from .transformation_extraction import extract_run
        except ImportError:
            from transformation_extraction import extract_run
        bundle = extract_run(args.run, args.ghidra_dir, args.engine)
        print("EXTRACTION SUMMARY:", bundle["runs"][0]["statuses"]["extraction"], len(bundle["graphs"]), flush=True)
        if bundle["runs"][0]["statuses"]["extraction"] != "passed":
            raise SystemExit(1)
    elif args.command == "map":
        try:
            from .transformation_mapping import map_run
        except ImportError:
            from transformation_mapping import map_run
        map_run(args.run, engine=args.engine)
    elif args.command == "validate":
        try:
            from .validate_transformation_harness import validate_run
        except ImportError:
            from validate_transformation_harness import validate_run
        validate_run(args.run, args.engine, json.loads(args.split_policy.read_bytes()))
    elif args.command == "report":
        try:
            from .transformation_report import report_run
        except ImportError:
            from transformation_report import report_run
        report = report_run(args.run, args.engine)
        if report["acceptance_status"] != "passed":
            raise SystemExit(1)
    elif args.command == "run":
        run_pipeline(json.loads(args.config.read_bytes()), args.ghidra_dir, args.engine, json.loads(args.split_policy.read_bytes()), args.fresh_replay)


if __name__ == "__main__":
    main()
