"""Build only verified generated sources; admit PE outputs after independent behavior checks."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

try:
    from .controlled_build import BuildFailure, CommandFailure, build_pe, pe_architecture, portable_flags, sanitize_text
    from .controlled_corpus import compiler_inventory
    from .step9_preflight import ROOT, exact_hash, safe_path
    from .transformation_harness import load_run
    from .transformation_schema import VERSION, serialize, stable_id, validate_bundle
    from .validate_controlled_corpus import expected
except ImportError:
    from controlled_build import BuildFailure, CommandFailure, build_pe, pe_architecture, portable_flags, sanitize_text
    from controlled_corpus import compiler_inventory
    from step9_preflight import ROOT, exact_hash, safe_path
    from transformation_harness import load_run
    from transformation_schema import VERSION, serialize, stable_id, validate_bundle
    from validate_controlled_corpus import expected


def cases():
    return [(index, [(j * 17 + salt * 31 + length) % 127 for j in range(length)]) for index in range(1024) for length, salt in [divmod(index, 4)]]


def behavior_record(rows, specification, generated, build_id, oracle=expected):
    observations = {}
    diagnostic = None
    try:
        for row in rows:
            side, case, output = row.split()
            case, output = int(case), int(output)
            if side not in ("original", "transformed") or not 0 <= case < 1024 or not 0 <= output < 2**32 or (side, case) in observations:
                raise ValueError("invalid/duplicate behavior row")
            observations[(side, case)] = output
        if len(observations) != 2048:
            raise ValueError("incomplete dual behavior transcript")
    except (ValueError, TypeError):
        diagnostic = "Malformed, duplicate or incomplete original/transformed transcript"
    tested, mismatches = [], []
    unavailable = False
    for case, values in cases():
        left, right = observations.get(("original", case)), observations.get(("transformed", case))
        reference = oracle(specification["source_routine_id"], values)
        unavailable |= reference is None
        if left is None or right is None:
            continue
        tested.append(dict(case_id=case, input_bytes=values, original_result=left, transformed_result=right, oracle_result=reference))
        if reference is not None and (left != reference or right != reference):
            mismatches.append(dict(case_id=case, input_bytes=values, original_result=left, transformed_result=right, oracle_result=reference))
    passed = diagnostic is None and not unavailable and not mismatches
    return dict(
        record_type="behavior",
        schema_version=VERSION,
        behavior_id=stable_id("behavior", build_id),
        build_id=build_id,
        original_routine=generated["original_function"],
        transformed_routine=generated["transformed_function"],
        input_contract=specification["input_contract"],
        oracle_version=VERSION,
        tested_cases=tested,
        original_outputs_digest=hashlib.sha256(serialize([[r["case_id"], r["original_result"]] for r in tested])).hexdigest() if tested else None,
        transformed_outputs_digest=hashlib.sha256(serialize([[r["case_id"], r["transformed_result"]] for r in tested])).hexdigest() if tested else None,
        output_comparison="unknown" if diagnostic else "equal" if all(r["original_result"] == r["transformed_result"] for r in tested) else "different",
        mismatch_witnesses=mismatches,
        side_effect_observations=dict(status="source_proven_pure", evidence=generated["proof_obligations"]),
        validation_status="passed" if passed else "unsupported" if unavailable else "failed",
        proof_reference=specification["transformation_id"],
        limitations=["Finite deterministic coverage, not exhaustive byte sequences; purity is source-proven, not a dynamic OS-effect trace."] + ([diagnostic] if diagnostic else []) + (["Independent oracle unavailable"] if unavailable else []),
    )


def persist(run_dir, bundle, root=ROOT):
    validate_bundle(bundle, bundle["frozen_dataset_reference"])
    temporary = Path(run_dir) / "manifest.pending.json"
    with temporary.open("xb") as stream:
        stream.write(serialize(bundle))
    os.replace(temporary, Path(run_dir) / "manifest.json")
    return load_run(run_dir, root)


def verify_builds(bundle, root=ROOT):
    for build in bundle["builds"]:
        if build["build_status"] == "success":
            path = safe_path(root, build["binary_artifact_reference"])
            if exact_hash(path) != build["binary_sha256"] or pe_architecture(path) != build["architecture"]:
                raise ValueError("validated build binary integrity mismatch")


def build_run(run_dir, root=ROOT, inventory=compiler_inventory, builder=build_pe):
    root, run_dir = Path(root).resolve(), Path(run_dir).resolve()
    bundle = load_run(run_dir, root)
    if bundle["builds"]:
        verify_builds(bundle, root)
        print("BUILD EXISTING: retained validated artifacts and explicit failure records", flush=True)
        return bundle
    try:
        compilers, unavailable = inventory()
    except ValueError:
        compilers, unavailable = [], ["No compiler available"]
    available = {c["compiler"]: c for c in compilers}
    specifications = {s["transformation_id"]: s for s in bundle["specifications"]}
    generated_metadata = json.loads((run_dir / "generation.json").read_bytes())
    run = bundle["runs"][0]
    timeout = min(run["experiment_configuration"]["execution_limits"]["timeout_seconds"], 180)
    for execution in bundle["executions"]:
        if execution["generation_status"] != "generated":
            continue
        specification = specifications[execution["transformation_id"]]
        generated = generated_metadata[execution["execution_id"]]
        source = safe_path(root, execution["generated_source_path"])
        if exact_hash(source) != execution["generated_source_sha256"]:
            raise ValueError("source changed before compilation")
        for configuration in run["experiment_configuration"]["compiler_matrix"]:
            compiler = available.get(configuration["compiler"])
            identity = dict(execution_id=execution["execution_id"], configuration=configuration, compiler_version=compiler["version"] if compiler else None, source_sha256=execution["generated_source_sha256"])
            build_id = stable_id("build", identity)
            directory = run_dir / "binaries" / build_id.replace(":", "-")
            output = directory / "program.exe"
            record = dict(
                record_type="build",
                schema_version=VERSION,
                build_id=build_id,
                execution_id=execution["execution_id"],
                compiler=configuration["compiler"],
                compiler_version=compiler["version"] if compiler else None,
                optimization=configuration["optimization"],
                architecture=None,
                compiler_flags=[],
                source_sha256=execution["generated_source_sha256"],
                binary_sha256=None,
                binary_artifact_reference=None,
                build_status="unavailable",
                build_diagnostics=unavailable or ["Requested compiler unavailable"],
                attempt_count=0,
            )
            behavior = None
            if compiler and configuration["optimization"] not in compiler["optimizations"]:
                record.update(build_status="unsupported", build_diagnostics=["Compiler optimization not supported by discovered configuration"])
            elif compiler:

                def flags(target):
                    if compiler["compiler"] == "msvc":
                        return ["/nologo", "/Od" if configuration["optimization"] == "O0" else "/O2", "/Brepro", str(source), f"/Fe{target}", "/link", "/INCREMENTAL:NO", "/OPT:NOICF"]
                    return ["-" + configuration["optimization"], "-Wl,--no-insert-timestamp", str(source), "-o", str(target)]

                def checked_behavior(rows):
                    nonlocal behavior
                    behavior = behavior_record(rows, specification, generated, build_id)
                    if behavior["validation_status"] != "passed":
                        raise ValueError("independent behavior validation failed; see structured witnesses")

                def runner(command, **kwargs):
                    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, **kwargs)
                    if result.returncode:
                        raise CommandFailure(result)
                    return result.stdout.strip()

                try:
                    result = builder(compiler, build_id, configuration["optimization"], output, flags, checked_behavior, root=root, runner=runner)
                    record.update(
                        build_status="success",
                        architecture=result["architecture"],
                        binary_sha256=exact_hash(output),
                        binary_artifact_reference=output.relative_to(root).as_posix(),
                        compiler_flags=result["flags"],
                        build_diagnostics=[json.dumps(item, sort_keys=True) for item in result["attempt_diagnostics"]],
                        attempt_count=result["attempts"],
                    )
                    run["artifact_hashes"][record["binary_artifact_reference"]] = record["binary_sha256"]
                    print("BUILD PASS:", build_id, specification["transformation_family"], configuration, "1024 independent cases", flush=True)
                except BuildFailure as error:
                    failure = error.record
                    phase = failure["attempt_diagnostics"][-1]["phase"]
                    status = "artifact_access_failed" if failure["error_kind"] in ("PermissionError", "OSError") else "compile_failed" if phase == "compile" else "validation_failed"
                    record.update(build_status=status, build_diagnostics=[json.dumps(failure, sort_keys=True)], attempt_count=failure["attempts"], compiler_flags=portable_flags(flags(output), root))
                    print("BUILD FAILED:", build_id, status, sanitize_text(failure["diagnostic"], root), flush=True)
            bundle["builds"].append(record)
            if behavior:
                bundle["behaviors"].append(behavior)
    bundle["builds"].sort(key=lambda b: b["build_id"])
    bundle["behaviors"].sort(key=lambda b: b["behavior_id"])
    run["build_ids"] = [b["build_id"] for b in bundle["builds"]]
    statuses = [b["build_status"] == "success" for b in bundle["builds"]]
    run["statuses"]["build"] = "passed" if statuses and all(statuses) and run["statuses"]["generation"] == "passed" else "partial" if any(statuses) else "failed"
    return persist(run_dir, bundle, root)
