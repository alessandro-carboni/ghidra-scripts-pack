"""Real Ghidra extraction, with the frozen Rust anchor/canonicalization contracts."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

try:
    from .step9_preflight import ROOT, exact_hash, safe_path
    from .transformation_build import persist, verify_builds
    from .transformation_harness import load_run
    from .transformation_schema import VERSION, serialize, stable_id
except ImportError:
    from step9_preflight import ROOT, exact_hash, safe_path
    from transformation_build import persist, verify_builds
    from transformation_harness import load_run
    from transformation_schema import VERSION, serialize, stable_id


class ExtractionFailure(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def validate_export(document, binary_hash):
    if document.get("model_version") != "0.12.0":
        raise ExtractionFailure("invalid_exporter_output", "Unknown Typed Evidence Graph model version")
    metadata = document.get("metadata", {})
    if metadata.get("research_binary_sha256") != binary_hash:
        raise ExtractionFailure("invalid_exporter_output", "Ghidra analyzed binary hash mismatch")
    if metadata.get("scope") != "complete_seeded_evidence_graph" or metadata.get("truncated") is not False:
        raise ExtractionFailure("incomplete_analysis", "Exporter did not attest complete evidence scope")
    nodes, edges = document.get("nodes"), document.get("edges")
    if not isinstance(nodes, list) or not nodes or not isinstance(edges, list):
        raise ExtractionFailure("invalid_exporter_output", "Missing node/edge collections")
    ids = [n.get("id") for n in nodes]
    if any(not isinstance(i, str) for i in ids) or len(ids) != len(set(ids)):
        raise ExtractionFailure("invalid_exporter_output", "Missing or duplicate node identity")
    if any(e.get("source") not in ids or e.get("target") not in ids for e in edges):
        raise ExtractionFailure("invalid_exporter_output", "Dangling graph edge")
    if metadata.get("node_count") != len(nodes) or metadata.get("edge_count") != len(edges):
        raise ExtractionFailure("incomplete_analysis", "Exporter counts disagree with graph")
    # Full typed-node/edge/property validation is delegated to the existing Rust loader.
    return document


def select_anchor(document, symbols, symbol):
    candidates = {symbols[name] for name in (symbol, "_" + symbol) if name in symbols}
    if len(candidates) != 1:
        raise ExtractionFailure("missing_symbol", "Missing or ambiguous controlled export identity")
    anchor = candidates.pop()
    if not any(n["id"] == anchor and n["type"] == "FUNCTION" for n in document["nodes"]):
        raise ExtractionFailure("missing_anchor", "Symbol does not identify an observed function node")
    return anchor


def canonicalize(engine, typed_path, anchor, output, timeout=180):
    command = [str(Path(engine).resolve()), "canonicalize-research-anchor", str(typed_path), anchor, str(output)]
    try:
        subprocess.run(command, check=True, timeout=timeout, capture_output=True)
    except subprocess.TimeoutExpired as error:
        raise ExtractionFailure("timeout", "Canonicalization timed out") from error
    except subprocess.CalledProcessError as error:
        raise ExtractionFailure("canonicalization_failed", "Existing Rust loader/canonicalizer rejected the graph") from error
    try:
        canonical = json.loads(Path(output).read_bytes())
        if canonical["schema_version"] != VERSION or canonical["source_document"]["anchor_function_id"] != anchor or canonical["anchor_function_id"] != anchor:
            raise ValueError("anchor/schema")
        if canonical["local_graph_truncation"]["requested_depth"] != dict(caller_depth=0, callee_depth=3):
            raise ValueError("depth")
        if not canonical["nodes"] or not canonical["provenance_map"] or not canonical["coverage_ledger"]:
            raise ValueError("missing provenance")
        if not any(n["id"] == anchor for n in canonical["source_document"]["nodes"]):
            raise ValueError("missing source anchor")
    except (ValueError, KeyError, TypeError) as error:
        raise ExtractionFailure("corrupted_graph", "Invalid canonical anchor/provenance contract") from error
    return canonical


def register_bytes(root, run, path, raw):
    """Register LF JSON or exact compiler bytes at creation; never rewrite an existing artifact."""
    relative = path.relative_to(root).as_posix()
    safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError("Existing extraction artifact conflict")
    else:
        with path.open("xb") as stream:
            stream.write(raw)
    digest = hashlib.sha256(raw).hexdigest()
    run["artifact_hashes"][relative] = digest
    return relative, digest


def observe(document, symbols, generated, family, evidence):
    """Topology can witness calls/helpers; instruction effects are outside this graph contract."""
    known = {n["id"] for n in document["nodes"] if n["type"] == "FUNCTION"}
    resolved = {name: symbols.get(name, symbols.get("_" + name)) for name in generated["generated_functions"]}
    limitations = ["Symbols identify controlled generated functions; they do not prove behavioral equivalence."]
    if family in ("dead_branch", "instruction_reordering"):
        return dict(status="not_observable", evidence=evidence, limitations=limitations + ["The typed graph does not expose branch guards or instruction order; no optimization conclusion is supported."])
    transformed = resolved.get(generated["transformed_function"])
    calls = {(e["source"], e["target"]) for e in document["edges"] if e["type"] == "calls_function"}
    reachable = {transformed}
    while True:
        updated = reachable | {b for a, b in calls if a in reachable}
        if updated == reachable:
            break
        reachable = updated
    helpers = set(resolved.values()) - {transformed}
    if family in ("transparent_wrapper", "thunk"):
        helpers.add(symbols.get(generated["original_function"], symbols.get("_" + generated["original_function"])))
    if helpers and None not in helpers and helpers <= known and helpers <= reachable:
        status = "observed"
    elif transformed in known:
        status = "partially_observed"
        limitations.append("Anchor observed, but not every expected helper/call is witnessed; absence does not establish optimized_away.")
    else:
        status = "unknown"
        limitations.append("Insufficient function visibility.")
    return dict(status=status, evidence=evidence, limitations=limitations)


def verify_graphs(bundle, engine, root=ROOT):
    """Recompute from the registered typed source: hashes alone do not prove canonical provenance."""
    for record in bundle["graphs"]:
        if record["extraction_status"] != "success":
            continue
        typed = safe_path(root, record["typed_graph_reference"])
        canonical = safe_path(root, record["canonical_graph_reference"])
        if exact_hash(typed) != record["typed_graph_sha256"] or exact_hash(canonical) != record["canonical_graph_sha256"]:
            raise ValueError("Graph hash mismatch")
        document = validate_export(json.loads(typed.read_bytes()), record["binary_sha256"])
        run_dir = typed.parents[2]
        generated = json.loads((run_dir / "generation.json").read_bytes())[record["execution_id"]]
        execution = next(e for e in bundle["executions"] if e["execution_id"] == record["execution_id"])
        specification = next(s for s in bundle["specifications"] if s["transformation_id"] == execution["transformation_id"])
        symbols_path = typed.with_name("symbols.json")
        symbols = json.loads(symbols_path.read_bytes())
        observed_evidence = [
            dict(artifact_id=record["build_id"], artifact_path=record["typed_graph_reference"], artifact_sha256=record["typed_graph_sha256"], reference="nodes and calls_function edges"),
            dict(artifact_id=record["build_id"], artifact_path=symbols_path.relative_to(root).as_posix(), artifact_sha256=exact_hash(symbols_path), reference="controlled PE export identities"),
        ]
        expected_observation = observe(document, symbols, generated, specification["transformation_family"], observed_evidence)
        if record["observability_metadata"] != expected_observation:
            raise ValueError("Observability claim differs from actual graph evidence")
        toolchain = json.loads((run_dir / "extraction/toolchain.json").read_bytes())
        if record["ghidra_version"] != toolchain["ghidra_version"] or record["exporter_version"] != toolchain["exporter_sources"]["ghidra_scripts/export_research_graph.py"]:
            raise ValueError("Graph toolchain provenance mismatch")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "canonical.json"
            rebuilt = canonicalize(engine, typed, record["anchor_identity"], output)
            if output.read_bytes() != canonical.read_bytes() or rebuilt["canonical_digest"] != record["canonical_digest"]:
                raise ValueError("Canonical provenance or deterministic reconstruction mismatch")
            if rebuilt["local_graph_truncation"] != record["truncation_metadata"]:
                raise ValueError("Truncation claim differs from canonical evidence")


def extract_run(run_dir, ghidra_dir, engine, root=ROOT):
    root, run_dir = Path(root).resolve(), Path(run_dir).resolve()
    bundle = load_run(run_dir, root)
    verify_builds(bundle, root)
    if bundle["graphs"]:
        verify_graphs(bundle, engine, root)
        print("EXTRACTION EXISTING: hashes and canonical reconstruction verified", flush=True)
        return bundle
    run = bundle["runs"][0]
    if run["statuses"]["build"] != "passed":
        raise ValueError("Extraction requires an admitted complete build phase")
    launcher = Path(ghidra_dir) / "support/pyghidraRun.bat"
    properties = Path(ghidra_dir) / "Ghidra/application.properties"
    available = launcher.is_file() and properties.is_file() and Path(engine).is_file()
    version = next((line.split("=", 1)[1].strip() for line in properties.read_text().splitlines() if line.startswith("application.version=")), "unknown") if properties.exists() else "unavailable"
    exporter = exact_hash(root / "ghidra_scripts/export_research_graph.py")
    toolchain = dict(ghidra_version=version, engine_sha256=exact_hash(Path(engine)) if Path(engine).is_file() else None, exporter_sources={p.relative_to(root).as_posix(): exact_hash(p) for p in sorted((root / "ghidra_scripts").glob("*.py"))})
    register_bytes(root, run, run_dir / "extraction/toolchain.json", serialize(toolchain))
    metadata = json.loads((run_dir / "generation.json").read_bytes())
    executions = {e["execution_id"]: e for e in bundle["executions"]}
    specs = {s["transformation_id"]: s for s in bundle["specifications"]}
    timeout = run["experiment_configuration"]["execution_limits"]["timeout_seconds"]
    work_parent = root / ".build-cache/step9-extraction"
    work_parent.mkdir(parents=True, exist_ok=True)
    for build in bundle["builds"]:
        generated = metadata[build["execution_id"]]
        spec = specs[executions[build["execution_id"]]["transformation_id"]]
        failure, document, symbols = None, None, None
        work = Path(tempfile.mkdtemp(prefix=build["build_id"].replace(":", "-") + "-", dir=work_parent))
        raw, projects = work / "raw", work / "projects"
        projects.mkdir()
        imported = work / "program.exe"
        if not available:
            failure = ExtractionFailure("unavailable", "Ghidra launcher/properties or Rust engine unavailable")
        elif build["architecture"] not in ("x86", "x64"):
            failure = ExtractionFailure("unsupported_architecture", "Architecture not supported by the experiment")
        else:
            shutil.copyfile(safe_path(root, build["binary_artifact_reference"]), imported)
            if exact_hash(imported) != build["binary_sha256"]:
                raise ValueError("Import copy hash mismatch")
            print("GHIDRA ANALYZE:", build["build_id"], spec["transformation_family"], flush=True)
            try:
                subprocess.run([str(launcher), "-H", str(projects), "Step9", "-import", str(imported), "-scriptPath", str(root / "ghidra_scripts"), "-postScript", "export_research_graph.py", str(raw)], check=True, timeout=timeout)
                document = validate_export(json.loads((raw / "program.exe.graph.json").read_bytes()), build["binary_sha256"])
                symbols = json.loads((raw / "program.exe.symbols.json").read_bytes())
                if not isinstance(symbols, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in symbols.items()):
                    raise ExtractionFailure("invalid_exporter_output", "Malformed symbol export")
            except subprocess.TimeoutExpired:
                failure = ExtractionFailure("timeout", "Ghidra analysis timed out; partial output not admitted")
            except subprocess.CalledProcessError:
                failure = ExtractionFailure("incomplete_analysis", "Ghidra process failed; partial output not admitted")
            except (OSError, ValueError) as error:
                failure = error if isinstance(error, ExtractionFailure) else ExtractionFailure("invalid_exporter_output", "Missing or malformed exporter output")
        typed_ref, typed_hash, evidence = None, None, []
        if failure is None:
            destination = run_dir / "extraction" / build["build_id"].replace(":", "-")
            # LF serialization is established BEFORE hashing/registration. Raw Ghidra bytes are not compiled-source provenance.
            typed_ref, typed_hash = register_bytes(root, run, destination / "typed.json", serialize(document))
            symbol_ref, symbol_hash = register_bytes(root, run, destination / "symbols.json", serialize(symbols))
            evidence = [dict(artifact_id=build["build_id"], artifact_path=typed_ref, artifact_sha256=typed_hash, reference="nodes and calls_function edges"), dict(artifact_id=build["build_id"], artifact_path=symbol_ref, artifact_sha256=symbol_hash, reference="controlled PE export identities")]
        for role in ("original", "transformed"):
            identity = stable_id("graph", [build["build_id"], role, exporter, version, dict(caller_depth=0, callee_depth=3)])
            record = dict(
                record_type="graph",
                schema_version=VERSION,
                graph_id=identity,
                execution_id=build["execution_id"],
                build_id=build["build_id"],
                binary_sha256=build["binary_sha256"],
                ghidra_version=version,
                exporter_version=exporter,
                extraction_configuration=dict(caller_depth=0, callee_depth=3),
                typed_graph_reference=typed_ref,
                typed_graph_sha256=typed_hash,
                canonical_graph_reference=None,
                canonical_graph_sha256=None,
                canonical_digest=None,
                anchor_identity=None,
                extraction_status="pending",
                observability_metadata=dict(status="unknown", evidence=[], limitations=["No admitted extraction"]),
                truncation_metadata=None,
                diagnostics=[],
            )
            try:
                if failure:
                    raise failure
                anchor = select_anchor(document, symbols, generated[role + "_function"])
                record["anchor_identity"] = anchor
                output = work / (role + ".canonical.json")
                canonical = canonicalize(engine, safe_path(root, typed_ref), anchor, output, timeout)
                rerun = work / (role + ".rerun.json")
                canonicalize(engine, safe_path(root, typed_ref), anchor, rerun, timeout)
                if output.read_bytes() != rerun.read_bytes():
                    raise ExtractionFailure("corrupted_graph", "Canonical rerun bytes differ")
                reference, digest = register_bytes(root, run, destination / (role + ".canonical.json"), output.read_bytes())
                record.update(
                    canonical_graph_reference=reference,
                    canonical_graph_sha256=digest,
                    canonical_digest=canonical["canonical_digest"],
                    truncation_metadata=canonical["local_graph_truncation"],
                    extraction_status="success",
                    observability_metadata=observe(document, symbols, generated, spec["transformation_family"], evidence),
                )
            except ExtractionFailure as error:
                record.update(extraction_status=error.status, diagnostics=[str(error)])
            bundle["graphs"].append(record)
            print("EXTRACT:", spec["transformation_family"], role, record["extraction_status"], record["observability_metadata"]["status"], flush=True)
    bundle["graphs"].sort(key=lambda g: g["graph_id"])
    run["graph_ids"] = [g["graph_id"] for g in bundle["graphs"]]
    passed = sum(g["extraction_status"] == "success" for g in bundle["graphs"])
    run["statuses"]["extraction"] = "passed" if passed == len(bundle["graphs"]) and passed else "partial" if passed else "failed"
    return persist(run_dir, bundle, root)
