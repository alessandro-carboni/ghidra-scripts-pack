"""Step 10.3: source-bound A/B materialization, atomic publication and exact replay."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    from .evaluation_protocol import ROOT, AUDIT_DIR, load_protocol, require, serialize
    from .evaluation_adapter import METHOD, executable, source_inventory
    from .step9_preflight import safe_path, exact_hash
except ImportError:
    from evaluation_protocol import ROOT, AUDIT_DIR, load_protocol, require, serialize
    from evaluation_adapter import METHOD, executable, source_inventory
    from step9_preflight import safe_path, exact_hash

VERSION = "0.1.0"
ENGINE = ROOT / "rust_engine/target/debug" / ("rust_engine.exe" if sys.platform == "win32" else "rust_engine")
DEFAULT_OUTPUT = AUDIT_DIR + "/runtime/catalog-v0_1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def method_approval(root=ROOT):
    folder = Path(root) / AUDIT_DIR / "research_adapter"
    evidence = json.loads((folder / "gate_evidence.json").read_bytes())
    approval = json.loads((folder / "approval.json").read_bytes())
    require(approval["status"] == "approved" and approval["gate_evidence_sha256"] == exact_hash(folder / "gate_evidence.json"), "A/B method not approved or approval stale")
    for path, digest in evidence["code_and_method_utf8_lf_sha256"].items():
        require(sha(safe_path(root, path).read_text(encoding="utf-8").encode()) == digest, "approved method/code changed: " + path)
    require(source_inventory() == json.loads((METHOD / "source_inventory.json").read_bytes()), "adapter dependency version changed")
    return exact_hash(folder / "approval.json")


def plan(root=ROOT, engine=ENGINE, research=None):
    root = Path(root)
    research = executable() if research is None else Path(research)
    protocol = load_protocol(root)
    approval = method_approval(root)
    require(Path(engine).is_file() and research.is_file(), "build both engines before planning")
    identity = dict(
        protocol_sha256=sha(serialize(protocol)),
        approval_sha256=approval,
        engine_sha256=exact_hash(engine),
        research_engine_sha256=exact_hash(research),
        generator_version=VERSION,
        generator_utf8_lf_sha256=sha(Path(__file__).read_text(encoding="utf-8").encode()),
        config=dict(max_topology_motifs=4096, max_interaction_motifs=4096),
        frozen_canonical_version="0.1.0",
        frozen_fingerprint_version="0.1.0",
        research_version="research-0.1.0",
    )
    manifest = json.loads(safe_path(root, "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    samples = {s["sample_id"]: s for s in manifest["samples"]}
    rows = []
    for graph in sorted(manifest["graphs"], key=lambda g: g["graph_id"]):
        source = safe_path(root, graph["path"])
        require(exact_hash(source) == graph["sha256"], "canonical file hash mismatch")
        canonical = json.loads(source.read_bytes())
        require(canonical["canonical_digest"] == graph["canonical_digest"] and canonical["anchor_function_id"] == graph["anchor_function_id"], "canonical identity mismatch")
        local_hash = sha(serialize(canonical["source_document"]))
        sample = samples[graph["sample_id"]]
        for condition in ("A", "B"):
            row = {k: graph[k] for k in ("graph_id", "sample_id", "routine_id", "source_group_id", "split", "anchor_function_id", "canonical_digest", "typed_graph_sha256")}
            row.update(condition=condition, build_id=sample.get("build_id"), sample_sha256=sample["sha256"], canonical_path=graph["path"], canonical_sha256=graph["sha256"], local_serialization_sha256=local_hash)
            row["record_id"] = sha(serialize(dict(identity=identity, record=row)))
            rows.append(row)
    require(len({r["record_id"] for r in rows}) == len(rows), "record identity collision")
    return dict(schema_version=VERSION, identity=identity, graph_count=len(manifest["graphs"]), records=rows)


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=120, check=False)
    if result.returncode:
        # Full diagnostics go to the terminal; avoid personal paths in science.
        print(result.stderr.decode(errors="replace"), file=sys.stderr, flush=True)
        raise ValueError("engine_rejected_input_or_artifact")
    return result.stdout


def artifact(root, path):
    return dict(path=path.relative_to(root).as_posix(), sha256=exact_hash(path), bytes=path.stat().st_size)


def produce(row, output, root=ROOT, engine=ENGINE, research=None):
    """Never read labels or pair data. Every graph, including anchor-only, is attempted."""
    require(row["condition"] in {"A", "B"}, "unsupported condition")
    research = executable() if research is None else research
    source = safe_path(root, row["canonical_path"])
    require(exact_hash(source) == row["canonical_sha256"], "stale canonical hash")
    canonical = json.loads(source.read_bytes())
    local = serialize(canonical["source_document"])
    require(sha(local) == row["local_serialization_sha256"], "corrupt embedded source")
    directory = safe_path(output, row["condition"] + "/" + row["record_id"])
    directory.mkdir(parents=True, exist_ok=False)
    try:
        if row["condition"] == "A":
            local_path = directory / "local.json"
            local_path.write_bytes(local)
            bundle = directory / "bundle.json"
            bundle.write_bytes(run([research, "extract", "A", local_path]))
            run([research, "validate", bundle])
            files = [bundle, local_path]
            doc = json.loads(bundle.read_bytes())
            require(doc["graph"]["condition"] == "A" and doc["input_sha256"] == sha(local), "wrong research provenance")
            fingerprint = doc["fingerprint"]
        else:
            fp = directory / "fingerprint.json"
            run([engine, "fingerprint-canonical", source, fp])
            files = [fp, fp.with_name(fp.name + ".provenance.json")]
            fingerprint = json.loads(fp.read_bytes())
            provenance = json.loads(files[1].read_bytes())
            require(provenance["source_document"] == canonical["source_document"], "wrong frozen sidecar source")
            require(provenance["fingerprint_digest"] == fingerprint["fingerprint_digest"] and fingerprint["source_canonical_digest"] == row["canonical_digest"], "wrong frozen sidecar binding")
        return dict(
            **row,
            status="success",
            artifacts=[artifact(output, p) for p in files],
            fingerprint_version=fingerprint["schema_version"],
            semantic_digest=fingerprint["semantic_digest"],
            fingerprint_digest=fingerprint["fingerprint_digest"],
            motif_truncation=fingerprint["motif_truncation"],
            source_coverage_totals=fingerprint["source_coverage_totals"],
        )
    except (ValueError, subprocess.TimeoutExpired) as error:
        # No artifact is admitted on failure, including any partially created file.
        return dict(**row, status="failed", reason="timeout" if isinstance(error, subprocess.TimeoutExpired) else "engine_or_provenance_validation_failed", artifacts=[])


def materialize(expected, destination, root=ROOT, engine=ENGINE, research=None):
    destination = Path(destination)
    require(not destination.exists(), "output collision; use --verify for an existing catalog")
    require(destination.resolve() == destination.absolute(), "output redirection forbidden")
    require(expected == plan(root, engine, research), "stale or modified plan")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Same-volume directory rename: no incomplete catalog appears at destination.
    with tempfile.TemporaryDirectory(prefix=".catalog-stage-", dir=destination.parent) as temp:
        stage = Path(temp) / "publish"
        stage.mkdir()
        rows = []
        for n, row in enumerate(expected["records"], 1):
            result = produce(row, stage, root, engine, research)
            rows.append(result)
            print(f"{n}/{len(expected['records'])} {row['condition']} {row['graph_id']}: {result['status']}", flush=True)
        report = dict(schema_version=VERSION, plan=expected, status="PASS" if all(r["status"] == "success" for r in rows) else "INCOMPLETE", records=rows)
        (stage / "catalog.json").write_bytes(serialize(report))
        # A complete failure-coverage report may publish as INCOMPLETE, never PASS.
        stage.rename(destination)
    return report


def verify(destination, expected, root=ROOT, engine=ENGINE, research=None):
    destination = Path(destination)
    report = json.loads(safe_path(destination, "catalog.json").read_bytes())
    require(set(report) == {"schema_version", "plan", "status", "records"} and report["schema_version"] == VERSION, "invalid catalog schema")
    require(serialize(report["plan"]) == serialize(expected), "stale input/code/engine/config identity")
    require(len(report["records"]) == len(expected["records"]), "missing graph-condition record")
    require(report["status"] == "PASS", "incomplete catalog is not reusable")
    files = {"catalog.json"}
    with tempfile.TemporaryDirectory(prefix="osgf-catalog-verify-") as temp:
        for row, actual in zip(expected["records"], report["records"]):
            require(all(actual.get(k) == v for k, v in row.items()) and actual.get("status") == "success", "record identity/status mismatch")
            for item in actual["artifacts"]:
                require(set(item) == {"path", "sha256", "bytes"}, "invalid artifact schema")
                p = safe_path(destination, item["path"])
                require(item["path"] not in files, "reused source-bearing artifact")
                files.add(item["path"])
                require(artifact(destination, p) == item, "artifact hash/size mismatch")
            regenerated = produce(row, Path(temp), root, engine, research)
            require(serialize(actual) == serialize(regenerated), "replay/source/provenance mismatch")
    require({p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()} == files, "unexpected catalog files")
    print("CATALOG VERIFIED", len(report["records"]), "records; full source replay=PASS", flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--materialize", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="repository-relative new directory under evaluation runtime/")
    args = parser.parse_args()
    require(args.output.startswith(AUDIT_DIR + "/runtime/"), "outputs must stay in ignored evaluation runtime")
    destination = safe_path(ROOT, args.output)
    expected = plan()
    if args.dry_run:
        print(serialize(expected).decode(), end="")
        return
    report = materialize(expected, destination) if args.materialize else verify(destination, expected)
    counts = Counter((r["condition"], r["status"]) for r in report["records"])
    print("SUMMARY", dict(sorted(counts.items())), "catalog_sha256=" + exact_hash(destination / "catalog.json"), flush=True)
    require(report["status"] == "PASS", "catalog incomplete; see per-record failure coverage")


if __name__ == "__main__":
    main()
