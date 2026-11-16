"""Prospective family-separated benign corpus; compile/static-analyze, never execute targets."""

import argparse
import os
from pathlib import Path
import struct
import tempfile

try:
    from . import graph_first as g
    from . import reference_library as lib
    from . import reference_benchmark as bench
    from . import reference_corpus_sources as sources
    from .run_reference_controlled import execute
except ImportError:
    import graph_first as g
    import reference_library as lib
    import reference_benchmark as bench
    import reference_corpus_sources as sources
    from run_reference_controlled import execute

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "osgf.benign-separated-study/0.1.0"


def pin(a):
    paths = [
        Path(__file__),
        Path(sources.__file__),
        ROOT / "scripts/run_reference_controlled.py",
        ROOT / "ghidra_scripts/export_research_graph.py",
        ROOT / "ghidra_scripts/export_pcode_evidence.py",
        ROOT / "ghidra_scripts/export_report.py",
        ROOT / "ghidra_scripts/pcode_extraction.py",
        a.engine,
        a.operational_engine,
        a.compiler,
    ]
    paths += [ROOT / "scripts" / n for n in ("reference_library.py", "reference_coverage.py", "reference_benchmark.py", "graph_first.py", "graph_first_evaluation.py", "evaluate_operational_baseline.py", "recovered_evidence.py", "diagnose_baseline_core.py")]
    return {str(p.resolve()): lib.sha(p.read_bytes()) for p in paths}


def prepare(a):
    root = a.study.resolve()
    g.require(not root.exists(), "new study directory required")
    root.mkdir(parents=True)
    families = {}
    for name, spec in sources.FAMILIES.items():
        path = root / "sources" / (name + ".c")
        path.parent.mkdir(exist_ok=True)
        path.write_text(sources.source(name), encoding="utf-8", newline="\n")
        families[name] = dict(split=spec["split"], contract=spec["contract"], negative=spec["negative"], source=path.relative_to(root).as_posix(), sha256=lib.sha(path.read_bytes()))
    omitted = getattr(a, "unavailable_family", None)
    reason = getattr(a, "unavailable_reason", None)
    parent = getattr(a, "parent_protocol", None)
    g.require(not omitted or (omitted in families and reason and parent and parent.is_file()), "unavailable family requires reason and preserved parent protocol")
    if parent:
        previous = g.load(parent)
        g.require(previous["schema_version"] == SCHEMA and previous["families"] == families, "parent source contracts or split assignments changed")
    g.write(
        root / "protocol.json",
        dict(
            schema_version=SCHEMA,
            families=families,
            conditions=bench.CONDITIONS,
            implementation=pin(a),
            compiler=str(a.compiler.resolve()),
            builds=[dict(optimization="O0", role="reference"), dict(optimization="O2", role="query")],
            labels="source-contract: subject/equivalent positive; foil distinct; no labels from scores",
            partitions="one distinct authored functional source lineage per split; shared includes/test harness/CRT documented, no claim of external independent annotation",
            threshold="discovery only; no parameter/weight/feature tuning after heldout",
            safety="benign programs; no target execution, network communication or security changes",
            missingness="retain all planned pairs and expected region coverage; unavailable comparisons remain null; never fabricate anchors or silently discard missing regions",
            limitations="only three correlated authored families; exploratory heldout family transfer, not representative malware generalization",
            unavailable_families={omitted: reason} if omitted else {},
            parent_protocol=dict(path=str(parent.resolve()), sha256=lib.sha(parent.read_bytes())) if parent else None,
        ),
    )
    print("PASS protocol registered before extraction/scoring:", root / "protocol.json", flush=True)


def extract(a, protocol, name, spec, optimization):
    root = a.study.resolve()
    folder = root / "runtime" / (name + "-" + optimization)
    g.require(not folder.exists(), "existing build output refused")
    folder.mkdir(parents=True)
    binary = folder / (name + ".exe")
    execute([a.compiler, "-" + optimization, "-g0", "-Wl,--no-insert-timestamp", root / spec["source"], "-lws2_32", "-o", binary], folder / "compile.log")
    raw = binary.read_bytes()
    offset = struct.unpack_from("<I", raw, 0x3C)[0]
    g.require(raw[offset : offset + 4] == b"PE\0\0", "expected PE")
    architecture = {0x14C: "x86", 0x8664: "x86-64"}.get(struct.unpack_from("<H", raw, offset + 4)[0])
    g.require(architecture is not None, "unsupported compiler target")
    (folder / "projects").mkdir()
    env = os.environ.copy()
    env["JAVA_HOME_OVERRIDE"] = str(a.java_home)
    typed, high = folder / "typed", folder / "high"
    execute(
        [
            a.ghidra_python,
            "-m",
            "pyghidra.ghidra_launch",
            "-D",
            "application.settingsdir=" + str(folder / "settings"),
            "--install-dir",
            a.ghidra,
            "ghidra.app.util.headless.AnalyzeHeadless",
            folder / "projects",
            name,
            "-import",
            binary,
            "-scriptPath",
            ROOT / "ghidra_scripts",
            "-postScript",
            "export_research_graph.py",
            typed,
            "-postScript",
            "export_pcode_evidence.py",
            high,
            "high",
            "subject",
            "equivalent",
            "foil",
        ],
        folder / "ghidra.log",
        env,
    )
    log = (folder / "ghidra.log").read_text(errors="replace")
    g.require("ERROR " not in log and "Traceback (most recent call last)" not in log, "Ghidra error; preserve log and stop")
    graph_path = typed / (binary.name + ".graph.json")
    document = g.load(graph_path)
    digest = lib.sha(raw)
    g.require(document["metadata"]["research_binary_sha256"] == digest, "binary provenance mismatch")
    symbols = g.load(typed / (binary.name + ".symbols.json"))
    index = g.extract(document, a.engine, folder / "seeds")
    records = {r["anchor"]: r for r in index["records"]}
    mapping = {r: records[symbols[r]] for r in ("subject", "equivalent", "foil") if r in symbols and symbols[r] in records}
    coverage = dict(
        build=name + "-" + optimization,
        split=spec["split"],
        binary_sha256=digest,
        architecture=architecture,
        all_seeds=len(records),
        expected_regions=3,
        recovered_regions=len(mapping),
        missing_regions=sorted(set(("subject", "equivalent", "foil")) - mapping.keys()),
        no_seed_symbol_recovered="no_seed" in symbols,
        no_seed_probe_selected=symbols.get("no_seed") in records,
        graph_unresolved_calls=document.get("metadata", {}).get("unresolved_call_count"),
        graph_truncated=document.get("metadata", {}).get("truncated"),
    )
    g.write(folder / "coverage.json", coverage)
    if not mapping:
        return binary, graph_path, [], coverage
    g.write(folder / "context.json", dict(structural=dict(callee_depth=2, caller_depth=1, max_edges=2048, max_evidence_nodes=512, max_function_nodes=64, max_total_nodes=576), max_operational_functions=64, max_operations=10000, max_dependencies=20000))
    g.write(folder / "features.json", dict(max_two_edge_paths=4096))
    g.command(a.operational_engine, "operational-bind", graph_path, high, folder / "bundle.json")
    regions = []
    for region, record in sorted(mapping.items()):
        fp = folder / "seeds" / record["fingerprint"]
        local, canonical, operational = [folder / (region + suffix) for suffix in (".local.json", ".canonical.json", ".op.json")]
        g.command(a.operational_engine, "operational-local", folder / "bundle.json", record["anchor"], folder / "context.json", local)
        g.command(a.operational_engine, "operational-canonical", local, canonical)
        g.command(a.operational_engine, "operational-fingerprint", canonical, folder / "features.json", operational)
        g.require(g.load(local)["structural"] == g.load(fp)["canonical"]["source_document"], "operational structural mismatch")
        regions.append(dict(region=region, fingerprint=fp, operational=operational))
    return binary, graph_path, regions, coverage


def cached(a, name, spec, optimization):
    """Reuse completed static artifacts only after source/seed/binary validation."""
    folder = a.study.resolve() / "runtime" / (name + "-" + optimization)
    binary = folder / (name + ".exe")
    receipt = g.load(folder / "coverage.json")
    graph_path = folder / "typed" / (binary.name + ".graph.json")
    document = g.load(graph_path)
    digest = lib.sha(binary.read_bytes())
    g.require(digest == receipt["binary_sha256"] == document["metadata"]["research_binary_sha256"], "cached binary hash mismatch")
    index = g.load(folder / "seeds/index.json")
    with tempfile.TemporaryDirectory(prefix="osgf-corpus-seed-audit-") as temporary:
        regenerated = g.extract(document, a.engine, Path(temporary) / "seeds")
    g.require(g.encoded(index) == g.encoded(regenerated), "cached seed index differs")
    symbols = g.load(folder / "typed" / (binary.name + ".symbols.json"))
    records = {r["anchor"]: r for r in index["records"]}
    mapping = {r: records[symbols[r]] for r in ("subject", "equivalent", "foil") if r in symbols and symbols[r] in records}
    g.require(receipt["split"] == spec["split"] and receipt["recovered_regions"] == len(mapping) and receipt["missing_regions"] == sorted(set(("subject", "equivalent", "foil")) - mapping.keys()), "cached coverage mismatch")
    regions = []
    for region, record in sorted(mapping.items()):
        fp = folder / "seeds" / record["fingerprint"]
        operational = folder / (region + ".op.json")
        fingerprint = g.load(fp)
        g.operational(g.compare(fingerprint, fingerprint, a.engine), operational, operational, a.operational_engine)
        regions.append(dict(region=region, fingerprint=fp, operational=operational))
    return binary, graph_path, regions, receipt


def run(a):
    root = a.study.resolve()
    protocol = g.load(root / "protocol.json")
    resume = getattr(a, "action", "run") == "resume-available"
    current = pin(a)
    g.require(protocol["schema_version"] == SCHEMA, "unsupported study")
    if resume:
        changed = {k for k in set(current) | set(protocol["implementation"]) if current.get(k) != protocol["implementation"].get(k)}
        g.require(changed <= {str(Path(__file__).resolve())}, "scientific method, source generator or tool changed; resume refused")
        g.write(
            root / "continuation.json",
            dict(
                parent_protocol_sha256=lib.sha((root / "protocol.json").read_bytes()),
                implementation=current,
                changed=sorted(changed),
                amendment="Post-observation availability accounting: preserve missing regions, do not manufacture anchors. Reuse verified completed artifacts; original protocol unchanged. No score or threshold changes.",
            ),
        )
    else:
        g.require(protocol["implementation"] == current, "preregistered implementation/tool changed")
    for spec in protocol["families"].values():
        g.require(lib.sha((root / spec["source"]).read_bytes()) == spec["sha256"], "preregistered source changed")
    library = root / "library"
    if not resume:
        lib.init(library)
    existing = {entry["reference_id"]: entry for entry in lib.validate(library, a.engine, a.operational_engine)}
    cases, coverage, queries = [], [], []
    for name, spec in protocol["families"].items():
        if name in protocol.get("unavailable_families", {}):
            coverage.append(dict(build=name, split=spec["split"], status="unavailable", expected_regions=6, recovered_regions=None, reason=protocol["unavailable_families"][name]))
            print("UNAVAILABLE", name, "- preserved omission; no compilation or score", flush=True)
            continue
        for optimization in ("O0", "O2"):
            folder = root / "runtime" / (name + "-" + optimization)
            binary, graph_path, regions, receipt = cached(a, name, spec, optimization) if resume and folder.exists() else extract(a, protocol, name, spec, optimization)
            coverage.append(receipt)
            for region in regions:
                label = region["region"]
                common = dict(
                    id=name + ":" + optimization + ":" + label,
                    split=spec["split"],
                    source_family=name,
                    near_duplicate_group=name,
                    binary_sha256=receipt["binary_sha256"],
                    operational_artifact=region["operational"].relative_to(root).as_posix(),
                    group=name,
                    compiler=protocol["compiler"],
                    optimization=optimization,
                    annotation_source="protocol.json and source contract; authored before scoring, qualified not externally verified",
                )
                if optimization == "O0":
                    annotation = dict(
                        sample=dict(sha256=receipt["binary_sha256"], executable_format="PE", architecture=receipt["architecture"], source=spec["source"], acquisition_date="2026-11-12", authorization_or_provenance="locally authored benign static-only corpus", family_label_if_known=None),
                        functional_region=dict(
                            region_id=label,
                            analyst_annotation="source-defined region; no similarity-derived labels",
                            described_functionality=spec["contract"] + " Selected region: " + label,
                            annotation_source="protocol.json and " + spec["source"],
                            annotation_status="qualified",
                            annotation_confidence_or_uncertainty="source contract under documented stable OS assumptions; targets never executed; no external analyst validation",
                            classification="benign_reference",
                        ),
                        extraction_tool_version=a.ghidra.name + "; exact engine/exporter hashes in protocol.json",
                        provenance_reference=str(root / "protocol.json"),
                    )
                    fp = g.load(region["fingerprint"])
                    ident = lib.identity(annotation["sample"], annotation["functional_region"], fp, fp["schema_version"])
                    if ident in existing:
                        entry = existing[ident]
                        g.require(
                            entry["sample"] == annotation["sample"]
                            and entry["functional_region"] == annotation["functional_region"]
                            and entry["fingerprint"]["artifact"]["sha256"] == lib.sha(region["fingerprint"].read_bytes())
                            and entry["fingerprint"]["optional_operational_artifact"]["sha256"] == lib.sha(region["operational"].read_bytes()),
                            "cached registration differs",
                        )
                    else:
                        entry = lib.register(library, region["fingerprint"], binary, annotation, a.engine, region["operational"], a.operational_engine)
                    cases.append(dict(**common, query_artifact=None, reference_id=entry["reference_id"]))
                else:
                    cases.append(dict(**common, query_artifact=region["fingerprint"].relative_to(root).as_posix(), reference_id=None))
            if optimization == "O2":
                queries.append((name, graph_path))
            print("PASS extraction", name, optimization, receipt["recovered_regions"], "/3 regions;", receipt["all_seeds"], "automatic seeds", flush=True)
    pairs = []
    for q in cases:
        if q["query_artifact"] is None:
            continue
        for r in cases:
            if r["reference_id"] is None or r["split"] != q["split"]:
                continue
            positive = sources.positive(q["id"].split(":")[-1], r["id"].split(":")[-1])
            pairs.append(dict(query=q["id"], reference=r["id"], positive=positive, hard_negative=not positive, annotation_source="prospective protocol/source contract"))
    dataset = root / "dataset.json"
    g.write(dataset, dict(schema_version=bench.SCHEMA, description="Prospective internal three-lineage benign corpus. Fixed method; discovery-only calibration. No external annotation or malware claim.", cases=cases, pairs=pairs))
    g.write(root / "seed_coverage.json", coverage)
    registration = root / "registration.json"
    bench.preregister(dataset, library, a.engine, registration, a.operational_engine)
    first = bench.run(dataset, library, a.engine, registration, root / "evaluation", a.operational_engine)
    second = bench.run(dataset, library, a.engine, registration, root / "repeat", a.operational_engine)
    g.require(g.encoded(first) == g.encoded(second), "nondeterministic benchmark")
    for name, path in queries:
        lib.workflow(g.load(path), library, a.engine, root / "all-seed-search" / name)
    scored = {condition: {(row["query"], row["reference"]): row["score"] for row in rows} for condition, rows in first["rows"].items()}
    planned = []
    for name, spec in protocol["families"].items():
        for qregion in ("subject", "equivalent", "foil"):
            for rregion in ("subject", "equivalent", "foil"):
                key = (name + ":O2:" + qregion, name + ":O0:" + rregion)
                status = "available" if key in scored["A"] else "unavailable_family" if name in protocol.get("unavailable_families", {}) else "missing_automatic_seed"
                planned.append(dict(query_region=key[0], reference_region=key[1], split=spec["split"], positive=sources.positive(qregion, rregion), status=status, scores={condition: values.get(key) for condition, values in scored.items()}))
    g.write(
        root / "completion.json",
        dict(
            schema_version=SCHEMA,
            protocol_sha256=lib.sha((root / "protocol.json").read_bytes()),
            status="partial_unavailable" if len(pairs) < 27 else "completed",
            expected_pairs=27,
            pairs=len(pairs),
            unavailable_families=protocol.get("unavailable_families", {}),
            deterministic=True,
            seed_coverage=coverage,
            summary=first["summary"],
            planned_pair_accounting=planned,
        ),
    )
    print("PASS available corpus comparisons:", len(pairs), "/ 27 planned pairs, fixed-input deterministic; missing discovery means no thresholds", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "run", "resume-available"))
    for name in ("study", "engine", "operational-engine", "compiler", "ghidra", "ghidra-python", "java-home"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--unavailable-family", choices=tuple(sources.FAMILIES))
    p.add_argument("--unavailable-reason")
    p.add_argument("--parent-protocol", type=Path)
    a = p.parse_args()
    (prepare if a.action == "prepare" else run)(a)


if __name__ == "__main__":
    main()
