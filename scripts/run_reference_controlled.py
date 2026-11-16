"""Benign static-only pilot. Builds two variants; never executes the target binaries."""

import argparse
import os
from pathlib import Path
import subprocess
import struct

try:
    from . import graph_first as graph
    from . import reference_library as lib
    from . import reference_benchmark as bench
    from .controlled_corpus import compiler_inventory
except ImportError:
    import graph_first as graph
    import reference_library as lib
    import reference_benchmark as bench
    from controlled_corpus import compiler_inventory

SOURCE = r"""#include <windows.h>
#if defined(_MSC_VER)
#define KEEP __declspec(dllexport) __declspec(noinline)
#else
#define KEEP __attribute__((noinline))
#endif
/* Benign static-analysis fixture: resolve public library exports, never call them. */
#ifdef INDIRECT_LAYOUT
KEEP FARPROC subject_effect(HMODULE module) {
    return GetProcAddress(module, "GetCurrentProcessId");
}
KEEP FARPROC subject(HMODULE module) { return subject_effect(module); }
#else
KEEP FARPROC subject(HMODULE module) {
    return GetProcAddress(module, "GetCurrentProcessId");
}
#endif
KEEP FARPROC equivalent(HMODULE module) {
    FARPROC result = GetProcAddress(module, "GetCurrentProcessId");
    return result;
}
KEEP FARPROC foil(HMODULE module) {
    return GetProcAddress(module, "GetTickCount");
}
KEEP unsigned no_seed(unsigned x) { return x + 3u; }
int main(void) {
    HMODULE module = GetModuleHandleA("kernel32.dll");
    volatile FARPROC a = subject(module), b = equivalent(module), c = foil(module);
    return (a == b) + (c != 0) + (int)no_seed(1u);
}
"""


def execute(command, log, env=None):
    with Path(log).open("xb") as stream:
        result = subprocess.run([str(v) for v in command], stdout=stream, stderr=subprocess.STDOUT, env=env, timeout=600, check=False)
    graph.require(result.returncode == 0, "command failed; inspect " + str(log))
    print("PASS", " ".join(str(v) for v in command), flush=True)


def run(a):
    work = a.output.resolve()
    graph.require(not work.exists(), "new pilot output required")
    work.mkdir(parents=True)
    source = work / "benign_library_lookup.c"
    source.write_text(SOURCE, encoding="utf-8", newline="\n")
    graph.write(
        work / "design.json",
        dict(
            schema_version="osgf.controlled-reference-pilot/0.1.0",
            source_sha256=lib.sha(source.read_bytes()),
            purpose="development pilot, no independent heldout generalization",
            oracle="subject and equivalent resolve GetCurrentProcessId; foil resolves GetTickCount; labels declared before extraction/scoring",
            split="discovery only; shared source family must not cross partitions",
            safety="benign public symbol lookup; target binaries are never executed",
            optimizations=["O0", "O2"],
            compiler=str(a.compiler),
        ),
    )
    library = work / "library"
    lib.init(library)
    cases, coverage = [], []
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["JAVA_HOME_OVERRIDE"] = str(a.java_home)
    msvc = None
    if a.query_msvc:
        compilers, unavailable = compiler_inventory()
        msvc = next((c for c in compilers if c["compiler"] == "msvc"), None)
        graph.require(msvc is not None, "MSVC unavailable: " + str(unavailable))
    for optimization, role in [("O0", "reference"), ("O2", "query")]:
        folder = work / optimization
        folder.mkdir()
        binary = folder / "benign_library_lookup.exe"
        compiler_name = str(a.compiler)
        if role == "query" and msvc:
            compiler_name = msvc["path"]
            execute([msvc["path"], "/nologo", "/O2", "/Brepro", *(["/DINDIRECT_LAYOUT"] if a.query_helper else []), source, "/Fe" + str(binary), "/Fo" + str(folder / "lookup.obj"), "/link", "/INCREMENTAL:NO", "/OPT:NOICF", "kernel32.lib"], folder / "compile.log", msvc["env"])
        else:
            execute([a.compiler, "-" + optimization, "-g0", *(["-DINDIRECT_LAYOUT"] if role == "query" and a.query_helper else []), source, "-o", binary], folder / "compile.log")
        binary_bytes = binary.read_bytes()
        binary_hash = lib.sha(binary_bytes)
        pe_offset = struct.unpack_from("<I", binary_bytes, 0x3C)[0]
        graph.require(binary_bytes[pe_offset : pe_offset + 4] == b"PE\0\0", "expected PE compiler output")
        machine = struct.unpack_from("<H", binary_bytes, pe_offset + 4)[0]
        architecture = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(machine)
        graph.require(architecture is not None, "unrecognized PE architecture")
        (folder / "projects").mkdir()
        typed = folder / "typed"
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
                "reference-pilot",
                "-import",
                binary,
                "-scriptPath",
                repo / "ghidra_scripts",
                "-postScript",
                "export_research_graph.py",
                typed,
            ]
            + (["-postScript", "export_pcode_evidence.py", folder / "high", "high", "subject", "equivalent", "foil", *(["subject_effect"] if role == "query" and a.query_helper else [])] if a.operational_engine else []),
            folder / "ghidra.log",
            env,
        )
        log = (folder / "ghidra.log").read_text(errors="replace")
        graph.require("ERROR " not in log and "Traceback (most recent call last)" not in log, "Ghidra extraction error")
        document = graph.load(typed / (binary.name + ".graph.json"))
        graph.require(document["metadata"]["research_binary_sha256"] == binary_hash, "extraction byte provenance mismatch")
        symbols = graph.load(typed / (binary.name + ".symbols.json"))
        index = graph.extract(document, a.engine, folder / "seeds")
        records = {r["anchor"]: r for r in index["records"]}
        region_symbols = {name: ("subject_effect" if name == "subject" and role == "query" and a.query_helper else name) for name in ("subject", "equivalent", "foil")}
        selected = {name: records[symbols[symbol]] for name, symbol in region_symbols.items() if symbol in symbols and symbols[symbol] in records}
        coverage.append(
            dict(
                build=optimization,
                all_seeds=len(records),
                expected_regions=3,
                recovered_regions=len(selected),
                missing_regions=sorted(set(("subject", "equivalent", "foil")) - selected.keys()),
                unannotated_seeds=len(records) - len({r["seed_id"] for r in selected.values()}),
                no_seed_symbol_recovered="no_seed" in symbols,
                no_seed_probe_selected=symbols.get("no_seed") in records,
            )
        )
        if a.operational_engine:
            graph.write(folder / "context.json", dict(structural=dict(callee_depth=2, caller_depth=1, max_edges=2048, max_evidence_nodes=512, max_function_nodes=64, max_total_nodes=576), max_operational_functions=64, max_operations=10000, max_dependencies=20000))
            graph.write(folder / "features.json", dict(max_two_edge_paths=4096))
            graph.command(a.operational_engine, "operational-bind", typed / (binary.name + ".graph.json"), folder / "high", folder / "bundle.json")
        for name, record in sorted(selected.items()):
            artifact = folder / "seeds" / record["fingerprint"]
            operational = None
            if a.operational_engine:
                local, canonical, operational = [folder / (name + suffix) for suffix in (".local.json", ".canonical.json", ".op.json")]
                graph.command(a.operational_engine, "operational-local", folder / "bundle.json", record["anchor"], folder / "context.json", local)
                graph.command(a.operational_engine, "operational-canonical", local, canonical)
                graph.command(a.operational_engine, "operational-fingerprint", canonical, folder / "features.json", operational)
                graph.require(graph.load(local)["structural"] == graph.load(artifact)["canonical"]["source_document"], "operational context mismatch")
            common = dict(
                id=optimization + ":" + name,
                split="discovery",
                source_family="benign-library-lookup-pilot",
                near_duplicate_group="benign-library-lookup-pilot",
                binary_sha256=binary_hash,
                operational_artifact=operational.relative_to(work).as_posix() if operational else None,
                group="dynamic-public-symbol-lookup",
                compiler=compiler_name,
                optimization=optimization,
                annotation_source="design.json and benign_library_lookup.c; source contract, not inferred from scores",
            )
            if role == "reference":
                annotation = dict(
                    sample=dict(sha256=binary_hash, executable_format="PE", architecture=architecture, source="locally compiled benign_library_lookup.c", acquisition_date="2026-11-12", authorization_or_provenance="locally authored benign static-only pilot", family_label_if_known=None),
                    functional_region=dict(
                        region_id=name,
                        analyst_annotation="source-defined public symbol resolution",
                        described_functionality="resolve " + ("GetTickCount" if name == "foil" else "GetCurrentProcessId"),
                        annotation_source="design.json and source, before scoring",
                        annotation_status="qualified",
                        annotation_confidence_or_uncertainty="source-level oracle; compiler and extraction effects measured, not presumed",
                        classification="benign_reference",
                    ),
                    extraction_tool_version=f"{a.ghidra.name}; exporter SHA-256 {lib.sha((repo / 'ghidra_scripts/export_research_graph.py').read_bytes())}; Rust engine SHA-256 {lib.sha(a.engine.read_bytes())}",
                    provenance_reference=str(work / "design.json"),
                )
                entry = lib.register(library, artifact, binary, annotation, a.engine, operational, a.operational_engine)
                cases.append(dict(**common, reference_id=entry["reference_id"], query_artifact=None))
            else:
                cases.append(dict(**common, reference_id=None, query_artifact=artifact.relative_to(work).as_posix()))
        # Search every detected seed, including unannotated ones; labels do not select extraction.
        if role == "query":
            lib.workflow(document, library, a.engine, folder / "all-seed-search")
    pairs = []
    for q in cases:
        if q["query_artifact"] is None:
            continue
        for r in cases:
            if r["reference_id"] is None:
                continue
            positive = (q["id"].endswith(":foil")) == (r["id"].endswith(":foil"))
            pairs.append(dict(query=q["id"], reference=r["id"], positive=positive, hard_negative=not positive, annotation_source="preregistered source symbol-resolution contract"))
    graph.require(pairs, "no annotated cross-build pairs recovered")
    graph.write(work / "seed_coverage.json", coverage)
    dataset = work / "dataset.json"
    graph.write(dataset, dict(schema_version=bench.SCHEMA, description="Benign actual-binary development pilot. Same-source compiler optimization transfer only; no heldout or malware claims.", cases=cases, pairs=pairs))
    registration = work / "registration.json"
    bench.preregister(dataset, library, a.engine, registration, a.operational_engine)
    first = bench.run(dataset, library, a.engine, registration, work / "evaluation", a.operational_engine)
    second = bench.run(dataset, library, a.engine, registration, work / "repeat", a.operational_engine)
    graph.require(graph.encoded(first) == graph.encoded(second), "benchmark rerun differs")
    graph.write(work / "completion.json", dict(deterministic=True, pair_count=len(pairs), seed_coverage=coverage, summary=first["summary"]))
    print("PASS deterministic real-binary pilot", len(pairs), "pairs", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "engine", "compiler", "ghidra", "ghidra-python", "java-home"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--query-helper", action="store_true", help="move subject observation into a separate query callee")
    p.add_argument("--query-msvc", action="store_true", help="use installed MSVC for query build; GCC reference unchanged")
    p.add_argument("--operational-engine", type=Path)
    run(p.parse_args())


if __name__ == "__main__":
    main()
