"""Isolated real-binary and graph-level causal probes; no frozen inputs are modified."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

try:
    from . import diagnose_baseline_core as d
    from . import transformation_extraction as extraction
except ImportError:
    import diagnose_baseline_core as d
    import transformation_extraction as extraction

WORK = d.OUT / "runtime/micro"
ENGINE = d.admitted.pairs.catalog.ENGINE
SOURCE = r"""#include <stdio.h>
#define EX __declspec(dllexport) __attribute__((noinline))
EX unsigned arithmetic_add(unsigned x) { return x + 7u; }
EX unsigned arithmetic_xor(unsigned x) { return x ^ 7u; }
EX unsigned predicate_lt(unsigned x) { if (x < 7u) return 11u; return 19u; }
EX unsigned predicate_gt(unsigned x) { if (x > 7u) return 11u; return 19u; }
EX unsigned helper(unsigned x) { return x + 7u; }
EX unsigned wrapped(unsigned x) { return helper(x); }
EX unsigned constant7(unsigned x) { return x + 7u; }
EX unsigned constant9(unsigned x) { return x + 9u; }
int main(void) {
  unsigned x;
  for (x=0; x<256; ++x) printf("%u %u %u %u %u %u %u %u %u\n", x,
    arithmetic_add(x), arithmetic_xor(x), predicate_lt(x), predicate_gt(x),
    helper(x), wrapped(x), constant7(x), constant9(x));
  return 0;
}
"""


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args, timeout=180):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f"command failed {args[1:3]}: {result.stderr.decode(errors='replace')[-2500:]}")
    return result.stdout


def recount(local):
    functions = sum(n["type"] == "FUNCTION" for n in local["nodes"])
    local["truncation"]["counts"] = dict(function_nodes=functions, evidence_nodes=len(local["nodes"]) - functions, total_nodes=len(local["nodes"]), edges=len(local["edges"]), unresolved_calls=len(local["unresolved_calls"]))


def extract(local, condition, limits=()):
    lp = WORK / "local.json"
    lp.write_bytes(d.admitted.serialize(local))
    raw = run([d.admitted.pairs.catalog.executable(), "extract", condition, lp, *limits])
    assert raw == run([d.admitted.pairs.catalog.executable(), "extract", condition, lp, *limits])
    bundle = json.loads(raw)
    bp = WORK / "checked_bundle.json"
    bp.write_bytes(raw)
    run([d.admitted.pairs.catalog.executable(), "validate", bp])
    # B must also agree with the production fingerprint and source provenance.
    if condition == "B":
        cp, fp = WORK / "check.canonical.json", WORK / "check.fp.json"
        run([ENGINE, "canonicalize-local-subgraph", lp, cp])
        flags = ["--max-topology-motifs", limits[0], "--max-interaction-motifs", limits[1]] if limits else []
        run([ENGINE, "fingerprint-canonical", cp, fp, *flags])
        frozen = json.loads(fp.read_bytes())
        for key in [v + "_view" for v in d.VIEWS] + ["provenance_index", "motif_truncation", "observability_view"]:
            assert frozen[key] == bundle["fingerprint"][key]
    return bundle


def compare(q, r):
    qp, rp = WORK / "q.json", WORK / "r.json"
    qp.write_bytes(d.admitted.serialize(q))
    rp.write_bytes(d.admitted.serialize(r))
    args = [d.admitted.pairs.catalog.executable(), "compare", qp, rp]
    raw = run(args)
    assert raw == run(args)
    result = json.loads(raw)
    views = {v: d.jaccard(q["fingerprint"][v + "_view"], r["fingerprint"][v + "_view"]) for v in d.VIEWS}
    for v in views:
        assert views[v]["multiset_similarity"] == result[v]["multiset_similarity"]
    return dict(score=result["aggregate_multiset_similarity"], set_score=result["aggregate_set_similarity"], views=views, warnings=result["observability_warnings"], result_sha256=hashlib.sha256(raw).hexdigest(), deterministic=True)


def graph_experiments():
    local = json.loads((d.ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json").read_bytes())
    cases = []
    for name in ("api_decorated_alias", "constant_annotation", "section_role", "value_merging", "edge_context_alias", "distinct_constant", "api_A_W_not_alias", "api_Nt_Zw_not_alias", "missing_observability"):
        left, right = copy.deepcopy(local), copy.deepcopy(local)
        if name == "api_decorated_alias":
            next(n for n in right["nodes"] if n.get("normalized_name") == "WriteProcessMemory")["name"] = "KERNEL32.dll!__imp__WriteProcessMemory@20"
        elif name == "constant_annotation":
            next(n for n in right["nodes"] if n["type"] == "CONSTANT")["symbolic_names"].append("UNSUPPORTED_ALIAS")
        elif name == "section_role":
            next(n for n in right["nodes"] if n["type"] == "SECTION")["name"] = ".text"
        elif name == "value_merging":
            node = next(n for n in right["nodes"] if n.get("normalized_name") == "WriteProcessMemory")
            twin = copy.deepcopy(node)
            twin.update(id="api:twin", name="KERNEL32.dll!__imp__WriteProcessMemory@20")
            right["nodes"].append(twin)
            edge = next(e for e in right["edges"] if e["target"] == node["id"])
            duplicate = copy.deepcopy(edge)
            duplicate.update(target="api:twin", occurrences=1)
            right["edges"].append(duplicate)
            next(e for e in left["edges"] if e["target"] == node["id"])["occurrences"] = 2
            recount(right)
        elif name == "edge_context_alias":
            next(e for e in right["edges"] if e["type"] == "uses_constant")["context_apis"] = ["kernel32.dll!__imp__VirtualAlloc@16"]
        elif name == "distinct_constant":
            next(n for n in right["nodes"] if n["type"] == "CONSTANT")["value"] = 65
        elif name.startswith("api_"):
            names = ("CreateFileA", "CreateFileW") if name == "api_A_W_not_alias" else ("NtOpenFile", "ZwOpenFile")
            for graph, api in zip((left, right), names):
                next(n for n in graph["nodes"] if n["type"] == "API")["name"] = api
        comparisons = {}
        for condition in ("A", "B"):
            q = extract(left, condition)
            r = extract(right, condition, (0, 0) if name == "missing_observability" else ())
            comparisons[condition] = compare(q, r)
            comparisons[condition]["canonical_edges_equal"] = q["graph"]["edges"] == r["graph"]["edges"]
            comparisons[condition]["canonical_node_count"] = [len(q["graph"]["nodes"]), len(r["graph"]["nodes"])]
        if name in ("api_decorated_alias", "constant_annotation", "section_role"):
            assert comparisons["A"]["score"] < 1 and comparisons["B"]["score"] == 1
        elif name == "edge_context_alias":
            assert not comparisons["A"]["canonical_edges_equal"] and comparisons["B"]["canonical_edges_equal"]
            assert comparisons["A"]["score"] == comparisons["B"]["score"] == 1
        elif name in ("distinct_constant", "api_A_W_not_alias", "api_Nt_Zw_not_alias"):
            assert comparisons["B"]["score"] < 1
        cases.append(dict(case_id=name, scope="GRAPH_SYNTHETIC; no binary behavioral equivalence claim", source_fixture="rust_engine/tests/fixtures/canonical_local_v0_1.json", source_sha256=sha(d.ROOT / "rust_engine/tests/fixtures/canonical_local_v0_1.json"), comparisons=comparisons))
        print("GRAPH PROBE", name, {c: v["score"] for c, v in comparisons.items()}, flush=True)
    d.dump("MICRO_GRAPH_EXPERIMENTS.json", cases)


def real_experiments(ghidra):
    source, binary = WORK / "micro.c", WORK / "micro.exe"
    source.write_bytes(SOURCE.encode())
    command = ["gcc", "-O0", "-fno-inline", "-fno-ipa-icf", "-Wl,--no-insert-timestamp", str(source), "-o", str(binary)]
    run(command)
    rows = [list(map(int, line.split())) for line in run([binary]).decode().splitlines()]
    assert len(rows) == 256
    for x, add, xor, lt, gt, helper, wrapped, c7, c9 in rows:
        assert [add, xor, lt, gt, helper, wrapped, c7, c9] == [x + 7, x ^ 7, 11 if x < 7 else 19, 11 if x > 7 else 19, x + 7, x + 7, x + 7, x + 9]
    raw, projects = WORK / "raw", WORK / "projects"
    projects.mkdir(exist_ok=True)
    launcher = Path(ghidra) / "support/pyghidraRun.bat"
    cmd = [launcher, "-H", projects, "Step10A", "-import", binary, "-overwrite", "-scriptPath", d.ROOT / "ghidra_scripts", "-postScript", "export_research_graph.py", raw]
    print("REAL GHIDRA micro extraction", flush=True)
    output = run(cmd, timeout=600)
    (WORK / "ghidra.log").write_bytes(output)
    typed = raw / "micro.exe.graph.json"
    document = extraction.validate_export(json.loads(typed.read_bytes()), sha(binary))
    symbols = json.loads((raw / "micro.exe.symbols.json").read_bytes())
    cases = []
    for name, left, right, columns in [("arithmetic", "arithmetic_add", "arithmetic_xor", (1, 2)), ("predicate", "predicate_lt", "predicate_gt", (3, 4)), ("layout", "helper", "wrapped", (5, 6)), ("constant", "constant7", "constant9", (7, 8))]:
        bundles, evidence = [], []
        for symbol in (left, right):
            anchor = extraction.select_anchor(document, symbols, symbol)
            cp = WORK / (symbol + ".canonical.json")
            canonical = extraction.canonicalize(ENGINE, typed, anchor, cp)
            bundles.append(extract(canonical["source_document"], "B"))
            evidence.append(dict(symbol=symbol, anchor=anchor, canonical_path=cp.relative_to(d.ROOT).as_posix(), canonical_sha256=sha(cp), nodes=canonical["nodes"], edges=canonical["edges"], source_nodes=canonical["source_document"]["nodes"]))
        witnesses = [dict(input=r[0], left=r[columns[0]], right=r[columns[1]]) for r in rows if r[columns[0]] != r[columns[1]]]
        cases.append(
            dict(
                case_id=name,
                scope="REAL GCC O0 binary and fresh Ghidra extraction; same-PE controlled anchors",
                tested_inputs=256,
                semantic_relation="equivalent_unsigned32" if name == "layout" else "non_equivalent",
                witness=witnesses[0] if witnesses else None,
                mismatch_count=len(witnesses),
                evidence=evidence,
                comparison=compare(*bundles),
            )
        )
        print("REAL PROBE", name, cases[-1]["comparison"]["score"], "witness", cases[-1]["witness"], flush=True)
    version = (Path(ghidra) / "Ghidra/application.properties").read_text()
    d.dump(
        "MICRO_REAL_EXPERIMENTS.json",
        dict(
            cases=cases,
            source=SOURCE,
            source_sha256=sha(source),
            binary_sha256=sha(binary),
            typed_sha256=sha(typed),
            compiler=run(["gcc", "--version"]).decode().splitlines()[0],
            compiler_flags=command[1:5],
            ghidra_version=next(line for line in version.splitlines() if line.startswith("application.version=")),
            commands=["gcc -O0 -fno-inline -fno-ipa-icf -Wl,--no-insert-timestamp $work/micro.c -o $work/micro.exe", "$work/micro.exe", "& $ghidra/support/pyghidraRun.bat -H $work/projects Step10A -import $work/micro.exe -overwrite -scriptPath ghidra_scripts -postScript export_research_graph.py $work/raw"],
            exit_codes=[0, 0, 0],
        ),
    )


def step9():
    path = d.ROOT / "datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9/manifest.json"
    bundle = json.loads(path.read_bytes())
    for relative, digest in bundle["runs"][0]["artifact_hashes"].items():
        assert sha(d.ROOT / relative) == digest, relative
    extraction.verify_graphs(bundle, ENGINE)
    specs = {s["transformation_id"]: s for s in bundle["specifications"]}
    executions = {e["execution_id"]: e for e in bundle["executions"]}
    cases = []
    for build in sorted(bundle["builds"], key=lambda b: b["build_id"]):
        graphs = sorted([g for g in bundle["graphs"] if g["build_id"] == build["build_id"]], key=lambda g: g["canonical_graph_reference"])
        assert len(graphs) == 2
        fps = [extract(json.loads((d.ROOT / g["canonical_graph_reference"]).read_bytes())["source_document"], "B") for g in graphs]
        family = specs[executions[build["execution_id"]]["transformation_id"]]["transformation_family"]
        cases.append(dict(family=family, build_id=build["build_id"], graphs=graphs, comparison=compare(*fps), behavior=[b for b in bundle["behaviors"] if b["build_id"] == build["build_id"]]))
        print("STEP9 SUPPLEMENT", family, cases[-1]["comparison"]["score"], flush=True)
    d.dump("STEP9_SUPPLEMENT.json", dict(manifest_path=path.relative_to(d.ROOT).as_posix(), manifest_sha256=sha(path), scope="Six GCC O0 builds, twelve anchors; original/transformed share PE; supplementary, not held-out", cases=cases))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-dir", type=Path)
    parser.add_argument("--graph", action="store_true")
    parser.add_argument("--step9", action="store_true")
    args = parser.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    if args.graph:
        graph_experiments()
    if args.step9:
        step9()
    if args.ghidra_dir:
        raise SystemExit("NOT RUN: real micro.exe triggered host antivirus on 2026-10-27; review detection before any new execution. No security exclusions are configured by this script.")
