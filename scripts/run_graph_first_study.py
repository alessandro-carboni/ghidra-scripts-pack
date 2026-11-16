"""Registered seed-centered study. Static analysis only; never executes targets."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import itertools
import os
from pathlib import Path

try:
    from . import graph_first as g
    from . import graph_first_evaluation as evaluation
    from . import evaluate_operational_baseline as base
except ImportError:
    import graph_first as g
    import graph_first_evaluation as evaluation
    import evaluate_operational_baseline as base

ROOT = base.ROOT


def implementation():
    paths = [
        "scripts/graph_first.py",
        "scripts/graph_first_evaluation.py",
        "scripts/run_graph_first_study.py",
        "scripts/evaluate_operational_baseline.py",
        "scripts/diagnose_baseline_core.py",
        "scripts/recovered_evidence.py",
        "ghidra_scripts/export_research_graph.py",
        "ghidra_scripts/export_report.py",
        "ghidra_scripts/export_pcode_evidence.py",
        "ghidra_scripts/pcode_extraction.py",
        "scripts/pcode_evidence.py",
        "rules/seed_rules.json",
    ]
    return {p: base.sha(ROOT / p) for p in paths}


def register(args):
    args.study.mkdir(parents=True, exist_ok=True)
    g.write(
        args.study / "protocol.json",
        dict(
            schema_version="osgf.graph-first-study/0.1.0",
            implementation=implementation(),
            engine_sha256=base.sha(args.engine),
            operational_engine_sha256=base.sha(args.operational_engine),
            conditions=dict(
                A="frozen three-view equal mean",
                B="three frozen graph views plus co-observations equal mean over comparable views",
                C="unchanged operational-only set Jaccard",
                D="fixed 0.5 B + 0.5 C when both available; otherwise B, explicitly marked",
                E="B top5; reorder only operationally available slots by C descending, B then ID tie-break; missing retains position; graph score unchanged",
            ),
            primary=["B heldout MRR and Recall@1/3/5", "B candidate recall and eligible-query rate"],
            secondary=["ROC AUC", "raw partial ROC AUC [0,0.05]", "graph tie bounds", "discovery-only balanced-accuracy thresholds", "hard-negative/cross-family discrimination", "seed coverage", "missing evidence"],
            candidate_k=[1, 3, 5],
            context=dict(caller_depth=1, callee_depth=2, max_function_nodes=64, max_evidence_nodes=512, max_total_nodes=576, max_edges=2048),
            motif_budget=g.MAX_MOTIFS,
            enumeration_budget=g.MAX_ENUMERATION,
            partition="six new source families, two per split; same split cross-build only",
            truth="Source return-value contract under n<=16 and stable OS allocation availability; same API allocation/free trace; foil toggles return bit0. Never inferred from scores. Region identity maps used only AFTER automatic detection.",
            limitations="Internally authored prospective pilot, not external blind replication; correlated builds; no target execution; no malware-generalization claim",
        ),
    )
    print("REGISTERED", base.sha(args.study / "protocol.json"), flush=True)


def verify(args):
    p = g.load(args.study / "protocol.json")
    expected = p["implementation"]
    previous = base.sha(args.study / "protocol.json")
    for amendment in sorted(args.study.glob("protocol_amendment*.json")):
        a = g.load(amendment)
        g.require(a["original_protocol_sha256"] == base.sha(args.study / "protocol.json"), "amendment binding mismatch")
        g.require(a.get("previous_sha256", previous) == previous, "amendment chain mismatch")
        g.require(a["no_cross_case_scores_inspected"] is True, "invalid pre-evaluation amendment")
        expected = a["implementation"]
        previous = base.sha(amendment)
    g.require(expected == implementation(), "registered implementation changed")
    g.require(p["engine_sha256"] == base.sha(args.engine) and p["operational_engine_sha256"] == base.sha(args.operational_engine), "registered executable changed")
    return p


def run(args):
    protocol = verify(args)
    manifest = g.load(args.study / "manifest.json")
    validate_manifest(manifest)
    g.require(manifest["protocol_sha256"] == base.sha(args.study / "protocol.json"), "protocol binding changed")
    for source in manifest["sources"]:
        g.require(base.sha(ROOT / source["path"]) == source["sha256"], "source hash changed")
    work = args.study / "runtime/evaluation-001"
    g.require(not work.exists(), "fresh evaluation required")
    work.mkdir(parents=True)
    env = dict(os.environ, JAVA_HOME_OVERRIDE=str(args.java_home))
    names = ["subject", "subject_equivalent", "foil", "effect_helper", "compute", "compute_equivalent", "unresolved_probe"]

    def extract(build):
        directory = work / build["id"]
        directory.mkdir()
        (directory / "projects").mkdir()
        binary = ROOT / build["path"]
        g.require(base.sha(binary) == build["sha256"], "binary changed")
        typed, high = directory / "typed", directory / "high"
        cmd = [
            args.python,
            "-m",
            "pyghidra.ghidra_launch",
            "-D",
            "application.settingsdir=" + str(directory / "settings"),
            "--install-dir",
            args.ghidra,
            "ghidra.app.util.headless.AnalyzeHeadless",
            directory / "projects",
            build["id"],
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
            *names,
        ]
        receipt = base.command(cmd, directory / "ghidra.log", env, 480)
        log = (directory / "ghidra.log").read_text(errors="replace")
        g.require("ERROR " not in log and "Traceback (most recent call last)" not in log, "Ghidra extraction failed")
        graph = g.load(typed / (binary.name + ".graph.json"))
        symbols = g.load(typed / (binary.name + ".symbols.json"))
        index = g.extract(graph, args.engine, directory / "seeded")
        # Ground truth mapping is downstream of the unchanged detector.
        expected = dict(subject=["subject"], subject_equivalent=["subject_equivalent", "effect_helper"], foil=["foil"])
        records = {r["anchor"]: r for r in index["records"]}
        g.write(directory / "context.json", dict(structural=protocol["context"], max_operational_functions=64, max_operations=10000, max_dependencies=20000))
        g.write(directory / "features.json", dict(max_two_edge_paths=4096))
        g.command(args.operational_engine, "operational-bind", typed / (binary.name + ".graph.json"), high, directory / "bundle.json")
        cases = []
        for region, members in expected.items():
            anchors = sorted({symbols[n] for n in members if n in symbols} & records.keys())
            # All qualifying seeds retained, no score-based seed selection.
            for anchor in anchors:
                record = records[anchor]
                fp = directory / "seeded" / record["fingerprint"]
                ident = build["id"] + ":" + region + ":" + anchor
                stem = "op-" + record["fingerprint"].removesuffix(".json")
                local, canonical, op = [directory / (stem + suffix) for suffix in (".local.json", ".canonical.json", ".fp.json")]
                g.command(args.operational_engine, "operational-local", directory / "bundle.json", anchor, directory / "context.json", local)
                g.command(args.operational_engine, "operational-canonical", local, canonical)
                g.command(args.operational_engine, "operational-fingerprint", canonical, directory / "features.json", op)
                # Bound to the exact same selected structural region.
                g.require(g.load(local)["structural"] == g.load(fp)["canonical"]["source_document"], "graph/operational context mismatch")
                cases.append(dict(id=ident, region=region, family=build["family"], split=build["split"], build=build["id"], compiler=build["compiler"], optimization=build["optimization"], semantic_class=build["family"] + (":foil" if region == "foil" else ":subject"), fingerprint=str(fp), operational=str(op)))
        coverage = dict(
            build=build["id"],
            all_detected_seeds=len(records),
            expected_regions=3,
            recovered_regions=len({c["region"] for c in cases}),
            no_seed_probe_selected=symbols["no_seed"] in records if "no_seed" in symbols else None,
            no_seed_probe_symbol_recovered="no_seed" in symbols,
            unresolved_probe_selected=symbols.get("unresolved_probe") in records,
            missing_regions=sorted(set(expected) - {c["region"] for c in cases}),
            seed_manifest=index["seed_manifest"],
        )
        print("PASS automatic seed extraction", build["id"], coverage["recovered_regions"], "/ 3 regions; all seeds", len(records), flush=True)
        return cases, coverage, receipt

    cases, coverage, receipts = [], [], []
    with ThreadPoolExecutor(max_workers=3) as pool:
        for cs, cov, receipt in pool.map(extract, manifest["builds"]):
            cases.extend(cs)
            coverage.append(cov)
            receipts.append(receipt)
    cases.sort(key=lambda c: c["id"])
    fps = {c["id"]: g.load(c["fingerprint"]) for c in cases}
    pairs = {c: [] for c in evaluation.CONDITIONS}
    (work / "pairs").mkdir()
    count = 0
    for q, r in itertools.combinations(cases, 2):
        if q["split"] != r["split"] or q["build"] == r["build"]:
            continue
        path = work / "pairs" / str(count)
        # Authoritative legacy validation happens for every comparison.
        comparison = g.compare(fps[q["id"]], fps[r["id"]], args.engine)
        repeated = g.compare(fps[q["id"]], fps[r["id"]], args.engine)
        g.require(g.encoded(comparison) == g.encoded(repeated), "graph result nondeterministic")
        op_paths = [Path(str(path) + suffix) for suffix in (".op.json", ".repeat.json")]
        for p in op_paths:
            g.command(args.operational_engine, "operational-compare", q["operational"], r["operational"], p)
        g.require(op_paths[0].read_bytes() == op_paths[1].read_bytes(), "operational result nondeterministic")
        op = g.load(op_paths[0])
        a = comparison["baseline_comparison"]["aggregate_set_similarity"]
        b = comparison["graph_similarity"]["set_similarity"]
        c = op["operational"]["set_similarity"]
        scores = dict(A=a, B=b, C=c, D=(b + c) / 2 if b is not None and c is not None else b, E=b)
        g.write(Path(str(path) + ".graph.json"), comparison)
        for condition, score in scores.items():
            for query, reference in ((q, r), (r, q)):
                pairs[condition].append(
                    dict(
                        query=query["id"],
                        reference=reference["id"],
                        split=q["split"],
                        positive=q["semantic_class"] == r["semantic_class"],
                        same_family=q["family"] == r["family"],
                        score=score,
                        graph=b,
                        operational=c,
                        operational_support=op["operational"]["query_support"],
                        combined_fallback=c is None,
                        cross_compiler=q["compiler"] != r["compiler"],
                        cross_optimization=q["optimization"] != r["optimization"],
                    )
                )
        count += 1
        if count % 25 == 0:
            print("PASS deterministic pairs", count, flush=True)
    verify(args)
    report = dict(
        schema_version="osgf.graph-first-study-result/0.1.0",
        status="PASS",
        protocol_sha256=base.sha(args.study / "protocol.json"),
        protocol_amendments={p.name: base.sha(p) for p in sorted(args.study.glob("protocol_amendment*.json"))},
        manifest_sha256=base.sha(args.study / "manifest.json"),
        cases=cases,
        coverage=coverage,
        receipts=receipts,
        pairs=pairs,
        summary=evaluation.summarize(pairs),
        unordered_pairs=count,
        deterministic=True,
        no_target_execution=True,
        limitations=protocol["limitations"],
        pair_count_interpretation="Each unordered comparison supplies two directed retrieval rows; these are not independent samples",
    )
    g.write(args.study / "results.json", report)
    for condition in evaluation.CONDITIONS:
        s = report["summary"][condition]["splits"]["heldout"]
        print(condition, "HELDOUT", "MRR", s["retrieval"]["mrr"], "ROC", s["continuous"]["auc"], "classification", s["classification"], flush=True)


def validate_manifest(manifest):
    """A partially compiled study must not masquerade as a complete evaluation."""
    sources = {s["family"]: s for s in manifest["sources"]}
    g.require(len(sources) == len(manifest["sources"]) == 6, "six unique source families required")
    g.require(all(sum(s["split"] == split for s in sources.values()) == 2 for split in ("discovery", "validation", "heldout")), "two source families per split required")
    expected = {(f, c, o) for f in sources for c, o in (("gcc", "O0"), ("gcc", "O2"), ("msvc", "O0"))}
    builds = manifest["builds"]
    actual = {(b["family"], b["compiler"], b["optimization"]) for b in builds}
    g.require(actual == expected and len(builds) == len(expected), "incomplete build matrix: all 18 registered builds required; do not omit quarantined/unavailable samples")
    for build in builds:
        source = sources[build["family"]]
        g.require(build["source_sha256"] == source["sha256"] and build["split"] == source["split"], "build source/split mismatch")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("register", "run"))
    p.add_argument("--study", type=Path, required=True)
    p.add_argument("--engine", type=Path, required=True)
    p.add_argument("--operational-engine", type=Path, required=True)
    p.add_argument("--ghidra", type=Path)
    p.add_argument("--python", type=Path)
    p.add_argument("--java-home", type=Path)
    args = p.parse_args()
    args.study = args.study.resolve()
    register(args) if args.action == "register" else run(args)
