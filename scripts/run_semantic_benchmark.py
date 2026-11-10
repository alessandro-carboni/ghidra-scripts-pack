"""Prospective internally authored benchmark; fixed method and low-FPR discovery calibration."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import itertools
import json
import os
from pathlib import Path

try:
    from . import evaluate_operational_baseline as base
    from . import semantic_flow as semantic
    from .evaluate_value_flow import auc
    from .pcode_evidence import serialize
    from .recovered_evidence import encoded
except ImportError:
    import evaluate_operational_baseline as base
    import semantic_flow as semantic
    from evaluate_value_flow import auc
    from pcode_evidence import serialize
    from recovered_evidence import encoded

CONDITIONS = ("exact", "multilevel", "physical", "parameters", "effects", "algebra", "families", "combined")


def implementation():
    paths = [
        "scripts/recovered_evidence.py",
        "scripts/semantic_flow.py",
        "scripts/pcode_evidence.py",
        "scripts/evaluate_operational_baseline.py",
        "scripts/evaluate_value_flow.py",
        "scripts/run_semantic_benchmark.py",
        "ghidra_scripts/recovered_extraction.py",
        "ghidra_scripts/export_recovered_evidence.py",
        "ghidra_scripts/pcode_extraction.py",
        "ghidra_scripts/export_research_graph.py",
    ]
    return {p: base.sha(base.ROOT / p) for p in paths}


def register(args):
    args.study.mkdir(parents=True, exist_ok=True)
    path = args.study / "method.json"
    base.require(not path.exists(), "method already registered")
    base.save(
        path,
        dict(
            schema_version="osgf.semantic-study/0.1.0",
            implementation=implementation(),
            engine_sha256=base.sha(args.engine),
            conditions=list(CONDITIONS),
            primary="combined",
            combined_weights=dict(multilevel=0.5, algebra=0.5),
            max_discovery_fpr=0.05,
            policy="New source families authored after method lock; internal prospective study, not external blinded validation; no test-driven tuning",
        ),
    )
    print("METHOD LOCKED", base.sha(path), flush=True)


def verify(args):
    method = json.loads((args.study / "method.json").read_bytes())
    base.require(method["implementation"] == implementation() and method["engine_sha256"] == base.sha(args.engine), "method/executable changed")
    base.require(method["conditions"] == list(CONDITIONS) and method["primary"] == "combined" and method["max_discovery_fpr"] == 0.05 and method["combined_weights"] == dict(multilevel=0.5, algebra=0.5), "registered policy changed")
    return method


def low_fpr_threshold(rows, limit=0.05):
    usable = [r for r in rows if r["score"] is not None]
    base.require(any(r["positive"] for r in usable) and any(not r["positive"] for r in usable), "discovery needs both classes")
    candidates = sorted({1.0000000000000002, *(r["score"] for r in usable)})
    candidates = [t for t in candidates if base.metrics(rows, t)["fpr"] <= limit]
    return max(candidates, key=lambda t: (base.metrics(rows, t)["tpr"], -base.metrics(rows, t)["fpr"], t))


def evaluate(args):
    method = verify(args)
    manifest_path = args.study / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    base.require(manifest["method_sha256"] == base.sha(args.study / "method.json"), "manifest method mismatch")
    families = {s["family"]: s["split"] for s in manifest["sources"]}
    base.require(len(families) == len(manifest["sources"]) and all(sum(v == split for v in families.values()) >= 2 for split in ("discovery", "validation", "heldout")), "need multiple independent source families per split")
    for source in manifest["sources"]:
        base.require(base.sha(base.ROOT / source["path"]) == source["sha256"], "source changed")
    work = args.study / "runtime/evaluation-001"
    base.require(not work.exists(), "fresh evaluation output required")
    work.mkdir(parents=True)
    env = dict(os.environ, JAVA_HOME_OVERRIDE=str(args.java_home))
    env_engine = args.engine.resolve()

    def build_cases(build):
        base.require(build["split"] == families[build["family"]], "family split leakage")
        binary = base.ROOT / build["path"]
        base.require(base.sha(binary) == build["sha256"], "compiled bytes changed")
        directory = work / build["id"]
        directory.mkdir()
        (directory / "projects").mkdir()
        typed, recovered, high = [directory / n for n in ("typed", "recovered", "high")]
        receipts, cases = [], []
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
            base.ROOT / "ghidra_scripts",
            "-postScript",
            "export_research_graph.py",
            typed,
            "-postScript",
            "export_recovered_evidence.py",
            recovered,
            "subject",
            "subject_equivalent",
            "foil",
        ]
        receipts.append(base.command(cmd, directory / "ghidra.log", env, 360))
        log = (directory / "ghidra.log").read_text(encoding="utf-8", errors="replace")
        base.require("ERROR " not in log and "Traceback (most recent call last)" not in log, "Ghidra extraction error")
        docs = [json.loads(p.read_bytes()) for p in recovered.glob("*.json")]
        base.require(len(docs) == 3 and {d["source"]["function"]["name"] for d in docs} == {"subject", "subject_equivalent", "foil"}, "missing functions")
        high.mkdir()
        for i, doc in enumerate(docs):
            base.require(doc["source"]["source"]["sha256"] == build["sha256"], "evidence source mismatch")
            (high / f"{i}.json").write_bytes(serialize(doc["source"]))
        graph, context, config = [directory / n for n in ("graph.json", "context.json", "config.json")]
        base.save(context, dict(structural=dict(caller_depth=0, callee_depth=0), max_operational_functions=4, max_operations=10000, max_dependencies=20000))
        base.save(config, dict(max_two_edge_paths=4096))
        receipts.append(base.command([env_engine, "operational-bind", typed / (binary.name + ".graph.json"), high, graph], directory / "bind.log"))
        for doc in sorted(docs, key=lambda d: d["source"]["function"]["name"]):
            name = doc["source"]["function"]["name"]
            local, canonical, fp, multi = [directory / (name + suffix) for suffix in (".local.json", ".canonical.json", ".fp.json", ".multi.json")]
            for argv in [["operational-local", graph, doc["source"]["function"]["id"], context, local], ["operational-canonical", local, canonical], ["operational-fingerprint", canonical, config, fp], ["multilevel-fingerprint", fp, multi]]:
                receipts.append(base.command([env_engine, *argv], Path(argv[-1]).with_suffix(".log")))
            semantic_fp = semantic.fingerprint(doc)
            base.require(encoded(semantic_fp) == encoded(semantic.fingerprint(doc)), "nondeterministic fingerprint")
            path = directory / (name + ".semantic.json")
            path.write_bytes(encoded(semantic_fp))
            cases.append(
                dict(
                    id=build["id"] + ":" + name,
                    family=build["family"],
                    split=build["split"],
                    compiler=build["compiler"],
                    optimization=build["optimization"],
                    build=build["id"],
                    semantic_class=build["family"] + (":foil" if name == "foil" else ":subject"),
                    fingerprint=str(path),
                    multilevel=str(multi),
                    parameter_occurrences=len(doc["parameters"]),
                    cfg_status=doc["cfg_status"],
                    barriers={k: len(v["barriers"]) for k, v in semantic_fp["views"].items()},
                )
            )
        print("PASS fresh extraction", build["id"], flush=True)
        return cases, receipts

    cases, receipts = [], []
    with ThreadPoolExecutor(max_workers=3) as pool:
        for local_cases, local_receipts in pool.map(build_cases, manifest["builds"]):
            cases.extend(local_cases)
            receipts.extend(local_receipts)
    cases.sort(key=lambda c: c["id"])
    fingerprints = {c["id"]: json.loads(Path(c["fingerprint"]).read_bytes()) for c in cases}
    pairs = {name: [] for name in CONDITIONS}
    (work / "pairs").mkdir()
    count = 0
    for q, r in itertools.combinations(cases, 2):
        if q["split"] != r["split"] or q["build"] == r["build"]:
            continue
        first, second = [work / "pairs" / f"{count}.{suffix}.json" for suffix in ("first", "repeat")]
        for path in (first, second):
            receipts.append(base.command([env_engine, "multilevel-compare", q["multilevel"], r["multilevel"], path], path.with_suffix(".log")))
        base.require(first.read_bytes() == second.read_bytes(), "multilevel comparison nondeterministic")
        multi = json.loads(first.read_bytes())
        value = semantic.compare(fingerprints[q["id"]], fingerprints[r["id"]])
        base.require(encoded(value) == encoded(semantic.compare(fingerprints[q["id"]], fingerprints[r["id"]])), "semantic comparison nondeterministic")
        (work / "pairs" / f"{count}.semantic.json").write_bytes(encoded(value))
        scores = {k: v["set_similarity"] for k, v in value["views"].items()}
        scores.update(exact=multi["baseline"]["operational"]["set_similarity"], multilevel=multi["aggregates"]["exact_mean_012"]["set_similarity"])
        scores["combined"] = (scores["multilevel"] + scores["algebra"]) / 2 if scores["multilevel"] is not None and scores["algebra"] is not None else None
        for condition in CONDITIONS:
            pairs[condition].append(dict(query=q["id"], reference=r["id"], split=q["split"], positive=q["semantic_class"] == r["semantic_class"], score=scores[condition], same_family=q["family"] == r["family"]))
        count += 1
        if count % 50 == 0:
            print("PASS", count, "deterministic comparisons", flush=True)
    summary = {}
    for condition, rows in pairs.items():
        discovery = [r for r in rows if r["split"] == "discovery"]
        threshold = low_fpr_threshold(discovery, method["max_discovery_fpr"])
        balanced = base.calibrate(discovery)
        summary[condition] = dict(discovery_threshold=threshold, discovery_balanced_threshold=balanced, splits={})
        for split in ("discovery", "validation", "heldout"):
            selected = [r for r in rows if r["split"] == split]
            stats = base.metrics(selected, threshold)
            stats.update(base.retrieval([c for c in cases if c["split"] == split], selected))
            stats.update(roc_auc=auc(selected), balanced_policy=base.metrics(selected, balanced), same_family=base.metrics([r for r in selected if r["same_family"]], threshold))
            summary[condition]["splits"][split] = stats
    verify(args)
    base.require(manifest_path.read_bytes() == manifest_bytes, "manifest changed during run")
    report = dict(
        status="PASS",
        method_sha256=base.sha(args.study / "method.json"),
        manifest_sha256=base.sha(manifest_path),
        cases=cases,
        pairs=pairs,
        summary=summary,
        receipts=receipts,
        no_target_execution=True,
        deterministic_reruns=True,
        limitation="Prospective internally authored six-family pilot; no external blinding or population significance; correlated compiler pairs",
    )
    base.save(args.study / "results.json", report)
    for condition in CONDITIONS:
        s = summary[condition]["splits"]["heldout"]
        print(condition, "HELDOUT", {k: s[k] for k in ("tpr", "fpr", "balanced_accuracy", "roc_auc", "mrr")}, flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("register-method", "run"))
    p.add_argument("--study", type=Path, required=True)
    p.add_argument("--engine", type=Path, required=True)
    p.add_argument("--ghidra", type=Path)
    p.add_argument("--python", type=Path)
    p.add_argument("--java-home", type=Path)
    args = p.parse_args()
    args.study = args.study.resolve()
    register(args) if args.action == "register-method" else evaluate(args)
