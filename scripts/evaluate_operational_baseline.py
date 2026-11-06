"""Preregistered development/fresh-family A/B/C/D evaluation. Never executes target PEs."""

import argparse
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets/osgf_baseline_evaluation_v0_2"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def implementation():
    paths = (
        list((ROOT / "rust_engine/src").rglob("*.rs"))
        + list((ROOT / "rust_engine/operational/src").rglob("*.rs"))
        + [ROOT / "rust_engine/Cargo.toml", ROOT / "rust_engine/operational/Cargo.toml", ROOT / "rust_engine/operational/Cargo.lock", ROOT / "scripts/pcode_evidence.py", ROOT / "ghidra_scripts/pcode_extraction.py", ROOT / "ghidra_scripts/export_pcode_evidence.py", Path(__file__)]
    )
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def command(argv, log, env=None, timeout=240):
    start = time.perf_counter()
    with subprocess.Popen(list(map(str, argv)), cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
            log.write_bytes(output)
            raise
        peak = None
        if os.name == "nt":

            class Counters(ctypes.Structure):
                _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)] + [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(int(process._handle)), ctypes.byref(counters), counters.cb):
                peak = counters.PeakWorkingSetSize
        log.write_bytes(output)
        require(process.returncode == 0, f"Command failed ({process.returncode}): {argv}; see {log}")
    return dict(command=list(map(str, argv)), seconds=time.perf_counter() - start, peak_working_set_bytes=peak, memory_scope="Direct child process only; excludes subprocess tree", log=str(log.relative_to(ROOT)))


def metrics(pairs, threshold):
    usable = [p for p in pairs if p["score"] is not None]
    tp = sum(p["positive"] and p["score"] >= threshold for p in usable)
    fp = sum(not p["positive"] and p["score"] >= threshold for p in usable)
    pos = sum(p["positive"] for p in usable)
    neg = len(usable) - pos
    return dict(pairs=len(pairs), comparable=len(usable), nulls=len(pairs) - len(usable), tp=tp, fp=fp, fn=pos - tp, tn=neg - fp, tpr=tp / pos if pos else None, fpr=fp / neg if neg else None, hard_negative_fpr=fp / neg if neg else None, balanced_accuracy=(tp / pos + (neg - fp) / neg) / 2 if pos and neg else None)


def calibrate(pairs):
    candidates = sorted({0.0, 1.0000000000000002, *(p["score"] for p in pairs if p["score"] is not None)})
    require(any(p["positive"] and p["score"] is not None for p in pairs) and any(not p["positive"] and p["score"] is not None for p in pairs), "discovery needs comparable pairs of both labels")
    return max(candidates, key=lambda t: (metrics(pairs, t)["balanced_accuracy"], t))


def retrieval(cases, pairs):
    lookup = {tuple(sorted((p["query"], p["reference"]))): p for p in pairs}
    reciprocal, recalls, ties = [], {1: [], 3: [], 5: []}, 0
    for query in cases:
        gallery = []
        for candidate in cases:
            pair = lookup.get(tuple(sorted((query["id"], candidate["id"]))))
            if pair is not None and pair["score"] is not None:
                gallery.append((pair["score"], candidate["id"], pair["positive"]))
        positive = sum(p for _, _, p in gallery)
        if not positive or all(p for _, _, p in gallery):
            continue
        gallery.sort(key=lambda row: (-row[0], row[1]))
        ties += len({s for s, _, _ in gallery}) < len(gallery)
        reciprocal.append(1 / next(i for i, (_, _, p) in enumerate(gallery, 1) if p))
        for k in recalls:
            recalls[k].append(sum(p for _, _, p in gallery[:k]) / positive)
    return dict(mixed_queries=len(reciprocal), mrr=sum(reciprocal) / len(reciprocal) if reciprocal else None, recall_at_k={str(k): sum(v) / len(v) if v else None for k, v in recalls.items()}, queries_with_ties=ties, tie_break="case ID ascending; same-build candidates excluded")


def evaluate(args):
    protocol = json.loads((DATA / "protocol.json").read_bytes())
    require(protocol["implementation_byte_sha256"] == implementation(), "implementation changed after preregistration")
    require(sha(args.engine) == protocol["engine_sha256"], "engine changed after preregistration")
    require(sha(args.operational_engine) == protocol["operational_engine_sha256"], "operational engine changed after preregistration")
    manifest = json.loads((DATA / "manifest.json").read_bytes())
    work = args.work.resolve()
    require(not work.exists(), "use a new evaluation workspace")
    work.mkdir(parents=True)
    (work / "projects").mkdir()
    receipts, cases = [], []
    env = os.environ.copy()
    env["JAVA_HOME_OVERRIDE"] = str(args.java_home)
    local_config = work / "context.json"
    feature_config = work / "features.json"
    save(local_config, protocol["context_configuration"])
    save(feature_config, protocol["feature_configuration"])
    components = {}
    for source in manifest["sources"]:
        require(sha(ROOT / source["path"]) == source["sha256"], "source bytes changed")
        require(source["family"] not in components, "duplicate source family")
        components[source["family"]] = source["split"]
    for build in manifest["builds"]:
        require(components[build["family"]] == build["split"], "source component crosses splits")
        binary = ROOT / build["path"]
        require(sha(binary) == build["sha256"], "compiled bytes changed")
        directory = work / build["id"]
        directory.mkdir()
        typed, evidence = directory / "typed", directory / "high"
        cmd = [
            args.python,
            "-m",
            "pyghidra.ghidra_launch",
            "-D",
            "application.settingsdir=" + str(directory / "settings"),
            "--install-dir",
            args.ghidra,
            "ghidra.app.util.headless.AnalyzeHeadless",
            work / "projects",
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
            evidence,
            "high",
            "subject",
            "subject_equivalent",
            "foil",
        ]
        receipts.append(command(cmd, directory / "ghidra.log", env, 300))
        log = (directory / "ghidra.log").read_text(encoding="utf-8", errors="replace")
        require("ERROR " not in log and "Traceback (most recent call last)" not in log, "Ghidra logged extraction error")
        docs = [json.loads(p.read_bytes()) for p in evidence.glob("*.json")]
        require(len(docs) == 3 and {d["function"]["name"] for d in docs} == {"subject", "subject_equivalent", "foil"}, "missing/extra functions")
        require(all(d["source"]["sha256"] == build["sha256"] for d in docs), "P-code binary mismatch")
        graph = directory / "graph.json"
        receipts.append(command([args.operational_engine, "operational-bind", typed / (binary.name + ".graph.json"), evidence, graph], directory / "bind.log"))
        for doc in sorted(docs, key=lambda d: d["function"]["name"]):
            name = doc["function"]["name"]
            local, canonical, fp = [directory / (name + suffix) for suffix in (".local.json", ".canonical.json", ".fp.json")]
            for argv, label in [(["operational-local", graph, doc["function"]["id"], local_config, local], "local"), (["operational-canonical", local, canonical], "canonical"), (["operational-fingerprint", canonical, feature_config, fp], "fingerprint")]:
                receipts.append(command([args.operational_engine, *argv], directory / (name + "-" + label + ".log")))
            repeated = directory / (name + ".repeat.fp.json")
            receipts.append(command([args.operational_engine, "operational-fingerprint", canonical, feature_config, repeated], directory / (name + "-repeat.log")))
            require(fp.read_bytes() == repeated.read_bytes(), "nondeterministic fingerprint")
            # Independent legacy CLI reconstruction establishes A == structural-only B.
            legacy_local, legacy_canonical, legacy_fp = [directory / (name + suffix) for suffix in (".legacy-local.json", ".legacy-canonical.json", ".legacy-fp.json")]
            save(legacy_local, json.loads(local.read_bytes())["structural"])
            receipts.append(command([args.engine, "canonicalize-local-subgraph", legacy_local, legacy_canonical], directory / (name + "-legacy-canonical.log")))
            receipts.append(command([args.engine, "fingerprint-canonical", legacy_canonical, legacy_fp], directory / (name + "-legacy-fingerprint.log")))
            fingerprint = json.loads(fp.read_bytes())
            require(json.loads(legacy_fp.read_bytes()) == fingerprint["structural"], "A/B structural representations differ")
            cases.append(
                dict(
                    id=build["id"] + ":" + name,
                    family=build["family"],
                    split=build["split"],
                    compiler=build["compiler"],
                    optimization=build["optimization"],
                    build=build["id"],
                    semantic_class=build["family"] + (":foil" if name == "foil" else ":subject"),
                    fingerprint=str(fp),
                    legacy_canonical=str(legacy_canonical),
                    legacy_fingerprint=str(legacy_fp),
                    operational_features=len(fingerprint["operational_view"]),
                    observability=doc["observability"],
                )
            )
        print("PASS extraction and A/B identity:", build["id"], flush=True)
    pairs = {condition: [] for condition in "ABCD"}
    (work / "pairs").mkdir()
    for index, (q, r) in enumerate(itertools.combinations(cases, 2)):
        if q["split"] != r["split"] or q["build"] == r["build"]:
            continue
        output, repeat, legacy = [work / "pairs" / (str(index) + suffix) for suffix in (".json", ".repeat.json", ".legacy.json")]
        for dest in (output, repeat):
            receipts.append(command([args.operational_engine, "operational-compare", q["fingerprint"], r["fingerprint"], dest], dest.with_suffix(".log")))
        require(output.read_bytes() == repeat.read_bytes(), "nondeterministic comparison")
        receipts.append(command([args.engine, "compare-fingerprints", q["id"], q["legacy_canonical"], q["legacy_fingerprint"], r["id"], r["legacy_canonical"], r["legacy_fingerprint"], legacy, "--aggregate"], legacy.with_suffix(".log")))
        result = json.loads(output.read_bytes())
        a = json.loads(legacy.read_bytes())
        b = result["structural_v0_1"]
        require(a["aggregate_set_similarity"] == b["aggregate_set_similarity"] and a["aggregate_multiset_similarity"] == b["aggregate_multiset_similarity"], "A/B scores differ")
        for condition, score in zip("ABCD", [a["aggregate_set_similarity"], b["aggregate_set_similarity"], result["operational"]["set_similarity"], result["aggregate"]["set_similarity"]]):
            pairs[condition].append(
                dict(
                    query=q["id"],
                    reference=r["id"],
                    split=q["split"],
                    positive=q["semantic_class"] == r["semantic_class"],
                    score=score,
                    cross_compiler=q["compiler"] != r["compiler"],
                    cross_optimization=q["compiler"] == r["compiler"] and q["optimization"] != r["optimization"],
                    insufficient=result["operational"]["query_support"]["status"] == "INSUFFICIENT_EVIDENCE" or result["operational"]["reference_support"]["status"] == "INSUFFICIENT_EVIDENCE",
                )
            )
    summary = {}
    for condition in "ABCD":
        threshold = calibrate([p for p in pairs[condition] if p["split"] == "discovery"])
        summary[condition] = dict(discovery_threshold=threshold, splits={})
        for split in ("discovery", "validation", "heldout"):
            selected = [p for p in pairs[condition] if p["split"] == split]
            stats = metrics(selected, threshold)
            stats.update(retrieval([c for c in cases if c["split"] == split], selected))
            stats["insufficient_evidence_rate"] = sum(p["insufficient"] for p in selected) / len(selected) if selected else None
            for flag in ("cross_compiler", "cross_optimization"):
                scores = [p["score"] for p in selected if p["positive"] and p[flag] and p["score"] is not None]
                stats[flag + "_positive_mean"] = sum(scores) / len(scores) if scores else None
                stats[flag + "_positive_pairs"] = len(scores)
            if condition == "C":
                scores = [p["score"] for p in selected if p["positive"] and p["score"] is not None]
                stats["positive_feature_churn_mean"] = sum(1 - s for s in scores) / len(scores) if scores else None
            summary[condition]["splits"][split] = stats
    require(protocol["implementation_byte_sha256"] == implementation(), "implementation changed during evaluation")
    report = dict(status="PASS", protocol_sha256=sha(DATA / "protocol.json"), manifest_sha256=sha(DATA / "manifest.json"), summary=summary, cases=cases, pairs=pairs, receipts=receipts, limits=protocol["limitations"], no_target_execution=True)
    save(work / "results.json", report)
    save(DATA / "results.json", report)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--operational-engine", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    evaluate(parser.parse_args())
