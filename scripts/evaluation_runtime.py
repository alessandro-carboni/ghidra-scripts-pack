"""Step 10.9: matched debug-engine wall-clock observations, never scientific scores."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

try:
    from . import evaluation_metrics as m
except ImportError:
    import evaluation_metrics as m

g = m.g
require, serialize = g.require, g.serialize


def timed(call, clock=time.perf_counter_ns):
    start = clock()
    try:
        value = call()
    except (ValueError, subprocess.TimeoutExpired) as error:
        return None, dict(status="failed", elapsed_ns=clock() - start, reason="timeout" if isinstance(error, subprocess.TimeoutExpired) else str(error))
    elapsed = clock() - start
    require(elapsed >= 0, "nonmonotonic timer")
    return value, dict(status="success", elapsed_ns=elapsed, reason=None)


def summarize(observations, expected):
    keys = [(r["repetition"], r["condition"], r["stage"], r["id"]) for r in observations]
    require(len(keys) == len(set(keys)) and set(keys) == set(expected), "missing/duplicate/mismatched benchmark cohort")
    require(all(type(r["elapsed_ns"]) is int and r["elapsed_ns"] >= 0 for r in observations), "invalid elapsed time")
    require(all(r["warmup"] == (r["repetition"] == 0) for r in observations), "warmup labeling mismatch")
    result = []
    for condition, stage in sorted({(r["condition"], r["stage"]) for r in observations}):
        rows = [r for r in observations if r["condition"] == condition and r["stage"] == stage and not r["warmup"]]
        result.append(dict(condition=condition, stage=stage, attempted_n=len(rows), failure_n=sum(r["status"] != "success" for r in rows), milliseconds=m.distribution(r["elapsed_ns"] / 1e6 for r in rows if r["status"] == "success")))
    return result


def benchmark(protocol, matrix, catalog, observation_id):
    policy = protocol["design"]["runtime"]
    require(policy["warmups"] == 1 and policy["repetitions"] == 5, "unsupported runtime policy")
    by_graph = {(r["condition"], r["graph_id"]): r for r in catalog["records"]}
    graph_ids = sorted(gid for c, gid in by_graph if c == "A")
    require(set(graph_ids) == {gid for c, gid in by_graph if c == "B"}, "mismatched graph cohort")
    manifest = json.loads((g.ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    jobs = g.pairs.pair_jobs(manifest, catalog["records"], matrix["identity"])
    index = {(r["condition"], r["pair"]["pair_id"]): r for r in matrix["records"]}
    observations, expected = [], []

    def measure(repetition, condition, stage, identity, call):
        key = (repetition, condition, stage, identity)
        expected.append(key)
        value, result = timed(call)
        observations.append(dict(repetition=repetition, warmup=repetition == 0, condition=condition, stage=stage, id=identity, **result))
        require(result["status"] == "success", "benchmark operation failed: " + str(key))
        return value

    with tempfile.TemporaryDirectory(prefix="osgf-benchmark-") as temp:
        base = Path(temp)
        for repetition in range(6):
            order = ("A", "B") if repetition % 2 == 0 else ("B", "A")
            for condition in order:
                folder = base / str(repetition) / condition
                folder.mkdir(parents=True)
                for number, gid in enumerate(graph_ids):
                    row = by_graph[condition, gid]
                    paths, expected_fp, _ = measure(repetition, condition, "input_validation_loading", gid, lambda: g.pairs.load_input(row, g.pairs.CATALOG))
                    local = folder / f"{number}-local.json"
                    canonical = json.loads(g.pairs.safe_path(g.ROOT, row["canonical_path"]).read_bytes())
                    local.write_bytes(serialize(canonical["source_document"]))
                    if condition == "A":
                        raw = measure(repetition, condition, "combined_canonicalization_feature_extraction", gid, lambda: g.pairs.catalog.run([g.pairs.catalog.executable(), "extract", "A", local]))
                        require(json.loads(raw)["fingerprint"] == expected_fp, "timed A output differs")
                    else:
                        canon, fp = folder / f"{number}-canonical.json", folder / f"{number}-fp.json"

                        def extract():
                            measure(repetition, condition, "B_only_canonicalization", gid, lambda: g.pairs.catalog.run([g.pairs.catalog.ENGINE, "canonicalize-local-subgraph", local, canon]))
                            measure(repetition, condition, "B_only_feature_extraction", gid, lambda: g.pairs.catalog.run([g.pairs.catalog.ENGINE, "fingerprint-canonical", canon, fp]))

                        measure(repetition, condition, "combined_canonicalization_feature_extraction", gid, extract)
                        require(json.loads(fp.read_bytes()) == expected_fp, "timed B output differs")
                for job in [j for j in jobs if j["condition"] == condition]:
                    result = measure(repetition, condition, "pair_comparison_with_validation_and_io", job["pair"]["pair_id"], lambda: g.pairs.score(job, folder / "pairs"))
                    require(result == index[condition, job["pair"]["pair_id"]], "timed comparison differs")
                measure(repetition, condition, "ranking", "all_queries", lambda: [g.rank_query(q, condition, index) for q in protocol["eligibility"]["queries"]])
                print("BENCHMARK", repetition, "warmup" if repetition == 0 else "measured", condition, "120 graphs / 218 pairs / all query rankings complete", flush=True)
    summaries = summarize(observations, expected)
    versions = {}
    for name, args in (("python", [os.sys.executable, "--version"]), ("rustc", ["rustc", "--version"]), ("cargo", ["cargo", "--version"])):
        versions[name] = subprocess.check_output(args, text=True).strip()
    return dict(
        schema_version="0.1.0",
        observation_id=observation_id,
        generator_utf8_lf_sha256=g.pairs.sha(Path(__file__).read_text(encoding="utf-8").encode()),
        protocol_sha256=g.pairs.catalog.exact_hash(g.ROOT / g.AUDIT_DIR / "protocol.json"),
        matrix_sha256=g.pairs.sha(serialize(matrix)),
        catalog_sha256=g.pairs.sha(serialize(catalog)),
        graph_input_sizes=[dict(condition=row["condition"], graph_id=row["graph_id"], artifact_bytes=sum(a["bytes"] for a in row["artifacts"]), feature_counts={view: len(g.pairs.load_input(row, g.pairs.CATALOG)[1][view + "_view"]) for view in g.pairs.VIEWS}) for row in catalog["records"]],
        status="PASS",
        environment=dict(
            platform=platform.platform(),
            processor=platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
            machine=platform.machine(),
            logical_cpu_count=os.cpu_count(),
            versions=versions,
            profile="locked debug for both Rust executables",
            ghidra="NOT_RUN shared upstream canonical dataset; no new Ghidra extraction measured",
            source_compilers=sorted({b["compiler_version"] for b in manifest["builds"]}),
        ),
        limitations=[
            "Warm OS/filesystem caches not forcibly evicted; repeated fresh output paths, not zero-cost cached B.",
            "Wall time includes subprocess startup, input validation and IO as named; A uses one process, B two for combined extraction.",
            "Approved A CLI combines adapter and extraction. Individual substage timing unavailable for matched A/B; combined stage measured for both.",
            "Pair comparisons load admitted catalog artifacts and validate provenance every time; extraction timed independently on same inputs.",
            "Optional peak RSS unsupported: no verified common measurement method.",
            "Raw wall times are variable observations, excluded from deterministic scientific digests.",
        ],
        observations=observations,
        summary=summaries,
        expected_stage_counts=dict(Counter(r["stage"] for r in observations)),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation-id", required=True)
    args = parser.parse_args()
    require(args.observation_id.isascii() and args.observation_id.replace("-", "").isalnum(), "invalid observation ID")
    output = g.ROOT / g.AUDIT_DIR / "observations" / (args.observation_id + ".json")
    require(not output.exists(), "immutable observation already exists")
    protocol, matrix, catalog = g.admitted_scores()
    result = benchmark(protocol, matrix, catalog, args.observation_id)
    output.parent.mkdir(exist_ok=True)
    with output.open("xb") as stream:
        stream.write(serialize(result))
    print("OBSERVATION PASS", output.name, len(result["observations"]), "samples", flush=True)
    for row in result["summary"]:
        print(row, flush=True)


if __name__ == "__main__":
    main()
