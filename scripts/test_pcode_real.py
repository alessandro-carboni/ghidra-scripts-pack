"""Standalone real static-extraction gate. Never executes a corpus executable."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

try:
    from .pcode_evidence import loads, require
except ImportError:
    from pcode_evidence import loads, require

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = {"numeric": ["sum_array", "count_matches", "find_max"], "memory": ["copy_buffer", "xor_buffer", "weighted_buffer"], "text": ["count_digits", "count_letters", "search_string"]}


def implementation_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ("scripts/pcode_evidence.py", "scripts/test_pcode_real.py", "ghidra_scripts/pcode_extraction.py", "ghidra_scripts/export_pcode_evidence.py")}


def check_outputs(directory, names, binary_hash):
    files = sorted(directory.glob("*.json"))
    require(len(files) == len(names), "missing/extra extraction output: " + str(directory))
    docs = [loads(path.read_bytes()) for path in files]
    require({doc["function"]["name"] for doc in docs} == set(names), "function selection mismatch")
    require(all(doc["source"]["sha256"] == binary_hash for doc in docs), "binary provenance mismatch")
    require(all(doc["observability"]["state"] == "complete" and doc["operations"] for doc in docs), "incomplete real extraction")
    return {doc["function"]["name"]: (path.read_bytes(), doc) for path, doc in zip(files, docs)}


def run(args):
    work = args.work.resolve()
    require(not work.exists(), "Use a new work directory; do not overwrite evidence")
    work.mkdir(parents=True)
    (work / "projects").mkdir()
    manifest = json.loads(args.manifest.read_bytes())
    builds = {b["build_id"]: b for b in manifest["builds"]}
    report = {"status": "RUNNING", "sample_execution": False, "rows": [], "commands": [], "limitations": ["Development corpus only; not independent evaluation", "No behavioral equivalence inferred from observed operations", "Runtime includes fresh import and Ghidra startup; peak memory NOT RUN"]}
    report["implementation_sha256"] = implementation_hashes()
    env = os.environ.copy()
    env["JAVA_HOME_OVERRIDE"] = str(args.java_home)
    try:
        for build_id in args.build:
            require(build_id in builds, "unknown registered build")
            build = builds[build_id]
            family = build["artifact_group"]
            require(family in FUNCTIONS, "unsupported experiment family")
            names = args.function or FUNCTIONS[family]
            binary = args.build_root / build_id / (build_id + ".exe")
            binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
            require(binary_hash == build["build_hash"], "compiled-byte provenance mismatch")
            outputs = {}
            for repeat in (1, 2):
                # Fresh project AND settings for independent repeats, not a cached rerun.
                label = build_id + "-" + str(repeat)
                settings = work / ("settings-" + label)
                command = [str(args.python), "-m", "pyghidra.ghidra_launch", "-D", "application.settingsdir=" + str(settings), "--install-dir", str(args.ghidra), "ghidra.app.util.headless.AnalyzeHeadless", str(work / "projects"), label, "-import", str(binary), "-scriptPath", str(ROOT / "ghidra_scripts")]
                for layer in ("raw", "high"):
                    output = work / (label + "-" + layer)
                    command.extend(["-postScript", "export_pcode_evidence.py", str(output), layer, *names])
                report["commands"].append(command)
                start = time.perf_counter()
                with (work / (label + ".log")).open("w", encoding="utf-8") as log:
                    result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout, check=False)
                elapsed = time.perf_counter() - start
                require(result.returncode == 0, "Ghidra process failed: " + label)
                log_text = (work / (label + ".log")).read_text(encoding="utf-8")
                require("ERROR " not in log_text and "Traceback (most recent call last)" not in log_text, "Ghidra logged an error despite exit code zero: " + label)
                for layer in ("raw", "high"):
                    outputs[(repeat, layer)] = check_outputs(work / (label + "-" + layer), names, binary_hash)
                print("PASS", label, "static Raw/High extraction; seconds", round(elapsed, 3), flush=True)
                report.setdefault("timings", []).append(dict(run=label, seconds=elapsed))
            for layer in ("raw", "high"):
                for name in names:
                    first, doc = outputs[(1, layer)][name]
                    require(first == outputs[(2, layer)][name][0], "nondeterministic evidence: " + build_id + "/" + name + "/" + layer)
                    row = dict(
                        build=build_id,
                        function=name,
                        representation=layer,
                        operations=len(doc["operations"]),
                        dependencies=len(doc["dependencies"]),
                        unresolved_inputs=doc["observability"]["unresolved_inputs"],
                        opcodes=sorted({op["opcode"] for op in doc["operations"]}),
                        sha256=hashlib.sha256(first).hexdigest(),
                        deterministic=True,
                    )
                    report["rows"].append(row)
            print("PASS", build_id, "byte-identical fresh repeats", flush=True)
        require(report["implementation_sha256"] == implementation_hashes(), "implementation changed during experiment; rerun with pinned files")
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        (work / "validation.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True, help="Existing PyGhidra virtual-environment interpreter")
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--build", action="append", required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "datasets/osgf_pairs_v0_1/manifest.json")
    parser.add_argument("--build-root", type=Path, default=ROOT / "samples/controlled/builds")
    parser.add_argument("--function", action="append", help="Explicit routine selection, e.g. a controlled wrapper")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    require(args.timeout > 0, "timeout must be positive")
    print(json.dumps(run(args), sort_keys=True, indent=2))
