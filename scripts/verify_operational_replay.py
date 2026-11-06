"""Replay only the allowlisted operational CLI receipts; never execute target PEs."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {"operational-bind", "operational-local", "operational-canonical", "operational-fingerprint", "operational-compare"}


def verify(engine, results, output):
    engine, results, output = engine.resolve(), results.resolve(), output.resolve()
    report = json.loads(results.read_bytes())
    if report.get("status") != "PASS" or output.exists():
        raise ValueError("requires a successful study and a new replay directory")
    output.mkdir(parents=True)
    counts = dict.fromkeys(sorted(COMMANDS), 0)
    checked = []
    for receipt in report["receipts"]:
        argv = receipt["command"]
        if len(argv) < 3 or argv[1] not in COMMANDS:
            continue
        expected = Path(argv[-1])
        if not expected.is_absolute():
            expected = ROOT / expected
        target = output / f"{len(checked):04d}.json"
        # Never execute argv[0] from a report: use the explicitly supplied engine.
        command = [str(engine), *argv[1:-1], str(target)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120, check=False)
        if result.returncode != 0:
            raise ValueError(f"Replay failed: {command}: {result.stderr.decode(errors='replace')}")
        if target.read_bytes() != expected.read_bytes():
            raise ValueError(f"Byte mismatch: {expected}")
        counts[argv[1]] += 1
        checked.append(dict(command=command, expected=str(expected), sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
        if len(checked) % 50 == 0:
            print(f"PASS {len(checked)} byte-identical operational outputs", flush=True)
    if not all(counts.values()):
        raise ValueError("Missing operational stage receipts")
    summary = dict(status="PASS", counts=counts, outputs=len(checked), original_results_sha256=hashlib.sha256(results.read_bytes()).hexdigest(), engine_sha256=hashlib.sha256(engine.read_bytes()).hexdigest(), checked=checked)
    (output / "verification.json").write_bytes((json.dumps(summary, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({k: v for k, v in summary.items() if k != "checked"}, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify(args.engine, args.results, args.output)
