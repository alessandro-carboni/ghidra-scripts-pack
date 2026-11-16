"""Run the unchanged evaluation pipeline against a separately registered study."""

import argparse
import json
from pathlib import Path

try:
    from . import evaluate_operational_baseline as evaluation
except ImportError:
    import evaluate_operational_baseline as evaluation


def run(args):
    study = args.study_dir.resolve()
    protocol = json.loads((study / "protocol.json").read_bytes())
    evaluation.require(protocol["replication_driver_sha256"] == evaluation.sha(Path(__file__)), "replication driver changed after registration")
    evaluation.require(not (study / "results.json").exists(), "replication results already exist")
    evaluation.DATA = study
    evaluation.evaluate(args)
    evaluation.require(protocol["replication_driver_sha256"] == evaluation.sha(Path(__file__)), "replication driver changed during evaluation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--operational-engine", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    run(parser.parse_args())
