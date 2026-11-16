"""Fresh real-Ghidra baseline followed by pinned optional-value-view ablation."""

import argparse
import json
from pathlib import Path

try:
    from . import evaluate_operational_baseline as base
    from . import evaluate_value_flow as value
except ImportError:
    import evaluate_operational_baseline as base
    import evaluate_value_flow as value


def run(args):
    study = args.study_dir.resolve()
    protocol = json.loads((study / "protocol.json").read_bytes())
    base.require(protocol["study_driver_sha256"] == base.sha(Path(__file__)), "study driver changed")
    base.require(protocol["method_protocol_sha256"] == base.sha(study / "method_protocol.json"), "method registration changed")
    method = json.loads((study / "method_protocol.json").read_bytes())
    for relative, expected in method["implementation_sha256"].items():
        base.require(base.sha(base.ROOT / relative) == expected, "locked method changed: " + relative)
    base.require(not (study / "results.json").exists(), "baseline results already exist")
    base.DATA = study
    base.evaluate(args)
    baseline_path = study / "results.json"
    baseline = json.loads(baseline_path.read_bytes())
    registration = dict(
        scope="New source families, method locked before authoring; not externally blinded",
        implementation_sha256=method["implementation_sha256"],
        engine_sha256=method["engine_sha256"],
        baseline_results_sha256=base.sha(baseline_path),
        fingerprint_sha256={c["fingerprint"]: base.sha(Path(c["fingerprint"])) for c in baseline["cases"]},
    )
    registration_path = study / "value_protocol.json"
    base.require(not registration_path.exists(), "value registration already exists")
    base.save(registration_path, registration)
    value.evaluate(argparse.Namespace(protocol=registration_path, baseline_results=baseline_path, engine=args.operational_engine, output=args.work.parent / "value-001"))
    base.require(protocol["study_driver_sha256"] == base.sha(Path(__file__)), "study driver changed during execution")


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
