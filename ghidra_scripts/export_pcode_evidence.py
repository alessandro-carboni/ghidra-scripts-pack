# @runtime pyghidra
# @category Research
"""Opt-in static export. Args: output-dir raw|high function-name ..."""

from pathlib import Path
import argparse
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcode_extraction import extract  # noqa: E402
from pcode_evidence import serialize  # noqa: E402


def main():
    from ghidra.framework import Application
    from ghidra.app.decompiler import DecompInterface

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("representation", choices=("raw", "high"))
    parser.add_argument("functions", nargs="+")
    parser.add_argument("--max-operations", type=int, default=10000)
    parser.add_argument("--max-dependencies", type=int, default=20000)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args(list(getScriptArgs()))  # noqa: F821
    program, task_monitor = currentProgram, monitor  # noqa: F821
    environment = dict(
        ghidra_version=str(Application.getApplicationVersion()),
        ghidra_revision=str(Application.getApplicationProperty("application.revision.ghidra")),
        language=str(program.getLanguageID()),
        compiler_spec=str(program.getCompilerSpec().getCompilerSpecID()),
        analysis_policy="fresh-headless-default-analysis;decompiler-default-options",
    )
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    requested = set(args.functions)
    found = set()
    for function in program.getFunctionManager().getFunctions(True):
        name = str(function.getName())
        if name not in requested:
            continue
        doc = extract(program, function, task_monitor, environment, args.representation, args.max_operations, args.max_dependencies, args.timeout_seconds, decompiler_factory=DecompInterface)
        path = output / (args.representation + "-" + str(function.getEntryPoint()).replace(":", "_") + ".json")
        if path.exists():
            raise ValueError("Refusing to overwrite evidence: " + str(path))
        path.write_bytes(serialize(doc))
        found.add(name)
        print("PCODE", name, args.representation, doc["observability"]["state"], len(doc["operations"]), "operations", len(doc["dependencies"]), "dependencies")
    if found != requested:
        raise ValueError("Missing requested functions: " + repr(sorted(requested - found)))


if __name__ == "__main__":
    main()
