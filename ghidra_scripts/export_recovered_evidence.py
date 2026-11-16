# @runtime pyghidra
# @category Research
"""Static additive HighParam/CFG export: output-dir function-name ..."""

from pathlib import Path
import argparse
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recovered_extraction import extract_recovered  # noqa: E402
from recovered_evidence import encoded  # noqa: E402


def main():
    from ghidra.framework import Application
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import HighParam

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("functions", nargs="+")
    args = parser.parse_args(list(getScriptArgs()))  # noqa: F821
    program, task_monitor = currentProgram, monitor  # noqa: F821
    environment = dict(
        ghidra_version=str(Application.getApplicationVersion()),
        ghidra_revision=str(Application.getApplicationProperty("application.revision.ghidra")),
        language=str(program.getLanguageID()),
        compiler_spec=str(program.getCompilerSpec().getCompilerSpecID()),
        analysis_policy="fresh-headless-default-analysis;decompiler-default-options",
    )
    args.output.mkdir(parents=True, exist_ok=True)
    requested, found = set(args.functions), set()
    for function in program.getFunctionManager().getFunctions(True):
        if str(function.getName()) not in requested:
            continue
        doc = extract_recovered(program, function, task_monitor, environment, DecompInterface, lambda h: isinstance(h, HighParam))
        path = args.output / (str(function.getEntryPoint()).replace(":", "_") + ".json")
        with path.open("xb") as stream:
            stream.write(encoded(doc))
        found.add(str(function.getName()))
        print("RECOVERED", function.getName(), len(doc["parameters"]), "parameter occurrences", doc["cfg_status"], flush=True)
    if found != requested:
        raise ValueError("Missing functions: " + repr(requested - found))


if __name__ == "__main__":
    main()
