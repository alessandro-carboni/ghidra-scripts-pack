# @runtime pyghidra
# @category Research
"""Export real typed evidence plus symbols used ONLY for source provenance mapping."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import export_report  # noqa: E402


def main():
    export_report.__dict__.update({key: value for key, value in globals().items() if key in ("currentProgram", "monitor", "getDataAt", "getInstructionAt", "toAddr", "getFunctionAt", "getFunctionContaining")})
    export_report.currentProgram = currentProgram  # noqa: F821
    export_report.monitor = monitor  # noqa: F821
    graph = export_report.build_seeded_typed_graph()
    graph["metadata"]["research_binary_sha256"] = str(currentProgram.getExecutableSHA256()).lower()  # noqa: F821
    symbols = {}
    for function in currentProgram.getFunctionManager().getFunctions(True):  # noqa: F821
        symbols[function.getName()] = export_report.build_stable_function_id(function.getEntryPoint())
    output = Path(getScriptArgs()[0])  # noqa: F821
    output.mkdir(parents=True, exist_ok=True)
    name = currentProgram.getName()  # noqa: F821
    (output / (name + ".graph.json")).write_text(json.dumps(graph, sort_keys=True, indent=2), encoding="utf-8")
    (output / (name + ".symbols.json")).write_text(json.dumps(symbols, sort_keys=True, indent=2), encoding="utf-8")
    print("RESEARCH GRAPH EXPORTED: " + name)


if __name__ == "__main__":
    main()
