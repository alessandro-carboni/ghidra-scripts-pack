#@runtime pyghidra
#@author
#@category Triage
#@keybinding
#@menupath
#@toolbar

import os
import json


def get_external_symbols():
    symbol_table = currentProgram.getSymbolTable()
    external_symbols = symbol_table.getExternalSymbols()

    symbols = set()

    for symbol in external_symbols:
        name = symbol.getName()
        if name:
            symbols.add(name)

    return sorted(symbols)


def build_report():
    return {
        "sample": {
            "name": currentProgram.getName(),
            "path": currentProgram.getExecutablePath() or "",
            "format": currentProgram.getExecutableFormat()
        },
        "external_symbols": get_external_symbols()
    }


def main():
    script_args = getScriptArgs()
    output_dir = script_args[0] if len(script_args) > 0 else "."
    output_path = os.path.join(output_dir, "raw_report.json")

    report = build_report()

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print("[+] Report written to: {}".format(output_path))


if __name__ == "__main__":
    main()