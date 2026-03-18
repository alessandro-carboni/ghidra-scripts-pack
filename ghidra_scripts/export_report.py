#@runtime pyghidra
#@author
#@category Triage
#@keybinding
#@menupath
#@toolbar

import os
import json

from ghidra.program.util import DefinedDataIterator


MAX_STRINGS = 300
MAX_STRING_LENGTH = 200


def get_external_symbols():
    symbol_table = currentProgram.getSymbolTable()
    external_symbols = symbol_table.getExternalSymbols()

    symbols = set()

    for symbol in external_symbols:
        name = symbol.getName()
        if name:
            symbols.add(name)

    return sorted(symbols)


def get_strings():
    results = []

    for data in DefinedDataIterator.definedStrings(currentProgram):
        try:
            value = data.getDefaultValueRepresentation()
        except:
            continue

        if not value:
            continue

        value = value.strip()

        if len(value) < 4:
            continue

        if len(value) > MAX_STRING_LENGTH:
            value = value[:MAX_STRING_LENGTH]

        results.append({
            "address": str(data.getAddress()),
            "value": value
        })

        if len(results) >= MAX_STRINGS:
            break

    return results


def get_functions():
    functions = []
    function_manager = currentProgram.getFunctionManager()

    for func in function_manager.getFunctions(True):
        functions.append({
            "name": func.getName(),
            "entry": str(func.getEntryPoint()),
            "external": func.isExternal(),
            "thunk": func.isThunk(),
            "called_functions": [],
            "referenced_strings": [],
            "tags": [],
            "score": 0
        })

    return functions


def build_report():
    return {
        "sample": {
            "name": currentProgram.getName(),
            "path": currentProgram.getExecutablePath() or "",
            "format": currentProgram.getExecutableFormat()
        },
        "external_symbols": get_external_symbols(),
        "strings": get_strings(),
        "functions": get_functions()
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