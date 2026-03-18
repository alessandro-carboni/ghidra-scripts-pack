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

SUSPICIOUS_API_WEIGHTS = {
    "VirtualAlloc": 25,
    "VirtualAllocEx": 30,
    "WriteProcessMemory": 35,
    "CreateRemoteThread": 40,
    "CreateRemoteThreadEx": 40,
    "NtWriteVirtualMemory": 35,
    "NtCreateThreadEx": 40,
    "SetWindowsHookExW": 20,
    "SetWindowsHookExA": 20,
    "WinExec": 15,
    "ShellExecuteW": 10,
    "ShellExecuteA": 10,
    "CreateProcessW": 15,
    "CreateProcessA": 15,
    "URLDownloadToFileW": 20,
    "URLDownloadToFileA": 20,
    "InternetOpenUrlW": 15,
    "InternetOpenUrlA": 15,
    "InternetReadFile": 15,
    "WinHttpOpen": 15,
    "WinHttpConnect": 15,
    "WinHttpSendRequest": 15,
    "socket": 10,
    "connect": 15,
    "recv": 10,
    "send": 10,
    "WSAStartup": 5,
    "CryptEncrypt": 20,
    "CryptDecrypt": 20,
    "BCryptEncrypt": 20,
    "BCryptDecrypt": 20,
    "RegSetValueExW": 20,
    "RegSetValueExA": 20,
    "RegCreateKeyExW": 20,
    "RegCreateKeyExA": 20,
    "CreateServiceW": 25,
    "CreateServiceA": 25,
    "StartServiceW": 20,
    "StartServiceA": 20,
    "OpenSCManagerW": 10,
    "OpenSCManagerA": 10,
    "IsDebuggerPresent": 10,
    "CheckRemoteDebuggerPresent": 15,
    "OutputDebugStringW": 10,
    "OutputDebugStringA": 10,
    "TerminateProcess": 10,
    "CreateFileW": 5,
    "WriteFile": 5,
    "ReadFile": 5
}

CAPABILITY_RULES = {
    "process_injection": {
        "apis": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtWriteVirtualMemory", "NtCreateThreadEx"],
        "min_matches": 2,
        "score": 40
    },
    "networking": {
        "apis": ["socket", "connect", "recv", "send", "WSAStartup", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW"],
        "min_matches": 2,
        "score": 20
    },
    "crypto": {
        "apis": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"],
        "min_matches": 1,
        "score": 20
    },
    "persistence": {
        "apis": ["RegSetValueExW", "RegSetValueExA", "RegCreateKeyExW", "RegCreateKeyExA", "CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "OpenSCManagerW", "OpenSCManagerA"],
        "min_matches": 1,
        "score": 25
    },
    "anti_analysis": {
        "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringW", "OutputDebugStringA"],
        "min_matches": 1,
        "score": 15
    }
}


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


def get_suspicious_apis(external_symbols):
    results = []

    for api_name in external_symbols:
        if api_name in SUSPICIOUS_API_WEIGHTS:
            results.append({
                "name": api_name,
                "weight": SUSPICIOUS_API_WEIGHTS[api_name]
            })

    return sorted(results, key=lambda x: (-x["weight"], x["name"]))


def detect_capabilities(external_symbols):
    symbol_set = set(external_symbols)
    capabilities = []

    for capability_name, rule in CAPABILITY_RULES.items():
        matched = []

        for api_name in rule["apis"]:
            if api_name in symbol_set:
                matched.append(api_name)

        if len(matched) >= rule["min_matches"]:
            capabilities.append({
                "name": capability_name,
                "matched_apis": sorted(matched),
                "score": rule["score"]
            })

    return sorted(capabilities, key=lambda x: (-x["score"], x["name"]))


def compute_overall_score(suspicious_apis, capabilities):
    score = 0

    for item in suspicious_apis:
        score += item["weight"]

    for capability in capabilities:
        score += capability["score"]

    return score


def get_risk_level(score):
    if score >= 120:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def build_summary(sample_name, external_symbols, suspicious_apis, capabilities, functions, strings, score, risk_level):
    return {
        "sample_name": sample_name,
        "risk_level": risk_level,
        "overall_score": score,
        "external_symbol_count": len(external_symbols),
        "suspicious_api_count": len(suspicious_apis),
        "capability_count": len(capabilities),
        "function_count": len(functions),
        "string_count": len(strings)
    }


def build_report():
    sample_name = currentProgram.getName()
    external_symbols = get_external_symbols()
    strings = get_strings()
    functions = get_functions()
    suspicious_apis = get_suspicious_apis(external_symbols)
    capabilities = detect_capabilities(external_symbols)
    overall_score = compute_overall_score(suspicious_apis, capabilities)
    risk_level = get_risk_level(overall_score)
    summary = build_summary(
        sample_name,
        external_symbols,
        suspicious_apis,
        capabilities,
        functions,
        strings,
        overall_score,
        risk_level
    )

    return {
        "sample": {
            "name": sample_name,
            "path": currentProgram.getExecutablePath() or "",
            "format": currentProgram.getExecutableFormat()
        },
        "summary": summary,
        "external_symbols": external_symbols,
        "suspicious_apis": suspicious_apis,
        "capabilities": capabilities,
        "strings": strings,
        "functions": functions
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