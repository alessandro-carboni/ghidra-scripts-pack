#@runtime pyghidra
#@author
#@category Triage
#@keybinding
#@menupath
#@toolbar

import os
import json


MAX_STRINGS = 400
MAX_STRING_LENGTH = 220
MAX_INTERESTING_STRINGS = 40
MAX_REFERENCED_STRINGS_PER_FUNCTION = 12
MAX_TOP_FUNCTIONS = 25
MAX_FLOW_PATHS = 30
MAX_THREE_HOP_FLOWS = 25

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
    "WinExec": 10,
    "ShellExecuteW": 4,
    "ShellExecuteA": 4,
    "CreateProcessW": 8,
    "CreateProcessA": 8,
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
    "RegSetValueExW": 5,
    "RegSetValueExA": 5,
    "RegCreateKeyExW": 5,
    "RegCreateKeyExA": 5,
    "CreateServiceW": 25,
    "CreateServiceA": 25,
    "StartServiceW": 20,
    "StartServiceA": 20,
    "OpenSCManagerW": 10,
    "OpenSCManagerA": 10,
    "IsDebuggerPresent": 3,
    "CheckRemoteDebuggerPresent": 8,
    "OutputDebugStringW": 1,
    "OutputDebugStringA": 1,
    "TerminateProcess": 5,
    "CreateFileW": 2,
    "CreateFileA": 2,
    "WriteFile": 2,
    "ReadFile": 2,
    "LoadLibraryW": 4,
    "LoadLibraryA": 4,
    "GetProcAddress": 3
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
        "apis": ["RegCreateKeyEx", "RegSetValueEx", "RegOpenKeyEx"],
        "min_matches": 3,
        "score": 15
    },

    "anti_analysis": {
        "apis": ["IsDebuggerPresent", "OutputDebugString", "CheckRemoteDebuggerPresent"],
        "min_matches": 3,
        "score": 8
    },
    "dynamic_loading": {
        "apis": ["LoadLibraryW", "LoadLibraryA", "GetProcAddress"],
        "min_matches": 3,
        "score": 10
    }
}

STRING_PATTERNS = {
    "url_or_network": {
        "keywords": ["http://", "https://", "ftp://", "www.", ".com", ".net", ".org", "user-agent", "host:", "cookie"],
        "score": 15,
        "tag": "networking"
    },
    "filesystem_path": {
        "keywords": ["c:\\", "\\users\\", "\\appdata\\", "\\temp\\", "\\windows\\", ".exe", ".bat", ".cmd", ".ps1"],
        "score": 10,
        "tag": "filesystem"
    },
    "registry": {
        "keywords": ["hkey_", "software\\microsoft\\windows\\currentversion\\run", "runonce", "regsvr32"],
        "score": 20,
        "tag": "persistence"
    },
    "crypto_ransom": {
        "keywords": ["aes", "rsa", "encrypt", "decrypt", "ransom", "bitcoin", "wallet"],
        "score": 12,
        "tag": "crypto"
    },
    "commands": {
        "keywords": ["cmd.exe", "powershell", "rundll32", "wmic", "schtasks", "bitsadmin", "certutil"],
        "score": 20,
        "tag": "execution"
    },
    "anti_analysis": {
        "keywords": ["sandbox", "debugger", "vmware", "virtualbox", "wireshark", "procmon", "ollydbg"],
        "score": 20,
        "tag": "anti_analysis"
    }
}

ROLE_API_MAP = {
    "loader": ["LoadLibraryW", "LoadLibraryA", "GetProcAddress"],
    "network": ["socket", "connect", "recv", "send", "WSAStartup", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW"],
    "persistence": ["RegSetValueExW", "RegSetValueExA", "RegCreateKeyExW", "RegCreateKeyExA", "CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "OpenSCManagerW", "OpenSCManagerA"],
    "anti_analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringW", "OutputDebugStringA"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"],
    "execution": ["CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteW", "ShellExecuteA"],
    "injection": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtWriteVirtualMemory", "NtCreateThreadEx"]
}

BENIGN_UI_APIS = set([
    "CreateWindowExW", "DialogBoxParamW", "DispatchMessageW", "TranslateMessage",
    "GetMessageW", "DefWindowProcW", "LoadCursorW", "LoadIconW", "BeginPaint",
    "EndPaint", "DrawTextW", "ShowWindow", "UpdateWindow", "CreateDialogParamW",
    "ChooseFontW", "PageSetupDlgW", "PrintDlgExW", "GetOpenFileNameW",
    "GetSaveFileNameW", "MessageBoxW"
])

BENIGN_SYSTEM_LIB_HINTS = set([
    "USER32", "GDI32", "COMDLG32", "COMCTL32", "SHELL32", "PROPSYS", "URLMON"
])

SUSPICIOUS_SECTION_NAMES = set([
    "UPX0", "UPX1", "UPX2",
    ".aspack", ".adata", ".packed", ".petite",
    ".boom", ".stub", ".themida", ".vmp0", ".vmp1", ".vmp2"
])

PACKER_API_HINTS = set([
    "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory",
    "LoadLibraryW", "LoadLibraryA",
    "GetProcAddress"
])

CLASSIC_UNPACKING_MNEMONICS = set([
    "PUSHAD", "PUSHA", "POPAD", "POPA", "JMP", "CALL"
])

SCHEMA_VERSION = "1.1.0"
ANALYSIS_MODE = "static_headless"

API_NORMALIZATION_MAP = {
    "CreateProcessA": "CreateProcess",
    "CreateProcessW": "CreateProcess",
    "ShellExecuteA": "ShellExecute",
    "ShellExecuteW": "ShellExecute",
    "URLDownloadToFileA": "URLDownloadToFile",
    "URLDownloadToFileW": "URLDownloadToFile",
    "InternetOpenUrlA": "InternetOpenUrl",
    "InternetOpenUrlW": "InternetOpenUrl",
    "RegSetValueExA": "RegSetValueEx",
    "RegSetValueExW": "RegSetValueEx",
    "RegCreateKeyExA": "RegCreateKeyEx",
    "RegCreateKeyExW": "RegCreateKeyEx",
    "CreateServiceA": "CreateService",
    "CreateServiceW": "CreateService",
    "StartServiceA": "StartService",
    "StartServiceW": "StartService",
    "OpenSCManagerA": "OpenSCManager",
    "OpenSCManagerW": "OpenSCManager",
    "OutputDebugStringA": "OutputDebugString",
    "OutputDebugStringW": "OutputDebugString",
    "LoadLibraryA": "LoadLibrary",
    "LoadLibraryW": "LoadLibrary",
    "CreateFileA": "CreateFile",
    "CreateFileW": "CreateFile"
}

BENIGN_STRING_KEYWORDS = [
    "microsoft",
    "notepad",
    "richedit",
    "comdlg",
    "print",
    "page setup",
    "font",
    "open file",
    "save file"
]


def canonicalize_api_name(name):
    if not name:
        return name
    return API_NORMALIZATION_MAP.get(name, name)


def normalize_api_list(api_list):
    normalized = set()
    for api_name in api_list:
        normalized.add(canonicalize_api_name(api_name))
    return sorted(normalized)


def build_capability_rule_index():
    idx = {}
    for capability_name, rule in CAPABILITY_RULES.items():
        normalized = set()
        for api_name in rule["apis"]:
            normalized.add(canonicalize_api_name(api_name))
        idx[capability_name] = {
            "apis": sorted(normalized),
            "min_matches": rule["min_matches"],
            "score": rule["score"]
        }
    return idx


NORMALIZED_CAPABILITY_RULES = build_capability_rule_index()


def count_matching_apis(api_names, candidate_names):
    api_set = set(normalize_api_list(api_names))
    candidate_set = set(normalize_api_list(candidate_names))
    return sorted(api_set & candidate_set)


def get_capability_confidence(match_count, min_matches):
    if match_count >= (min_matches + 2):
        return "high"
    if match_count >= (min_matches + 1):
        return "medium"
    return "low"


def has_any_keyword(value, keywords):
    lower_value = value.lower()
    for keyword in keywords:
        if keyword in lower_value:
            return True
    return False


def build_analysis_metadata():
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": ANALYSIS_MODE
    }
    
def safe_join(items, sep=", "):
    if not items:
        return ""
    return sep.join([str(x) for x in items if x is not None and str(x).strip() != ""])


def describe_function_brief(func):
    roles = safe_join(func.get("roles", []))
    structure_role = func.get("structure_role", "unknown")
    score = func.get("score", 0)

    parts = [f"{func['name']} (score={score}, structure={structure_role}"]
    if roles:
        parts.append(f", roles={roles}")
    parts.append(")")
    return "".join(parts)


def clean_string_value(value):
    value = value.strip()
    if value.startswith('u"') and value.endswith('"'):
        value = value[2:-1]
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value.strip()


def is_probably_boring_library_name(value):
    lower_value = value.lower()
    return lower_value.endswith(".dll") and "\\" not in lower_value and "/" not in lower_value


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

    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)

    for data in data_iter:
        try:
            data_type = data.getDataType()
            if data_type is None:
                continue

            type_name = data_type.getName().lower()
            if "string" not in type_name and "unicode" not in type_name and "terminated" not in type_name:
                continue

            value = data.getDefaultValueRepresentation()
        except:
            continue

        if not value:
            continue

        value = clean_string_value(str(value))

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


def get_base_functions():
    functions = []
    function_manager = currentProgram.getFunctionManager()

    for func in function_manager.getFunctions(True):
        functions.append({
            "name": func.getName(),
            "entry": str(func.getEntryPoint()),
            "external": func.isExternal(),
            "thunk": func.isThunk(),
            "internal_calls": [],
            "external_calls": [],
            "incoming_calls": 0,
            "referenced_strings": [],
            "matched_capabilities": [],
            "roles": [],
            "structure_role": "unknown",
            "tags": [],
            "score": 0,
            "risk_level": "low"
        })

    return functions


def get_suspicious_apis(external_symbols):
    aggregated = {}

    for api_name in external_symbols:
        canonical = canonicalize_api_name(api_name)
        if api_name in SUSPICIOUS_API_WEIGHTS:
            weight = SUSPICIOUS_API_WEIGHTS[api_name]
        elif canonical in SUSPICIOUS_API_WEIGHTS:
            weight = SUSPICIOUS_API_WEIGHTS[canonical]
        else:
            continue

        if canonical not in aggregated or weight > aggregated[canonical]["weight"]:
            aggregated[canonical] = {
                "name": canonical,
                "weight": weight,
                "variants": set([api_name])
            }
        else:
            aggregated[canonical]["variants"].add(api_name)

    results = []
    for item in aggregated.values():
        results.append({
            "name": item["name"],
            "weight": item["weight"],
            "variants": sorted(item["variants"])
        })

    return sorted(results, key=lambda x: (-x["weight"], x["name"]))


def detect_capabilities(external_symbols):
    normalized_symbols = normalize_api_list(external_symbols)
    symbol_set = set(normalized_symbols)
    capabilities = []

    for capability_name, rule in NORMALIZED_CAPABILITY_RULES.items():
        matched = []

        for api_name in rule["apis"]:
            if api_name in symbol_set:
                matched.append(api_name)

        if len(matched) >= rule["min_matches"]:
            confidence = get_capability_confidence(len(matched), rule["min_matches"])

            score = rule["score"]
            if confidence == "medium":
                score += 5
            elif confidence == "high":
                score += 10

            capabilities.append({
                "name": capability_name,
                "matched_apis": sorted(matched),
                "match_count": len(matched),
                "min_matches": rule["min_matches"],
                "confidence": confidence,
                "score": score,
                "source": "global_import_surface"
            })

    return sorted(capabilities, key=lambda x: (-x["score"], x["name"]))


def analyze_interesting_strings(strings):
    interesting = []

    for item in strings:
        value = item["value"]
        lower_value = value.lower()

        if is_probably_boring_library_name(value):
            continue

        if len(value.strip()) < 5:
            continue

        matched_tags = set()
        score = 0
        reasons = []
        benign_hits = 0

        for rule_name, rule in STRING_PATTERNS.items():
            matched_keywords = []

            for keyword in rule["keywords"]:
                if keyword in lower_value:
                    matched_keywords.append(keyword)

            if matched_keywords:
                rule_score = rule["score"]

                # deboost di pattern troppo generici
                if rule_name == "filesystem_path" and len(matched_keywords) == 1:
                    rule_score = max(4, rule_score - 6)

                if rule_name == "url_or_network":
                    # domini e pattern generici spesso sono benigni
                    generic_only = True
                    for k in matched_keywords:
                        if k in ["http://", "https://", "user-agent", "host:", "cookie"]:
                            generic_only = False
                            break
                    if generic_only:
                        rule_score = max(5, rule_score - 8)

                matched_tags.add(rule["tag"])
                score += rule_score
                reasons.append({
                    "rule": rule_name,
                    "keywords": sorted(set(matched_keywords)),
                    "score": rule_score
                })

        if has_any_keyword(value, BENIGN_STRING_KEYWORDS):
            benign_hits += 1

        if lower_value.startswith("prop:system."):
            benign_hits += 1

        if "windows.security." in lower_value:
            benign_hits += 1

        if "microsoft." in lower_value:
            benign_hits += 1

        if benign_hits > 0:
            benign_penalty = min(18, benign_hits * 8)
            score -= benign_penalty
            reasons.append({
                "rule": "benign_ui_or_vendor_hint",
                "keywords": [],
                "score": -benign_penalty
            })

        if score > 0:
            interesting.append({
                "address": item["address"],
                "value": value,
                "tags": sorted(matched_tags),
                "score": score,
                "reasons": reasons,
                "benign_hint": benign_hits > 0
            })

    interesting = sorted(interesting, key=lambda x: (-x["score"], x["value"]))
    return interesting[:MAX_INTERESTING_STRINGS]


def get_function_risk_level(score):
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def detect_function_roles(external_calls, tags):
    roles = set()
    external_call_set = set(external_calls)
    tag_set = set(tags)

    for role_name, api_list in ROLE_API_MAP.items():
        for api_name in api_list:
            if api_name in external_call_set:
                roles.add(role_name)
                break

    if "networking" in tag_set:
        roles.add("network")
    if "persistence" in tag_set:
        roles.add("persistence")
    if "anti_analysis" in tag_set:
        roles.add("anti_analysis")
    if "crypto" in tag_set:
        roles.add("crypto")
    if "execution" in tag_set:
        roles.add("execution")
    if "filesystem" in tag_set and "loader" in roles:
        roles.add("loader")

    return sorted(roles)


def enrich_functions(base_functions, interesting_strings):
    listing = currentProgram.getListing()
    reference_manager = currentProgram.getReferenceManager()
    function_manager = currentProgram.getFunctionManager()

    interesting_string_map = {}
    for item in interesting_strings:
        interesting_string_map[item["address"]] = item

    enriched = []

    for base_func in base_functions:
        entry_addr = toAddr(base_func["entry"])
        func = function_manager.getFunctionAt(entry_addr)

        if func is None:
            enriched.append(base_func)
            continue

        external_calls = set()
        internal_calls = set()
        referenced_string_values = []
        referenced_string_tags = set()
        local_capabilities = set()
        local_score = 0
        seen_string_addresses = set()
        score_breakdown = []
        local_api_hits = set()

        instructions = listing.getInstructions(func.getBody(), True)

        for instr in instructions:
            refs = reference_manager.getReferencesFrom(instr.getAddress())

            for ref in refs:
                to_addr = ref.getToAddress()
                if to_addr is None:
                    continue

                to_addr_str = str(to_addr)

                target_func = function_manager.getFunctionAt(to_addr)
                if target_func is None:
                    target_func = function_manager.getFunctionContaining(to_addr)

                if target_func is not None:
                    target_name = target_func.getName()
                    canonical_target = canonicalize_api_name(target_name)

                    if target_name in SUSPICIOUS_API_WEIGHTS:
                        api_weight = SUSPICIOUS_API_WEIGHTS[target_name]
                        local_score += api_weight
                        score_breakdown.append({
                            "type": "suspicious_api",
                            "name": canonical_target,
                            "delta": api_weight,
                            "reason": "local reference to suspicious API"
                        })
                        local_api_hits.add(canonical_target)
                    elif canonical_target in SUSPICIOUS_API_WEIGHTS:
                        api_weight = SUSPICIOUS_API_WEIGHTS[canonical_target]
                        local_score += api_weight
                        score_breakdown.append({
                            "type": "suspicious_api",
                            "name": canonical_target,
                            "delta": api_weight,
                            "reason": "local reference to suspicious API variant"
                        })
                        local_api_hits.add(canonical_target)

                    for capability_name, rule in NORMALIZED_CAPABILITY_RULES.items():
                        if canonical_target in rule["apis"]:
                            local_capabilities.add(capability_name)

                    if target_func.isExternal() or target_func.isThunk():
                        external_calls.add(canonical_target)
                    else:
                        if target_name != func.getName():
                            internal_calls.add(target_name)

                if to_addr_str in interesting_string_map and to_addr_str not in seen_string_addresses:
                    string_item = interesting_string_map[to_addr_str]
                    string_score = min(string_item["score"], 15)

                    referenced_string_values.append({
                        "address": string_item["address"],
                        "value": string_item["value"],
                        "score": string_item["score"],
                        "tags": string_item["tags"],
                        "benign_hint": string_item.get("benign_hint", False)
                    })
                    seen_string_addresses.add(to_addr_str)

                    if not string_item.get("benign_hint", False):
                        local_score += string_score
                        score_breakdown.append({
                            "type": "interesting_string",
                            "name": string_item["value"][:80],
                            "delta": string_score,
                            "reason": "function references interesting string"
                        })

                    for tag in string_item["tags"]:
                        referenced_string_tags.add(tag)

        local_capability_bonus = 0
        for capability_name in sorted(local_capabilities):
            local_capability_bonus += 3

        local_capability_bonus = min(local_capability_bonus, 9)
        if local_capability_bonus > 0:
            local_score += local_capability_bonus
            score_breakdown.append({
                "type": "local_capabilities",
                "name": ",".join(sorted(local_capabilities)),
                "delta": local_capability_bonus,
                "reason": "multiple capability-related local signals"
            })

        all_tags = set(local_capabilities) | set(referenced_string_tags)
        roles = detect_function_roles(external_calls, all_tags)

        connectivity_bonus = 0
        if len(internal_calls) >= 15:
            connectivity_bonus += 2
        if len(external_calls) >= 30:
            connectivity_bonus += 2
        if connectivity_bonus > 0:
            local_score += connectivity_bonus
            score_breakdown.append({
                "type": "connectivity",
                "name": func.getName(),
                "delta": connectivity_bonus,
                "reason": "high local fan-out"
            })

        local_benign_adjustment = 0
        if "persistence" in local_capabilities and len(local_api_hits) <= 2:
            local_benign_adjustment -= 12

        if "anti_analysis" in local_capabilities and len(local_api_hits) <= 2:
            local_benign_adjustment -= 10

        if "dynamic_loading" in local_capabilities and "loader" in roles and len(local_api_hits) <= 3:
            local_benign_adjustment -= 10

        # dispatcher molto ampi ma con pochi segnali reali spesso sono normali orchestratori GUI/app
        if (
            len(internal_calls) >= 20 and
            len(external_calls) >= 20 and
            len(local_api_hits) <= 2 and
            len(local_capabilities) <= 1 and
            len(referenced_string_values) == 0
        ):
            local_benign_adjustment -= 10

        if local_benign_adjustment != 0:
            local_score += local_benign_adjustment
            score_breakdown.append({
                "type": "benign_adjustment",
                "name": func.getName(),
                "delta": local_benign_adjustment,
                "reason": "weak isolated signal adjusted downward"
            })

        if local_score < 0:
            local_score = 0

        if local_score > 45:
            local_score = 45

        enriched.append({
            "name": func.getName(),
            "entry": str(func.getEntryPoint()),
            "external": func.isExternal(),
            "thunk": func.isThunk(),
            "internal_calls": sorted(internal_calls),
            "external_calls": sorted(external_calls),
            "incoming_calls": 0,
            "referenced_strings": sorted(
                referenced_string_values,
                key=lambda x: (-x["score"], x["value"])
            )[:MAX_REFERENCED_STRINGS_PER_FUNCTION],
            "matched_capabilities": sorted(local_capabilities),
            "roles": roles,
            "structure_role": "unknown",
            "tags": sorted(all_tags),
            "local_api_hits": sorted(local_api_hits),
            "score_breakdown": score_breakdown,
            "score": local_score,
            "risk_level": get_function_risk_level(local_score)
        })

    return sorted(enriched, key=lambda x: (-x["score"], x["name"]))


def apply_incoming_call_counts(functions):
    counts = {}
    for func in functions:
        counts[func["name"]] = 0

    for func in functions:
        for callee in func["internal_calls"]:
            if callee in counts:
                counts[callee] += 1

    updated = []
    for func in functions:
        new_func = dict(func)
        new_func["incoming_calls"] = counts.get(func["name"], 0)
        updated.append(new_func)

    return updated


def assign_structure_roles(functions):
    updated = []

    for func in functions:
        internal_out = len(func["internal_calls"])
        external_out = len(func["external_calls"])
        incoming = func["incoming_calls"]
        total_out = internal_out + external_out

        structure_role = "leaf"

        if incoming == 0 and total_out >= 8:
            structure_role = "initializer"
        elif internal_out >= 8 and total_out >= 15:
            structure_role = "dispatcher"
        elif internal_out >= 3 and external_out >= 3:
            structure_role = "worker"
        elif total_out >= 6:
            structure_role = "worker"

        new_func = dict(func)
        new_func["structure_role"] = structure_role
        updated.append(new_func)

    return updated


def build_top_functions(functions):
    ranked = []

    for func in functions:
        if func["score"] > 0:
            ranked.append({
                "name": func["name"],
                "entry": func["entry"],
                "score": func["score"],
                "risk_level": func["risk_level"],
                "roles": func["roles"],
                "structure_role": func["structure_role"],
                "incoming_calls": func["incoming_calls"],
                "external_call_count": len(func["external_calls"]),
                "internal_call_count": len(func["internal_calls"]),
                "referenced_string_count": len(func["referenced_strings"]),
                "tags": func["tags"]
            })

    return ranked[:MAX_TOP_FUNCTIONS]


def build_callgraph(functions):
    nodes = []
    edges = []

    for func in functions:
        nodes.append({
            "name": func["name"],
            "entry": func["entry"],
            "score": func["score"],
            "risk_level": func["risk_level"],
            "roles": func["roles"],
            "structure_role": func["structure_role"],
            "incoming_calls": func["incoming_calls"]
        })

        for callee in func["internal_calls"]:
            edges.append({
                "from": func["name"],
                "to": callee,
                "type": "internal_call"
            })

        for callee in func["external_calls"]:
            edges.append({
                "from": func["name"],
                "to": callee,
                "type": "external_call"
            })

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes[:250],
        "edges": edges[:800]
    }


def build_behavior_clusters(functions):
    clusters = {}
    for role_name in ROLE_API_MAP.keys():
        clusters[role_name] = []

    for func in functions:
        for role in func["roles"]:
            if role not in clusters:
                clusters[role] = []
            clusters[role].append({
                "name": func["name"],
                "entry": func["entry"],
                "score": func["score"],
                "risk_level": func["risk_level"],
                "structure_role": func["structure_role"]
            })

    for role_name in clusters.keys():
        clusters[role_name] = sorted(
            clusters[role_name],
            key=lambda x: (-x["score"], x["name"])
        )[:10]

    return clusters


def build_function_index(functions):
    idx = {}
    for func in functions:
        idx[func["name"]] = func
    return idx


def build_execution_flow_hypotheses(functions):
    function_index = build_function_index(functions)

    seeds = []
    for func in functions:
        if func["score"] >= 15 or len(func["roles"]) > 0:
            seeds.append(func)

    seeds = seeds[:50]
    paths = []

    for func in seeds:
        if len(func["internal_calls"]) == 0:
            continue

        for callee_name in func["internal_calls"][:10]:
            callee = function_index.get(callee_name)
            if callee is None:
                continue

            path_roles = list(dict.fromkeys(func["roles"] + callee["roles"]))
            path_score = func["score"] + callee["score"]

            if path_score < 20 and len(path_roles) == 0:
                continue

            description_parts = [
                f"{func['name']} -> {callee['name']}",
                f"combined_score={path_score}",
                f"from_structure={func['structure_role']}",
                f"to_structure={callee['structure_role']}"
            ]

            if path_roles:
                description_parts.append(f"roles={safe_join(path_roles)}")

            paths.append({
                "from": func["name"],
                "to": callee["name"],
                "combined_score": path_score,
                "from_roles": func["roles"],
                "to_roles": callee["roles"],
                "path_roles": path_roles,
                "from_structure_role": func["structure_role"],
                "to_structure_role": callee["structure_role"],
                "description": "; ".join(description_parts)
            })

    paths = sorted(paths, key=lambda x: (-x["combined_score"], x["from"], x["to"]))
    return paths[:MAX_FLOW_PATHS]


def build_three_hop_flows(functions):
    function_index = build_function_index(functions)
    flows = []

    candidate_functions = [f for f in functions if f["score"] >= 20 or len(f["roles"]) > 0]
    candidate_functions = candidate_functions[:35]

    for a in candidate_functions:
        for b_name in a["internal_calls"][:6]:
            b = function_index.get(b_name)
            if b is None:
                continue

            for c_name in b["internal_calls"][:6]:
                c = function_index.get(c_name)
                if c is None:
                    continue

                if c["name"] == a["name"]:
                    continue

                roles = []
                for item in a["roles"] + b["roles"] + c["roles"]:
                    if item not in roles:
                        roles.append(item)

                combined_score = a["score"] + b["score"] + c["score"]

                if combined_score < 35 and len(roles) == 0:
                    continue

                flows.append({
                    "path": [a["name"], b["name"], c["name"]],
                    "combined_score": combined_score,
                    "roles": roles,
                    "structure_roles": [a["structure_role"], b["structure_role"], c["structure_role"]]
                })

    flows = sorted(flows, key=lambda x: (-x["combined_score"], x["path"][0], x["path"][1], x["path"][2]))
    return flows[:MAX_THREE_HOP_FLOWS]


def build_function_role_summary(functions):
    summary = {
        "by_structure_role": {},
        "by_behavior_role": {}
    }

    for func in functions:
        sr = func["structure_role"]
        summary["by_structure_role"][sr] = summary["by_structure_role"].get(sr, 0) + 1

        for role in func["roles"]:
            summary["by_behavior_role"][role] = summary["by_behavior_role"].get(role, 0) + 1

    return summary


def build_behavior_summary(functions, capabilities, flow_hypotheses, three_hop_flows):
    high_risk_functions = []
    hub_functions = []
    role_counts = {}

    for func in functions:
        for role in func["roles"]:
            role_counts[role] = role_counts.get(role, 0) + 1

        if func["risk_level"] in ["high", "critical"]:
            high_risk_functions.append({
                "name": func["name"],
                "score": func["score"],
                "risk_level": func["risk_level"],
                "roles": func["roles"],
                "structure_role": func["structure_role"]
            })

        connectivity = len(func["internal_calls"]) + len(func["external_calls"])
        if connectivity >= 12 and (func["score"] >= 15 or len(func["roles"]) > 0):
            hub_functions.append({
                "name": func["name"],
                "score": func["score"],
                "risk_level": func["risk_level"],
                "roles": func["roles"],
                "structure_role": func["structure_role"],
                "connectivity": connectivity,
                "incoming_calls": func["incoming_calls"]
            })

    inferred_behaviors = []

    capability_names = [c["name"] for c in capabilities]

    if "process_injection" in capability_names:
        inferred_behaviors.append("possible process injection workflow")
    if "networking" in capability_names:
        inferred_behaviors.append("network communication capability present")
    if "persistence" in capability_names:
        inferred_behaviors.append("persistence-related activity present")
    if "anti_analysis" in capability_names:
        inferred_behaviors.append("anti-analysis or debugger-awareness present")
    if "crypto" in capability_names:
        inferred_behaviors.append("cryptographic functionality present")

    if role_counts.get("loader", 0) > 0 and role_counts.get("execution", 0) > 0:
        inferred_behaviors.append("loader/execution chain likely present")

    if role_counts.get("network", 0) > 0 and role_counts.get("persistence", 0) > 0:
        inferred_behaviors.append("network + persistence combination detected")

    if role_counts.get("loader", 0) > 0 and role_counts.get("injection", 0) > 0:
        inferred_behaviors.append("dynamic loading plus injection primitives detected")

    if len(three_hop_flows) > 0:
        inferred_behaviors.append("multi-stage internal control flow detected")

    return {
        "role_counts": role_counts,
        "high_risk_functions": high_risk_functions[:12],
        "hub_functions": sorted(hub_functions, key=lambda x: (-x["connectivity"], -x["incoming_calls"], -x["score"], x["name"]))[:12],
        "flow_hypothesis_count": len(flow_hypotheses),
        "three_hop_flow_count": len(three_hop_flows),
        "inferred_behaviors": inferred_behaviors
    }


def build_behavior_story(functions, flow_hypotheses, three_hop_flows):
    story = {
        "entry_candidates": [],
        "primary_dispatchers": [],
        "notable_workers": [],
        "storyline": [],
        "story_summary": []
    }

    initializers = sorted(
        [f for f in functions if f["structure_role"] == "initializer"],
        key=lambda x: (-x["score"], -len(x["internal_calls"]), x["name"])
    )

    dispatchers = sorted(
        [f for f in functions if f["structure_role"] == "dispatcher"],
        key=lambda x: (-(len(x["internal_calls"]) + len(x["external_calls"])), -x["score"], x["name"])
    )

    workers = sorted(
        [f for f in functions if f["structure_role"] == "worker" and (f["score"] >= 10 or len(f["roles"]) > 0)],
        key=lambda x: (-x["score"], -x["incoming_calls"], x["name"])
    )

    story["entry_candidates"] = [
        {
            "name": f["name"],
            "score": f["score"],
            "roles": f["roles"],
            "structure_role": f["structure_role"],
            "incoming_calls": f["incoming_calls"],
            "fan_out": len(f["internal_calls"]) + len(f["external_calls"])
        }
        for f in initializers[:8]
    ]

    story["primary_dispatchers"] = [
        {
            "name": f["name"],
            "score": f["score"],
            "roles": f["roles"],
            "structure_role": f["structure_role"],
            "fan_out": len(f["internal_calls"]) + len(f["external_calls"]),
            "incoming_calls": f["incoming_calls"]
        }
        for f in dispatchers[:8]
    ]

    story["notable_workers"] = [
        {
            "name": f["name"],
            "score": f["score"],
            "roles": f["roles"],
            "structure_role": f["structure_role"],
            "incoming_calls": f["incoming_calls"]
        }
        for f in workers[:12]
    ]

    for flow in three_hop_flows[:10]:
        path = flow["path"]
        roles = flow["roles"]
        structure_roles = flow["structure_roles"]

        role_text = safe_join(roles) if len(roles) > 0 else "no explicit behavioral roles"
        structure_text = " -> ".join(structure_roles)

        story["storyline"].append({
            "type": "three_hop_flow",
            "path": path,
            "combined_score": flow["combined_score"],
            "description": f"{' -> '.join(path)} | roles: {role_text} | structure: {structure_text}"
        })

    if len(story["storyline"]) == 0:
        for flow in flow_hypotheses[:10]:
            role_text = safe_join(flow["path_roles"]) if len(flow["path_roles"]) > 0 else "no explicit behavioral roles"
            story["storyline"].append({
                "type": "two_hop_flow",
                "path": [flow["from"], flow["to"]],
                "combined_score": flow["combined_score"],
                "description": f"{flow['from']} -> {flow['to']} | roles: {role_text} | structure: {flow['from_structure_role']} -> {flow['to_structure_role']}"
            })

    if len(story["entry_candidates"]) > 0:
        first_entry = story["entry_candidates"][0]
        story["story_summary"].append(
            f"Likely execution starts around {first_entry['name']} (score={first_entry['score']}, fan_out={first_entry['fan_out']})."
        )

    if len(story["primary_dispatchers"]) > 0:
        first_dispatcher = story["primary_dispatchers"][0]
        dispatcher_roles = safe_join(first_dispatcher["roles"])
        if dispatcher_roles:
            story["story_summary"].append(
                f"Primary dispatcher candidate is {first_dispatcher['name']} with roles: {dispatcher_roles}."
            )
        else:
            story["story_summary"].append(
                f"Primary dispatcher candidate is {first_dispatcher['name']}."
            )

    if len(story["notable_workers"]) > 0:
        top_workers = [w["name"] for w in story["notable_workers"][:3]]
        story["story_summary"].append(
            f"Most notable worker functions: {safe_join(top_workers)}."
        )

    if len(story["storyline"]) > 0:
        first_line = story["storyline"][0]
        story["story_summary"].append(
            f"Best reconstructed flow: {first_line['description']}."
        )

    return story


def detect_benign_contexts(external_symbols, interesting_strings, functions):
    contexts = []
    symbol_set = set(normalize_api_list(external_symbols))
    symbol_count = len(external_symbols)

    ui_hits = len([canonicalize_api_name(x) for x in external_symbols if x in BENIGN_UI_APIS])
    loader_hits = len(count_matching_apis(external_symbols, ["LoadLibrary", "GetProcAddress"]))
    create_file_hits = len(count_matching_apis(external_symbols, ["CreateFile", "ReadFile", "WriteFile"]))

    microsoft_urls = 0
    benign_string_count = 0
    for item in interesting_strings:
        value = item["value"].lower()
        if "microsoft.com" in value or "go.microsoft.com" in value:
            microsoft_urls += 1
        if item.get("benign_hint", False):
            benign_string_count += 1

    high_risk_function_count = len([f for f in functions if f["risk_level"] in ["high", "critical"]])
    medium_or_higher_count = len([f for f in functions if f["risk_level"] in ["medium", "high", "critical"]])
    persistence_functions = len([f for f in functions if "persistence" in f["roles"]])
    anti_analysis_functions = len([f for f in functions if "anti_analysis" in f["roles"]])
    injection_functions = len([f for f in functions if "injection" in f["roles"]])

    if ui_hits >= 8 and symbol_count > 120:
        contexts.append({
            "name": "rich_windows_gui_context",
            "score_adjustment": -35,
            "reason": "many GUI/UI APIs usually associated with benign Windows applications"
        })

    if loader_hits >= 2 and microsoft_urls > 0:
        contexts.append({
            "name": "benign_dynamic_loading_context",
            "score_adjustment": -20,
            "reason": "dynamic loading appears together with Microsoft-related strings"
        })

    if create_file_hits >= 2 and ui_hits >= 5:
        contexts.append({
            "name": "desktop_app_file_io_context",
            "score_adjustment": -12,
            "reason": "file I/O appears together with a desktop GUI profile"
        })

    if persistence_functions > 0 and persistence_functions <= 3 and injection_functions == 0:
        contexts.append({
            "name": "weak_persistence_signal",
            "score_adjustment": -15,
            "reason": "persistence-like APIs appear but only in a limited and non-cohesive way"
        })

    if anti_analysis_functions > 0 and anti_analysis_functions <= 3 and high_risk_function_count == 0:
        contexts.append({
            "name": "weak_anti_analysis_signal",
            "score_adjustment": -12,
            "reason": "debug-related APIs may reflect diagnostics or normal defensive logic"
        })

    if high_risk_function_count == 0:
        contexts.append({
            "name": "no_high_risk_functions",
            "score_adjustment": -15,
            "reason": "no function reached a high local risk threshold"
        })

    if medium_or_higher_count <= 2 and benign_string_count >= 2:
        contexts.append({
            "name": "benign_string_context",
            "score_adjustment": -10,
            "reason": "interesting strings contain multiple benign vendor/UI hints"
        })
        
    if ui_hits >= 10 and symbol_count >= 150:
        contexts.append({
            "name": "microsoft_desktop_app_profile",
            "score_adjustment": -20,
            "reason": "strong desktop/UI profile consistent with benign Microsoft desktop software"
        })

    return contexts

def compute_raw_score(suspicious_apis, capabilities, interesting_strings, top_functions, packer_analysis):
    score = 0

    # import globali: contano, ma molto meno di prima
    for item in suspicious_apis[:12]:
        score += min(item["weight"], 12)

    # capability globali: contano, ma non devono dominare da sole
    for capability in capabilities:
        score += min(capability["score"], 30)

    # stringhe: cap limit più basso
    for string_item in interesting_strings[:25]:
        if not string_item.get("benign_hint", False):
            score += min(string_item["score"], 12)

    # funzioni locali: sono il segnale più affidabile
    for func in top_functions[:6]:
        score += min(func["score"], 14)

    # packer: boost contenuto
    score += min(packer_analysis.get("packed_likelihood_score", 0), 25)

    return score


def apply_score_adjustments(raw_score, benign_contexts):
    adjusted = raw_score
    adjustments = []

    for ctx in benign_contexts:
        adjusted += ctx["score_adjustment"]
        adjustments.append({
            "name": ctx["name"],
            "delta": ctx["score_adjustment"],
            "reason": ctx["reason"]
        })

    if adjusted < 0:
        adjusted = 0

    return adjusted, adjustments


def get_risk_level(score):
    if score >= 120:
        return "critical"
    if score >= 85:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def build_top_indicators(suspicious_apis, capabilities, interesting_strings, top_functions):
    indicators = []

    for capability in capabilities[:5]:
        indicators.append("capability:{} (+{})".format(capability["name"], capability["score"]))

    for api in suspicious_apis[:5]:
        indicators.append("api:{} (+{})".format(api["name"], api["weight"]))

    for func in top_functions[:5]:
        indicators.append("function:{} (+{})".format(func["name"], func["score"]))

    for string_item in interesting_strings[:5]:
        indicators.append("string:{} (+{})".format(string_item["value"][:60], string_item["score"]))

    return indicators[:12]


def build_summary(sample_name, external_symbols, suspicious_apis, capabilities, functions, strings, interesting_strings, top_functions, raw_score, adjusted_score, risk_level, score_adjustments, packer_analysis):
    packed_warning = None

    if packer_analysis.get("likely_packed", False):
        packed_warning = (
            "This file appears to be packed. Static risk level, score, strings, and behavioral inference "
            "should be interpreted with caution because packing can hide or distort the program's real behavior."
        )

    return {
        "sample_name": sample_name,
        "packed_warning": packed_warning,
        "risk_level": risk_level,
        "overall_score": adjusted_score,
        "raw_score": raw_score,
        "score_adjustment_total": adjusted_score - raw_score,
        "adjustment_count": len(score_adjustments),
        "external_symbol_count": len(external_symbols),
        "suspicious_api_count": len(suspicious_apis),
        "capability_count": len(capabilities),
        "function_count": len(functions),
        "string_count": len(strings),
        "interesting_string_count": len(interesting_strings),
        "top_function_count": len(top_functions),
        "top_indicators": build_top_indicators(suspicious_apis, capabilities, interesting_strings, top_functions),
        "contract_version": SCHEMA_VERSION
    }

def build_analyst_summary(summary, behavior_summary, capabilities, top_functions, score_adjustments):
    key_points = []

    if summary.get("packed_warning"):
        key_points.append("Packed-sample caution: static findings may not fully reflect the program's real runtime behavior.")

    key_points.append(
        f"Overall risk classified as {summary['risk_level']} with final score {summary['overall_score']}."
    )

    if len(capabilities) > 0:
        cap_names = [c["name"] for c in capabilities[:5]]
        key_points.append(f"Detected capabilities: {safe_join(cap_names)}.")

    if len(behavior_summary["inferred_behaviors"]) > 0:
        key_points.append(
            f"Behavioral inference: {'; '.join(behavior_summary['inferred_behaviors'][:4])}."
        )

    if len(score_adjustments) > 0:
        key_points.append("Score adjusted by contextual benign indicators.")

    if len(top_functions) > 0:
        names = [f["name"] for f in top_functions[:3]]
        key_points.append(f"Priority functions for review: {safe_join(names)}.")

    return {
        "key_points": key_points,
        "primary_conclusion": key_points[0] if len(key_points) > 0 else "No conclusion."
    }

def safe_block_name(block):
    if block is None:
        return "unknown"
    try:
        return block.getName()
    except:
        return "unknown"


def collect_section_info():
    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    results = []

    for block in blocks:
        try:
            name = block.getName()
            start = str(block.getStart())
            end = str(block.getEnd())
            size = int(block.getSize())
            read = bool(block.isRead())
            write = bool(block.isWrite())
            execute = bool(block.isExecute())
            initialized = bool(block.isInitialized())
        except:
            continue

        suspicious = False
        reasons = []

        lower_name = name.lower() if name else ""

        if name in SUSPICIOUS_SECTION_NAMES:
            suspicious = True
            reasons.append("suspicious section name")

        if execute and write:
            suspicious = True
            reasons.append("section is executable and writable")

        if size == 0:
            reasons.append("empty section")

        if not initialized and execute:
            suspicious = True
            reasons.append("executable but uninitialized block")

        if lower_name in [".text", ".rdata", ".data", ".rsrc", ".idata", ".reloc"]:
            pass
        else:
            if execute and size < 1024:
                suspicious = True
                reasons.append("small executable non-standard section")

        results.append({
            "name": name,
            "start": start,
            "end": end,
            "size": size,
            "read": read,
            "write": write,
            "execute": execute,
            "initialized": initialized,
            "suspicious": suspicious,
            "reasons": reasons
        })

    return results


def get_program_entrypoint():
    symbol_table = currentProgram.getSymbolTable()

    try:
        entry_iter = symbol_table.getExternalEntryPointIterator()
        for addr in entry_iter:
            if addr is not None:
                return addr
    except:
        pass

    try:
        image_base = currentProgram.getImageBase()
        if image_base is not None:
            return image_base
    except:
        pass

    try:
        min_addr = currentProgram.getMinAddress()
        if min_addr is not None:
            return min_addr
    except:
        pass

    return None

def get_entrypoint_info():
    entry = get_program_entrypoint()
    memory = currentProgram.getMemory()

    if entry is None:
        return {
            "address": None,
            "section": "unknown",
            "section_is_executable": False,
            "section_is_writable": False
        }

    block = memory.getBlock(entry)

    return {
        "address": str(entry),
        "section": safe_block_name(block),
        "section_is_executable": bool(block.isExecute()) if block else False,
        "section_is_writable": bool(block.isWrite()) if block else False
    }

def collect_entrypoint_instruction_window(max_instructions=25):
    listing = currentProgram.getListing()
    entry = get_program_entrypoint()

    results = []

    if entry is None:
        return results

    instr = listing.getInstructionAt(entry)

    count = 0
    while instr is not None and count < max_instructions:
        results.append({
            "address": str(instr.getAddress()),
            "mnemonic": instr.getMnemonicString(),
            "text": str(instr)
        })
        instr = instr.getNext()
        count += 1

    return results


def detect_classic_unpacking_patterns(entry_window):
    findings = []

    mnemonics = [item["mnemonic"].upper() for item in entry_window]

    if "PUSHAD" in mnemonics or "PUSHA" in mnemonics:
        findings.append({
            "name": "pushad_pusha_near_entry",
            "score": 20,
            "reason": "classic packer stub pattern near entrypoint"
        })

    if "POPAD" in mnemonics or "POPA" in mnemonics:
        findings.append({
            "name": "popad_popa_near_entry",
            "score": 20,
            "reason": "classic unpacking transition pattern near entrypoint"
        })

    return findings


def find_oep_candidates(entrypoint_info):
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    entry = get_program_entrypoint()

    candidates = []
    seen = set()

    if entry is None:
        return candidates

    instr = listing.getInstructionAt(entry)
    scanned = 0

    while instr is not None and scanned < 120:
        mnemonic = instr.getMnemonicString().upper()

        if mnemonic in ["JMP", "CALL"]:
            try:
                flows = instr.getFlows()
            except:
                flows = []

            for target in flows:
                if target is None:
                    continue

                target_str = str(target)
                if target_str in seen:
                    continue

                # escludi target esterni/non utili per OEP recovery
                if target_str.startswith("EXTERNAL:"):
                    continue

                target_block = memory.getBlock(target)
                target_section = safe_block_name(target_block)
                same_section = (target_section == entrypoint_info["section"])

                # se non appartiene a un block reale, non è un buon candidato OEP
                if target_block is None:
                    continue

                reason_parts = []
                score = 0

                if not same_section:
                    if mnemonic == "JMP":
                        reason_parts.append("unconditional jump from entry stub to different section")
                        score += 35
                    elif mnemonic == "CALL":
                        reason_parts.append("call target from entry stub to different section")
                        score += 18

                    if target_block.isExecute():
                        reason_parts.append("target section executable")
                        score += 10
                    else:
                        # se non è eseguibile non è un buon OEP candidate
                        continue

                    if target_section == ".text":
                        reason_parts.append("target section is .text")
                        score += 20

                    if target_section not in SUSPICIOUS_SECTION_NAMES and target_section != "unknown":
                        reason_parts.append("target section is non-stub/non-suspicious")
                        score += 10
                else:
                    if mnemonic == "JMP":
                        reason_parts.append("jump stays inside same section")
                        score += 3
                    elif mnemonic == "CALL":
                        reason_parts.append("call stays inside same section")
                        score += 1

                    if target_block and target_block.isExecute():
                        reason_parts.append("same-section executable target")
                        score += 1

                if score > 0:
                    candidates.append({
                        "address": target_str,
                        "section": target_section,
                        "score": score,
                        "instruction": str(instr),
                        "reason": "; ".join(reason_parts)
                    })
                    seen.add(target_str)

        instr = instr.getNext()
        scanned += 1

    entry_str = str(entry)
    if entry_str not in seen:
        candidates.append({
            "address": entry_str,
            "section": entrypoint_info["section"],
            "score": 1,
            "instruction": "entrypoint",
            "reason": "fallback entrypoint candidate"
        })

    candidates = sorted(candidates, key=lambda x: (-x["score"], x["address"]))
    return candidates[:10]


def detect_packer_family_hint(section_info, external_symbols, entrypoint_info, classic_patterns):
    section_names = set([sec["name"] for sec in section_info])
    symbol_set = set(external_symbols)

    if "UPX0" in section_names or "UPX1" in section_names or "UPX2" in section_names:
        return "UPX-like"

    if ".aspack" in section_names:
        return "ASPack-like"

    if len(classic_patterns) > 0 and (
        "VirtualAlloc" in symbol_set or
        "VirtualProtect" in symbol_set or
        "GetProcAddress" in symbol_set or
        "LoadLibraryW" in symbol_set or
        "LoadLibraryA" in symbol_set
    ):
        return "generic runtime unpacking"

    if entrypoint_info["section"] in SUSPICIOUS_SECTION_NAMES:
        return "packed/loader stub section"

    return "unknown"


def build_packer_analysis(section_info, entrypoint_info, external_symbols, suspicious_apis):
    indicators = []
    score = 0

    suspicious_sections = [sec for sec in section_info if sec["suspicious"]]
    executable_nonstandard = [
        sec for sec in section_info
        if sec["execute"] and sec["name"] not in [".text", "CODE", ".code"]
    ]

    if len(suspicious_sections) > 0:
        indicators.append({
            "name": "suspicious_sections",
            "score": 20,
            "reason": "one or more sections look packer-like or executable+writable"
        })
        score += 20

    if entrypoint_info["section"] in SUSPICIOUS_SECTION_NAMES:
        indicators.append({
            "name": "entrypoint_in_suspicious_section",
            "score": 25,
            "reason": "entrypoint located inside suspicious section"
        })
        score += 25

    if entrypoint_info["section_is_writable"] and entrypoint_info["section_is_executable"]:
        indicators.append({
            "name": "entrypoint_in_rwx_section",
            "score": 20,
            "reason": "entrypoint section is writable and executable"
        })
        score += 20

    if len(external_symbols) < 20:
        indicators.append({
            "name": "very_small_import_surface",
            "score": 15,
            "reason": "few external symbols may indicate packing or stub behavior"
        })
        score += 15
    elif len(external_symbols) < 40:
        indicators.append({
            "name": "small_import_surface",
            "score": 8,
            "reason": "reduced import surface may indicate loader/stub behavior"
        })
        score += 8

    packer_api_hits = []
    for api_name in normalize_api_list(external_symbols):
        if api_name in normalize_api_list(PACKER_API_HINTS):
            packer_api_hits.append(api_name)

    if (
        ("GetProcAddress" in packer_api_hits or "LoadLibrary" in packer_api_hits)
        and
        ("VirtualAlloc" in packer_api_hits or "VirtualAllocEx" in packer_api_hits or "VirtualProtect" in packer_api_hits or "VirtualProtectEx" in packer_api_hits)
    ):
        indicators.append({
            "name": "runtime_unpacking_apis",
            "score": 20,
            "reason": "memory allocation/protection plus dynamic resolver APIs detected",
            "matched_apis": sorted(packer_api_hits)
        })
        score += 20

    if len(executable_nonstandard) > 0:
        indicators.append({
            "name": "nonstandard_executable_sections",
            "score": 10,
            "reason": "non-standard executable sections present",
            "count": len(executable_nonstandard)
        })
        score += 10

    confidence = "low"
    if score >= 55:
        confidence = "high"
    elif score >= 30:
        confidence = "medium"

    return {
        "packed_likelihood_score": score,
        "likely_packed": score >= 45,
        "confidence": confidence,
        "indicators": indicators,
        "suspicious_section_count": len(suspicious_sections)
    }

def enrich_packer_analysis_with_patterns(packer_analysis, classic_patterns, oep_candidates, packer_family_hint):
    score = packer_analysis["packed_likelihood_score"]
    indicators = list(packer_analysis["indicators"])

    for pattern in classic_patterns:
        indicators.append(pattern)
        score += pattern["score"]

    strong_oep = False
    if len(oep_candidates) > 0:
        top_candidate = oep_candidates[0]
        if top_candidate["score"] >= 35:
            strong_oep = True

    if strong_oep:
        indicators.append({
            "name": "strong_oep_candidate",
            "score": 15,
            "reason": "cross-section jump/call based candidate found near entrypoint"
        })
        score += 15

    likely_packed = score >= 40

    status = "packer-like indicators detected" if likely_packed else "executable does not appear packed"

    family = packer_family_hint
    if not likely_packed and family == "unknown":
        family = "none"

    return {
        "packed_likelihood_score": score,
        "likely_packed": likely_packed,
        "packer_family_hint": family,
        "status": status,
        "indicators": indicators
    }


def build_analyst_targets(top_functions):
    targets = []

    for func in top_functions[:8]:
        reasons = []
        checks = []

        if len(func["roles"]) > 0:
            reasons.append(f"behavior roles: {safe_join(func['roles'])}")
            checks.append("inspect role-related API usage")

        if func["structure_role"] == "dispatcher":
            reasons.append("high fan-out dispatcher-like function")
            checks.append("follow internal call fan-out and branching logic")

        if func["structure_role"] == "initializer":
            reasons.append("possible initialization entrypoint")
            checks.append("inspect setup, configuration, and bootstrap logic")

        if func["referenced_string_count"] > 0:
            reasons.append("references interesting strings")
            checks.append("inspect string xrefs and nearby call sites")

        if func["external_call_count"] > 5:
            reasons.append("many external calls")
            checks.append("review imported API sequence")

        if len(reasons) == 0:
            reasons.append("high local score")
            checks.append("inspect core control flow and callees")

        targets.append({
            "name": func["name"],
            "entry": func["entry"],
            "score": func["score"],
            "risk_level": func["risk_level"],
            "why": "; ".join(reasons) + ".",
            "what_to_check": "; ".join(checks) + "."
        })

    return targets


def build_analyst_playbook(behavior_story, top_functions, summary):
    steps = []

    if summary.get("packed_warning"):
        steps.append(
            "Treat static score and behavior inference with caution because the sample appears packed; prioritize unpacking stub review and likely OEP recovery."
        )

    if len(behavior_story["entry_candidates"]) > 0:
        first_entry = behavior_story["entry_candidates"][0]
        steps.append(
            f"Start from entry candidate {first_entry['name']} and inspect its outgoing internal calls."
        )

    if len(behavior_story["primary_dispatchers"]) > 0:
        first_dispatcher = behavior_story["primary_dispatchers"][0]
        steps.append(
            f"Open dispatcher {first_dispatcher['name']} and follow its highest fan-out branches."
        )

    if len(top_functions) > 0:
        first_target = top_functions[0]
        steps.append(
            f"Review top scored function {first_target['name']} for suspicious API combinations."
        )

    if len(behavior_story["storyline"]) > 0:
        first_story = behavior_story["storyline"][0]["path"]
        steps.append(
            f"Trace storyline path: {' -> '.join(first_story)}."
        )

    steps.append(
        "Validate whether registry, debugger, or dynamic loading indicators reflect benign application logic or suspicious behavior."
    )
    steps.append(
        "Confirm suspicious findings in Ghidra GUI through xrefs, decompiler view, and call graph inspection."
    )

    return {
        "steps": steps
    }

def build_report():
    analysis_metadata = build_analysis_metadata()

    sample_name = currentProgram.getName()
    sample_info = {
        "name": sample_name,
        "path": currentProgram.getExecutablePath() or "",
        "format": currentProgram.getExecutableFormat()
    }

    external_symbols = get_external_symbols()
    section_info = collect_section_info()
    entrypoint_info = get_entrypoint_info()
    entry_window = collect_entrypoint_instruction_window()
    classic_patterns = detect_classic_unpacking_patterns(entry_window)
    oep_candidates = find_oep_candidates(entrypoint_info)

    strings = get_strings()
    suspicious_apis = get_suspicious_apis(external_symbols)
    capabilities = detect_capabilities(external_symbols)
    interesting_strings = analyze_interesting_strings(strings)

    base_functions = get_base_functions()
    functions = enrich_functions(base_functions, interesting_strings)
    functions = apply_incoming_call_counts(functions)
    functions = assign_structure_roles(functions)

    top_functions = build_top_functions(functions)
    callgraph = build_callgraph(functions)
    execution_flow_hypotheses = build_execution_flow_hypotheses(functions)
    three_hop_flows = build_three_hop_flows(functions)
    behavior_clusters = build_behavior_clusters(functions)
    function_role_summary = build_function_role_summary(functions)
    behavior_summary = build_behavior_summary(functions, capabilities, execution_flow_hypotheses, three_hop_flows)
    behavior_story = build_behavior_story(functions, execution_flow_hypotheses, three_hop_flows)

    packer_base = build_packer_analysis(
        section_info,
        entrypoint_info,
        external_symbols,
        suspicious_apis
    )

    packer_family_hint = detect_packer_family_hint(
        section_info,
        external_symbols,
        entrypoint_info,
        classic_patterns
    )

    packer_analysis = enrich_packer_analysis_with_patterns(
        packer_base,
        classic_patterns,
        oep_candidates,
        packer_family_hint
    )

    raw_score = compute_raw_score(
        suspicious_apis,
        capabilities,
        interesting_strings,
        top_functions,
        packer_analysis
    )

    benign_contexts = detect_benign_contexts(external_symbols, interesting_strings, functions)
    adjusted_score, score_adjustments = apply_score_adjustments(raw_score, benign_contexts)
    risk_level = get_risk_level(adjusted_score)

    summary = build_summary(
        sample_name,
        external_symbols,
        suspicious_apis,
        capabilities,
        functions,
        strings,
        interesting_strings,
        top_functions,
        raw_score,
        adjusted_score,
        risk_level,
        score_adjustments,
        packer_analysis
    )

    analyst_summary = build_analyst_summary(
        summary,
        behavior_summary,
        capabilities,
        top_functions,
        score_adjustments
    )

    analyst_targets = build_analyst_targets(top_functions)

    analyst_playbook = build_analyst_playbook(
        behavior_story,
        top_functions,
        summary
    )

    return {
        "analysis_metadata": analysis_metadata,
        "sample": sample_info,
        "summary": summary,
        "global_analysis": {
            "external_symbols": external_symbols,
            "suspicious_apis": suspicious_apis,
            "capabilities": capabilities,
            "interesting_strings": interesting_strings,
            "strings": strings,
            "benign_contexts": benign_contexts,
            "score_adjustments": score_adjustments
        },
        "function_analysis": {
            "functions": functions,
            "top_functions": top_functions,
            "function_role_summary": function_role_summary
        },
        "behavior_analysis": {
            "callgraph": callgraph,
            "behavior_clusters": behavior_clusters,
            "execution_flow_hypotheses": execution_flow_hypotheses,
            "three_hop_flows": three_hop_flows,
            "behavior_summary": behavior_summary,
            "behavior_story": behavior_story
        },
        "binary_structure": {
            "packer_analysis": packer_analysis,
            "entrypoint_info": entrypoint_info,
            "entrypoint_window": entry_window,
            "oep_candidates": oep_candidates,
            "section_info": section_info
        },
        "analyst_output": {
            "analyst_summary": analyst_summary,
            "analyst_targets": analyst_targets,
            "analyst_playbook": analyst_playbook
        }
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