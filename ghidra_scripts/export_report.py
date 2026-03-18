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
MAX_INTERESTING_STRINGS = 80
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
    "CreateFileA": 5,
    "WriteFile": 5,
    "ReadFile": 5,
    "LoadLibraryW": 10,
    "LoadLibraryA": 10,
    "GetProcAddress": 15
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
    },
    "dynamic_loading": {
        "apis": ["LoadLibraryW", "LoadLibraryA", "GetProcAddress"],
        "min_matches": 2,
        "score": 20
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
        "score": 20,
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


def analyze_interesting_strings(strings):
    interesting = []

    for item in strings:
        value = item["value"]
        lower_value = value.lower()

        if is_probably_boring_library_name(value):
            continue

        matched_tags = set()
        score = 0
        reasons = []

        for rule_name, rule in STRING_PATTERNS.items():
            matched_keywords = []

            for keyword in rule["keywords"]:
                if keyword in lower_value:
                    matched_keywords.append(keyword)

            if matched_keywords:
                matched_tags.add(rule["tag"])
                score += rule["score"]
                reasons.append({
                    "rule": rule_name,
                    "keywords": sorted(set(matched_keywords)),
                    "score": rule["score"]
                })

        if score > 0:
            interesting.append({
                "address": item["address"],
                "value": value,
                "tags": sorted(matched_tags),
                "score": score,
                "reasons": reasons
            })

    interesting = sorted(interesting, key=lambda x: (-x["score"], x["value"]))
    return interesting[:MAX_INTERESTING_STRINGS]


def get_function_risk_level(score):
    if score >= 80:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
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

                    if target_name in SUSPICIOUS_API_WEIGHTS:
                        local_score += SUSPICIOUS_API_WEIGHTS[target_name]

                    for capability_name, rule in CAPABILITY_RULES.items():
                        if target_name in rule["apis"]:
                            local_capabilities.add(capability_name)

                    if target_func.isExternal() or target_func.isThunk():
                        external_calls.add(target_name)
                    else:
                        if target_name != func.getName():
                            internal_calls.add(target_name)

                if to_addr_str in interesting_string_map and to_addr_str not in seen_string_addresses:
                    string_item = interesting_string_map[to_addr_str]
                    referenced_string_values.append({
                        "address": string_item["address"],
                        "value": string_item["value"],
                        "score": string_item["score"],
                        "tags": string_item["tags"]
                    })
                    seen_string_addresses.add(to_addr_str)
                    local_score += min(string_item["score"], 20)

                    for tag in string_item["tags"]:
                        referenced_string_tags.add(tag)

        local_score += min(len(local_capabilities) * 8, 24)

        all_tags = set(local_capabilities) | set(referenced_string_tags)
        roles = detect_function_roles(external_calls, all_tags)

        if len(internal_calls) >= 8:
            local_score += 10
        if len(external_calls) >= 15:
            local_score += 10

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
        if func["score"] >= 20 or len(func["roles"]) > 0:
            seeds.append(func)

    seeds = seeds[:40]
    paths = []

    for func in seeds:
        if len(func["internal_calls"]) == 0:
            continue

        for callee_name in func["internal_calls"][:8]:
            callee = function_index.get(callee_name)
            if callee is None:
                continue

            path_roles = list(dict.fromkeys(func["roles"] + callee["roles"]))
            path_score = func["score"] + callee["score"]

            if path_score < 25 and len(path_roles) == 0:
                continue

            paths.append({
                "from": func["name"],
                "to": callee["name"],
                "combined_score": path_score,
                "from_roles": func["roles"],
                "to_roles": callee["roles"],
                "path_roles": path_roles,
                "from_structure_role": func["structure_role"],
                "to_structure_role": callee["structure_role"]
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


def build_behavior_story(functions, three_hop_flows):
    story = {
        "entry_candidates": [],
        "primary_dispatchers": [],
        "notable_workers": [],
        "storyline": []
    }

    dispatchers = [f for f in functions if f["structure_role"] == "dispatcher"]
    initializers = [f for f in functions if f["structure_role"] == "initializer"]
    workers = [f for f in functions if f["structure_role"] == "worker" and f["score"] >= 20]

    story["entry_candidates"] = [
        {
            "name": f["name"],
            "score": f["score"],
            "roles": f["roles"],
            "structure_role": f["structure_role"],
            "incoming_calls": f["incoming_calls"]
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

        sentence = " -> ".join(path)
        role_text = ", ".join(roles) if len(roles) > 0 else "no explicit behavioral roles"
        structure_text = " -> ".join(structure_roles)

        story["storyline"].append({
            "path": path,
            "combined_score": flow["combined_score"],
            "description": "{} | roles: {} | structure: {}".format(sentence, role_text, structure_text)
        })

    return story


def detect_benign_contexts(external_symbols, interesting_strings, functions):
    contexts = []
    symbol_set = set(external_symbols)
    symbol_count = len(external_symbols)

    ui_hits = len([x for x in external_symbols if x in BENIGN_UI_APIS])
    loader_hits = 0
    for api_name in ["LoadLibraryW", "LoadLibraryA", "GetProcAddress"]:
        if api_name in symbol_set:
            loader_hits += 1

    microsoft_urls = 0
    for item in interesting_strings:
        value = item["value"].lower()
        if "microsoft.com" in value or "go.microsoft.com" in value:
            microsoft_urls += 1

    high_risk_function_count = len([f for f in functions if f["risk_level"] in ["high", "critical"]])
    persistence_functions = len([f for f in functions if "persistence" in f["roles"]])
    anti_analysis_functions = len([f for f in functions if "anti_analysis" in f["roles"]])

    if ui_hits >= 8 and symbol_count > 150:
        contexts.append({
            "name": "rich_windows_gui_context",
            "score_adjustment": -35,
            "reason": "many GUI/UI APIs usually associated with benign Windows applications"
        })

    if loader_hits >= 2 and microsoft_urls > 0:
        contexts.append({
            "name": "benign_dynamic_loading_context",
            "score_adjustment": -20,
            "reason": "dynamic loading appears together with Microsoft documentation/update URLs"
        })

    if persistence_functions > 0 and persistence_functions <= 4:
        contexts.append({
            "name": "weak_persistence_signal",
            "score_adjustment": -15,
            "reason": "persistence-like APIs appear but only in a limited number of functions"
        })

    if anti_analysis_functions > 0 and anti_analysis_functions <= 4:
        contexts.append({
            "name": "weak_anti_analysis_signal",
            "score_adjustment": -10,
            "reason": "debug-related APIs may reflect normal defensive or diagnostic logic"
        })

    if high_risk_function_count == 0:
        contexts.append({
            "name": "no_high_risk_functions",
            "score_adjustment": -15,
            "reason": "no function reached a high local risk threshold"
        })

    return contexts


def compute_raw_score(suspicious_apis, capabilities, interesting_strings, top_functions):
    score = 0

    for item in suspicious_apis:
        score += item["weight"]

    for capability in capabilities:
        score += capability["score"]

    for string_item in interesting_strings:
        score += min(string_item["score"], 20)

    for func in top_functions[:10]:
        score += min(func["score"], 25)

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
    if score >= 180:
        return "critical"
    if score >= 100:
        return "high"
    if score >= 40:
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


def build_summary(sample_name, external_symbols, suspicious_apis, capabilities, functions, strings, interesting_strings, top_functions, raw_score, adjusted_score, risk_level, score_adjustments):
    return {
        "sample_name": sample_name,
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
        "top_indicators": build_top_indicators(suspicious_apis, capabilities, interesting_strings, top_functions)
    }

def build_analyst_summary(summary, behavior_summary, capabilities, top_functions, score_adjustments):
    key_points = []

    key_points.append("overall risk classified as '{}' with final score {}".format(
        summary["risk_level"],
        summary["overall_score"]
    ))

    if len(capabilities) > 0:
        cap_names = [c["name"] for c in capabilities[:5]]
        key_points.append("detected capabilities: {}".format(", ".join(cap_names)))

    if len(behavior_summary["inferred_behaviors"]) > 0:
        key_points.append("behavioral inference: {}".format("; ".join(behavior_summary["inferred_behaviors"][:4])))

    if len(score_adjustments) > 0:
        key_points.append("score adjusted by contextual benign indicators")

    if len(top_functions) > 0:
        names = [f["name"] for f in top_functions[:3]]
        key_points.append("priority functions for review: {}".format(", ".join(names)))

    return {
        "key_points": key_points,
        "primary_conclusion": key_points[0] if len(key_points) > 0 else "no conclusion"
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
        except:
            continue

        suspicious = False
        reasons = []

        if name in SUSPICIOUS_SECTION_NAMES:
            suspicious = True
            reasons.append("suspicious section name")

        if execute and write:
            suspicious = True
            reasons.append("section is executable and writable")

        if size == 0:
            reasons.append("empty section")

        results.append({
            "name": name,
            "start": start,
            "end": end,
            "size": size,
            "read": read,
            "write": write,
            "execute": execute,
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

    while instr is not None and scanned < 30:
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

                target_block = memory.getBlock(target)
                target_section = safe_block_name(target_block)
                same_section = (target_section == entrypoint_info["section"])

                reason_parts = []
                score = 0

                # Candidato serio solo se cambia sezione o viene da contesto sospetto
                if not same_section:
                    if mnemonic == "JMP":
                        reason_parts.append("unconditional jump from entry stub to different section")
                        score += 35
                    elif mnemonic == "CALL":
                        reason_parts.append("call target from entry stub to different section")
                        score += 20

                    if target_block and target_block.isExecute():
                        reason_parts.append("target section executable")
                        score += 10

                # stesso blocco/section = molto più debole
                else:
                    if mnemonic == "JMP":
                        reason_parts.append("jump stays inside same section")
                        score += 5
                    elif mnemonic == "CALL":
                        reason_parts.append("call stays inside same section")
                        score += 2

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
    if len(suspicious_sections) > 0:
        indicators.append({
            "name": "suspicious_sections",
            "score": 30,
            "reason": "one or more sections look packer-like or executable+writable"
        })
        score += 30

    if entrypoint_info["section"] in SUSPICIOUS_SECTION_NAMES:
        indicators.append({
            "name": "entrypoint_in_suspicious_section",
            "score": 30,
            "reason": "entrypoint located inside suspicious section"
        })
        score += 30

    if entrypoint_info["section_is_writable"] and entrypoint_info["section_is_executable"]:
        indicators.append({
            "name": "entrypoint_in_rwx_section",
            "score": 25,
            "reason": "entrypoint section is writable and executable"
        })
        score += 25

    if len(external_symbols) < 25:
        indicators.append({
            "name": "very_small_import_surface",
            "score": 20,
            "reason": "few external symbols may indicate packing or stub behavior"
        })
        score += 20

    packer_api_hits = []
    for api_name in external_symbols:
        if api_name in PACKER_API_HINTS:
            packer_api_hits.append(api_name)

    # richiedi una combinazione più sensata
    if (
        ("GetProcAddress" in packer_api_hits or "LoadLibraryW" in packer_api_hits or "LoadLibraryA" in packer_api_hits)
        and
        ("VirtualAlloc" in packer_api_hits or "VirtualAllocEx" in packer_api_hits or "VirtualProtect" in packer_api_hits or "VirtualProtectEx" in packer_api_hits)
    ):
        indicators.append({
            "name": "runtime_unpacking_apis",
            "score": 25,
            "reason": "memory allocation/protection plus dynamic resolver APIs detected",
            "matched_apis": sorted(packer_api_hits)
        })
        score += 25

    return {
        "packed_likelihood_score": score,
        "likely_packed": score >= 40,
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

    status = "packer-like indicators detected" if likely_packed else "executable doesn't appear packed"

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
            reasons.append("behavior roles: {}".format(", ".join(func["roles"])))
            checks.append("inspect role-related API usage")

        if func["structure_role"] == "dispatcher":
            reasons.append("high fan-out dispatcher-like function")
            checks.append("follow internal call fan-out and branching logic")

        if func["structure_role"] == "initializer":
            reasons.append("possible initialization entrypoint")
            checks.append("inspect setup/config/bootstrap logic")

        if func["referenced_string_count"] > 0:
            reasons.append("references interesting strings")
            checks.append("inspect string xrefs and nearby callsites")

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
            "why": "; ".join(reasons),
            "what_to_check": "; ".join(checks)
        })

    return targets


def build_analyst_playbook(behavior_story, top_functions):
    steps = []

    if len(behavior_story["entry_candidates"]) > 0:
        first_entry = behavior_story["entry_candidates"][0]
        steps.append("start from entry candidate '{}' and inspect its outgoing internal calls".format(first_entry["name"]))

    if len(behavior_story["primary_dispatchers"]) > 0:
        first_dispatcher = behavior_story["primary_dispatchers"][0]
        steps.append("open dispatcher '{}' and follow its highest-fan-out branches".format(first_dispatcher["name"]))

    if len(top_functions) > 0:
        first_target = top_functions[0]
        steps.append("review top scored function '{}' for suspicious API combinations".format(first_target["name"]))

    if len(behavior_story["storyline"]) > 0:
        first_story = behavior_story["storyline"][0]["path"]
        steps.append("trace storyline path: {}".format(" -> ".join(first_story)))

    steps.append("validate whether registry/debug/loading indicators are benign application logic or suspicious behavior")
    steps.append("confirm suspicious findings in Ghidra GUI through xrefs, decompiler view, and call graph inspection")

    return {
        "steps": steps
    }


def build_report():
    sample_name = currentProgram.getName()
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
    behavior_story = build_behavior_story(functions, three_hop_flows)

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

    raw_score = compute_raw_score(suspicious_apis, capabilities, interesting_strings, top_functions)

    # piccolo boost malware-like se packed molto probabile
    raw_score += min(packer_analysis["packed_likelihood_score"], 40)

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
        score_adjustments
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
        top_functions
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
        "interesting_strings": interesting_strings,
        "functions": functions,
        "top_functions": top_functions,
        "callgraph": callgraph,
        "behavior_clusters": behavior_clusters,
        "function_role_summary": function_role_summary,
        "execution_flow_hypotheses": execution_flow_hypotheses,
        "three_hop_flows": three_hop_flows,
        "behavior_summary": behavior_summary,
        "behavior_story": behavior_story,
        "benign_contexts": benign_contexts,
        "score_adjustments": score_adjustments,
        "analyst_summary": analyst_summary,
        "analyst_targets": analyst_targets,
        "analyst_playbook": analyst_playbook,
        "packer_analysis": packer_analysis,
        "entrypoint_info": entrypoint_info,
        "entrypoint_window": entry_window,
        "oep_candidates": oep_candidates,
        "section_info": section_info,
        "strings": strings
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