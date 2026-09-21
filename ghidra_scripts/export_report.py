# @runtime pyghidra
# @author
# @category Triage
# @keybinding
# @menupath
# @toolbar

import os
import sys
import json
import math
import re


def _load_typed_graph_model():
    try:
        from typed_graph_model import (
            TYPED_GRAPH_MODEL_VERSION,
            build_api_call_edge,
            build_api_id,
            build_api_node,
            build_call_visibility_indicator_id,
            build_call_visibility_indicator_node,
            build_constant_id,
            build_constant_node,
            build_constant_use_edge,
            build_function_call_edge,
            build_function_node,
            build_function_section_edge,
            build_indirect_call_indicator_edge,
            build_section_id,
            build_section_node,
            build_stable_function_id,
            build_string_category_edge,
            build_string_category_id,
            build_string_category_node,
            build_string_id,
            build_string_node,
            build_string_reference_edge,
            build_unresolved_function_call,
        )
    except ImportError:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        from typed_graph_model import (
            TYPED_GRAPH_MODEL_VERSION,
            build_api_call_edge,
            build_api_id,
            build_api_node,
            build_call_visibility_indicator_id,
            build_call_visibility_indicator_node,
            build_constant_id,
            build_constant_node,
            build_constant_use_edge,
            build_function_call_edge,
            build_function_node,
            build_function_section_edge,
            build_indirect_call_indicator_edge,
            build_section_id,
            build_section_node,
            build_stable_function_id,
            build_string_category_edge,
            build_string_category_id,
            build_string_category_node,
            build_string_id,
            build_string_node,
            build_string_reference_edge,
            build_unresolved_function_call,
        )

    return (
        TYPED_GRAPH_MODEL_VERSION,
        build_api_call_edge,
        build_api_id,
        build_api_node,
        build_call_visibility_indicator_id,
        build_call_visibility_indicator_node,
        build_constant_id,
        build_constant_node,
        build_constant_use_edge,
        build_function_call_edge,
        build_function_node,
        build_function_section_edge,
        build_indirect_call_indicator_edge,
        build_section_id,
        build_section_node,
        build_stable_function_id,
        build_string_category_edge,
        build_string_category_id,
        build_string_category_node,
        build_string_id,
        build_string_node,
        build_string_reference_edge,
        build_unresolved_function_call,
    )


(
    TYPED_GRAPH_MODEL_VERSION,
    build_api_call_edge,
    build_api_id,
    build_api_node,
    build_call_visibility_indicator_id,
    build_call_visibility_indicator_node,
    build_constant_id,
    build_constant_node,
    build_constant_use_edge,
    build_function_call_edge,
    build_function_node,
    build_function_section_edge,
    build_indirect_call_indicator_edge,
    build_section_id,
    build_section_node,
    build_stable_function_id,
    build_string_category_edge,
    build_string_category_id,
    build_string_category_node,
    build_string_id,
    build_string_node,
    build_string_reference_edge,
    build_unresolved_function_call,
) = _load_typed_graph_model()

DEFAULT_RULES_DIR_NAME = "rules"
DEFAULT_RULE_FILES = {
    "api_weights": "api_weights.json",
    "capability_rules": "capability_rules.json",
    "string_patterns": "string_patterns.json",
}

MAX_STRINGS = 400
MAX_STRING_LENGTH = 220
MAX_INTERESTING_STRINGS = 40
MAX_REFERENCED_STRINGS_PER_FUNCTION = 12
MAX_TOP_FUNCTIONS = 25
MAX_FLOW_PATHS = 30
MAX_THREE_HOP_FLOWS = 25
MAX_SECTION_ENTROPY_SAMPLE_BYTES = 65536
HIGH_ENTROPY_THRESHOLD = 7.20
VERY_HIGH_ENTROPY_THRESHOLD = 7.60
MAX_OEP_SCAN_INSTRUCTIONS = 180
LATE_TRANSFER_MIN_INDEX = 24
PREV_MNEMONIC_WINDOW = 5

STANDARD_CODE_SECTION_NAMES = set([".text", "text", ".code", "code"])
STANDARD_COMMON_SECTION_NAMES = set([".text", ".rdata", ".data", ".rsrc", ".idata", ".reloc", "text", ".code", "code"])

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
    "GetProcAddress": 3,
}

CAPABILITY_RULES = {
    "process_injection": {"apis": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtWriteVirtualMemory", "NtCreateThreadEx"], "min_matches": 2, "score": 40},
    "networking": {"apis": ["socket", "connect", "recv", "send", "WSAStartup", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW"], "min_matches": 2, "score": 20},
    "crypto": {"apis": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"], "min_matches": 1, "score": 20},
    "persistence": {"apis": ["RegCreateKeyEx", "RegSetValueEx", "RegOpenKeyEx"], "min_matches": 3, "score": 15},
    "anti_analysis": {"apis": ["IsDebuggerPresent", "OutputDebugString", "CheckRemoteDebuggerPresent"], "min_matches": 3, "score": 8},
    "dynamic_loading": {"apis": ["LoadLibraryW", "LoadLibraryA", "GetProcAddress"], "min_matches": 3, "score": 10},
}

STRING_PATTERNS = {
    "url_or_network": {"keywords": ["http://", "https://", "ftp://", "www.", ".com", ".net", ".org", "user-agent", "host:", "cookie"], "score": 15, "tag": "networking"},
    "filesystem_path": {"keywords": ["c:\\", "\\users\\", "\\appdata\\", "\\temp\\", "\\windows\\", ".exe", ".bat", ".cmd", ".ps1"], "score": 10, "tag": "filesystem"},
    "registry": {"keywords": ["hkey_", "software\\microsoft\\windows\\currentversion\\run", "runonce", "regsvr32"], "score": 20, "tag": "persistence"},
    "crypto_ransom": {"keywords": ["aes", "rsa", "encrypt", "decrypt", "ransom", "bitcoin", "wallet"], "score": 12, "tag": "crypto"},
    "commands": {"keywords": ["cmd.exe", "powershell", "rundll32", "wmic", "schtasks", "bitsadmin", "certutil"], "score": 20, "tag": "execution"},
    "anti_analysis": {"keywords": ["sandbox", "debugger", "vmware", "virtualbox", "wireshark", "procmon", "ollydbg"], "score": 20, "tag": "anti_analysis"},
}

ROLE_API_MAP = {
    "loader": ["LoadLibraryW", "LoadLibraryA", "GetProcAddress"],
    "network": ["socket", "connect", "recv", "send", "WSAStartup", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW"],
    "persistence": ["RegSetValueExW", "RegSetValueExA", "RegCreateKeyExW", "RegCreateKeyExA", "CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "OpenSCManagerW", "OpenSCManagerA"],
    "anti_analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringW", "OutputDebugStringA"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"],
    "execution": ["CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteW", "ShellExecuteA"],
    "injection": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtWriteVirtualMemory", "NtCreateThreadEx"],
}

BENIGN_UI_APIS = set(
    [
        "CreateWindowExW",
        "DialogBoxParamW",
        "DispatchMessageW",
        "TranslateMessage",
        "GetMessageW",
        "DefWindowProcW",
        "LoadCursorW",
        "LoadIconW",
        "BeginPaint",
        "EndPaint",
        "DrawTextW",
        "ShowWindow",
        "UpdateWindow",
        "CreateDialogParamW",
        "ChooseFontW",
        "PageSetupDlgW",
        "PrintDlgExW",
        "GetOpenFileNameW",
        "GetSaveFileNameW",
        "MessageBoxW",
    ]
)

BENIGN_SYSTEM_LIB_HINTS = set(["USER32", "GDI32", "COMDLG32", "COMCTL32", "SHELL32", "PROPSYS", "URLMON"])

SUSPICIOUS_SECTION_NAMES = set(["UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".packed", ".petite", ".boom", ".stub", ".themida", ".vmp0", ".vmp1", ".vmp2"])

PACKER_API_HINTS = set(["VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "LoadLibraryW", "LoadLibraryA", "GetProcAddress"])

CLASSIC_UNPACKING_MNEMONICS = set(["PUSHAD", "PUSHA", "POPAD", "POPA", "JMP", "CALL"])

SCHEMA_VERSION = "1.2.0"
ANALYSIS_MODE = "static_headless"
RULE_CONTRACT_VERSION = "1.0.0"

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
    "CreateFileW": "CreateFile",
    "RegOpenKeyExA": "RegOpenKeyEx",
    "RegOpenKeyExW": "RegOpenKeyEx",
}

BENIGN_STRING_KEYWORDS = ["microsoft", "notepad", "richedit", "comdlg", "print", "page setup", "font", "open file", "save file"]


STRING_CATEGORY_ORDER = [
    "url",
    "ip_address",
    "registry_path",
    "shell_command",
    "powershell",
    "file_path",
    "user_agent",
    "debugger_name",
    "vm_indicator",
]

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\\r\\n\"'<>|]+")
UNIX_PATH_RE = re.compile(r"(?:^|[\s\"'])/(?:usr|var|tmp|home|etc|opt|bin|sbin)/[^\s\"']+")

REGISTRY_HINTS = (
    "hkey_",
    "hkcu\\",
    "hklm\\",
    "hkcr\\",
    "hku\\",
    "software\\microsoft\\windows\\currentversion\\",
)

SHELL_COMMAND_HINTS = (
    "cmd.exe",
    "cmd /c",
    "powershell",
    "pwsh",
    "rundll32",
    "wmic",
    "schtasks",
    "bitsadmin",
    "certutil",
    "regsvr32",
)

DEBUGGER_NAME_HINTS = (
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "windbg",
    "immunity debugger",
    "ida64",
    "ida.exe",
)

VM_INDICATOR_HINTS = (
    "vmware",
    "virtualbox",
    "vbox",
    "qemu",
    "xen",
    "hyper-v",
    "parallels",
    "sandboxie",
)

MEMORY_PROTECTION_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
}

ALLOCATION_FLAG_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "NtAllocateVirtualMemory",
}

PROCESS_RIGHTS_APIS = {
    "OpenProcess",
    "NtOpenProcess",
}

REGISTRY_FLAG_APIS = {
    "RegOpenKeyEx",
    "RegCreateKeyEx",
    "RegOpenKeyTransacted",
    "RegCreateKeyTransacted",
}

MEMORY_PROTECTION_BASE_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

MEMORY_PROTECTION_MODIFIERS = {
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
}

ALLOCATION_FLAGS = {
    0x1000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x4000: "MEM_REPLACE_PLACEHOLDER",
    0x40000: "MEM_RESERVE_PLACEHOLDER",
    0x80000: "MEM_RESET",
    0x100000: "MEM_TOP_DOWN",
    0x200000: "MEM_WRITE_WATCH",
    0x400000: "MEM_PHYSICAL",
    0x1000000: "MEM_RESET_UNDO",
    0x20000000: "MEM_LARGE_PAGES",
}

PROCESS_RIGHTS_EXACT = {
    0x1F0FFF: ["PROCESS_ALL_ACCESS_LEGACY"],
    0x1FFFFF: ["PROCESS_ALL_ACCESS"],
}

PROCESS_RIGHT_FLAGS = {
    0x0001: "PROCESS_TERMINATE",
    0x0002: "PROCESS_CREATE_THREAD",
    0x0004: "PROCESS_SET_SESSIONID",
    0x0008: "PROCESS_VM_OPERATION",
    0x0010: "PROCESS_VM_READ",
    0x0020: "PROCESS_VM_WRITE",
    0x0040: "PROCESS_DUP_HANDLE",
    0x0080: "PROCESS_CREATE_PROCESS",
    0x0100: "PROCESS_SET_QUOTA",
    0x0200: "PROCESS_SET_INFORMATION",
    0x0400: "PROCESS_QUERY_INFORMATION",
    0x0800: "PROCESS_SUSPEND_RESUME",
    0x1000: "PROCESS_QUERY_LIMITED_INFORMATION",
    0x2000: "PROCESS_SET_LIMITED_INFORMATION",
    0x100000: "SYNCHRONIZE",
}

REGISTRY_RIGHTS_EXACT = {
    0x20019: ["KEY_READ"],
    0x20006: ["KEY_WRITE"],
    0xF003F: ["KEY_ALL_ACCESS"],
}

REGISTRY_RIGHT_FLAGS = {
    0x0001: "KEY_QUERY_VALUE",
    0x0002: "KEY_SET_VALUE",
    0x0004: "KEY_CREATE_SUB_KEY",
    0x0008: "KEY_ENUMERATE_SUB_KEYS",
    0x0010: "KEY_NOTIFY",
    0x0020: "KEY_CREATE_LINK",
    0x0100: "KEY_WOW64_64KEY",
    0x0200: "KEY_WOW64_32KEY",
}

CONSTANT_LOOKBACK_INSTRUCTIONS = 8

LOADED_RULES_METADATA = {
    "rules_dir": None,
    "rules_dir_exists": False,
    "rules_arg_provided": False,
    "expected_files": [],
    "loaded_files": [],
    "fallbacks_used": [],
    "errors": [],
    "rule_sources": {},
    "effective_rule_counts": {},
}


def _get_script_directory():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()


def _resolve_rules_dir(script_args):
    if len(script_args) > 1 and script_args[1]:
        return script_args[1]

    script_dir = _get_script_directory()
    project_root = os.path.dirname(script_dir)
    return os.path.join(project_root, DEFAULT_RULES_DIR_NAME)


def _load_json_file(path):
    with open(path, "r") as f:
        return json.load(f)


def _validate_api_weights(data):
    if not isinstance(data, dict):
        raise ValueError("api_weights must be a JSON object")
    for key, value in data.items():
        if not isinstance(key, str):
            raise ValueError("api_weights keys must be strings")
        if not isinstance(value, int):
            raise ValueError("api_weights values must be integers")
    return data


def _validate_capability_rules(data):
    if not isinstance(data, dict):
        raise ValueError("capability_rules must be a JSON object")

    for capability_name, rule in data.items():
        if not isinstance(capability_name, str):
            raise ValueError("capability name must be a string")
        if not isinstance(rule, dict):
            raise ValueError("capability rule must be an object")
        if "apis" not in rule or "min_matches" not in rule or "score" not in rule:
            raise ValueError("capability rule must contain apis, min_matches, score")
        if not isinstance(rule["apis"], list) or not all(isinstance(x, str) for x in rule["apis"]):
            raise ValueError("capability rule 'apis' must be a list of strings")
        if not isinstance(rule["min_matches"], int):
            raise ValueError("capability rule 'min_matches' must be an integer")
        if not isinstance(rule["score"], int):
            raise ValueError("capability rule 'score' must be an integer")

    return data


def _validate_string_patterns(data):
    if not isinstance(data, dict):
        raise ValueError("string_patterns must be a JSON object")

    for rule_name, rule in data.items():
        if not isinstance(rule_name, str):
            raise ValueError("string pattern name must be a string")
        if not isinstance(rule, dict):
            raise ValueError("string pattern rule must be an object")
        if "keywords" not in rule or "score" not in rule or "tag" not in rule:
            raise ValueError("string pattern rule must contain keywords, score, tag")
        if not isinstance(rule["keywords"], list) or not all(isinstance(x, str) for x in rule["keywords"]):
            raise ValueError("string pattern 'keywords' must be a list of strings")
        if not isinstance(rule["score"], int):
            raise ValueError("string pattern 'score' must be an integer")
        if not isinstance(rule["tag"], str):
            raise ValueError("string pattern 'tag' must be a string")

    return data


def _build_rule_sources_map():
    loaded_rule_names = set([item["rule"] for item in LOADED_RULES_METADATA.get("loaded_files", [])])
    fallback_rule_names = set([item["rule"] for item in LOADED_RULES_METADATA.get("fallbacks_used", [])])

    sources = {}
    for rule_key in DEFAULT_RULE_FILES.keys():
        if rule_key in loaded_rule_names:
            sources[rule_key] = "external"
        elif rule_key in fallback_rule_names:
            sources[rule_key] = "internal_fallback"
        else:
            sources[rule_key] = "unknown"

    return sources


def _build_effective_rule_counts():
    return {
        "api_weights": len(SUSPICIOUS_API_WEIGHTS),
        "capability_rules": len(CAPABILITY_RULES),
        "normalized_capability_rules": len(NORMALIZED_CAPABILITY_RULES),
        "string_patterns": len(STRING_PATTERNS),
    }


def build_rule_contract():
    capability_names = sorted(NORMALIZED_CAPABILITY_RULES.keys())
    string_pattern_names = sorted(STRING_PATTERNS.keys())

    return {
        "version": RULE_CONTRACT_VERSION,
        "external_rule_files": dict(DEFAULT_RULE_FILES),
        "effective_rule_counts": _build_effective_rule_counts(),
        "capability_rule_names": capability_names,
        "string_pattern_names": string_pattern_names,
    }


def load_external_rules(script_args):
    global SUSPICIOUS_API_WEIGHTS
    global CAPABILITY_RULES
    global STRING_PATTERNS
    global NORMALIZED_CAPABILITY_RULES
    global LOADED_RULES_METADATA

    rules_dir = _resolve_rules_dir(script_args)

    LOADED_RULES_METADATA = {
        "rules_dir": rules_dir,
        "rules_dir_exists": os.path.isdir(rules_dir),
        "rules_arg_provided": len(script_args) > 1 and bool(script_args[1]),
        "expected_files": [{"rule": rule_key, "filename": DEFAULT_RULE_FILES[rule_key]} for rule_key in sorted(DEFAULT_RULE_FILES.keys())],
        "loaded_files": [],
        "fallbacks_used": [],
        "errors": [],
        "rule_sources": {},
        "effective_rule_counts": {},
    }

    config = [
        ("api_weights", _validate_api_weights, "SUSPICIOUS_API_WEIGHTS"),
        ("capability_rules", _validate_capability_rules, "CAPABILITY_RULES"),
        ("string_patterns", _validate_string_patterns, "STRING_PATTERNS"),
    ]

    for rule_key, validator, target_name in config:
        filename = DEFAULT_RULE_FILES[rule_key]
        path = os.path.join(rules_dir, filename)

        try:
            if not os.path.exists(path):
                LOADED_RULES_METADATA["fallbacks_used"].append({"rule": rule_key, "reason": "file_not_found", "path": path})
                continue

            loaded = _load_json_file(path)
            loaded = validator(loaded)

            if target_name == "SUSPICIOUS_API_WEIGHTS":
                SUSPICIOUS_API_WEIGHTS = loaded
            elif target_name == "CAPABILITY_RULES":
                CAPABILITY_RULES = loaded
            elif target_name == "STRING_PATTERNS":
                STRING_PATTERNS = loaded

            LOADED_RULES_METADATA["loaded_files"].append({"rule": rule_key, "path": path})

        except Exception as e:
            LOADED_RULES_METADATA["errors"].append({"rule": rule_key, "path": path, "error": str(e)})
            LOADED_RULES_METADATA["fallbacks_used"].append({"rule": rule_key, "reason": "load_error", "path": path})

    NORMALIZED_CAPABILITY_RULES = build_capability_rule_index()
    LOADED_RULES_METADATA["rule_sources"] = _build_rule_sources_map()
    LOADED_RULES_METADATA["effective_rule_counts"] = _build_effective_rule_counts()


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
        idx[capability_name] = {"apis": sorted(normalized), "min_matches": rule["min_matches"], "score": rule["score"]}
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


SOFT_CAPABILITIES = set(["anti_analysis", "persistence", "dynamic_loading"])
HIGH_IMPACT_CAPABILITIES = set(["process_injection", "networking", "crypto"])


def is_soft_capability(capability_name):
    return capability_name in SOFT_CAPABILITIES


def is_high_impact_capability(capability_name):
    return capability_name in HIGH_IMPACT_CAPABILITIES


def get_capability_confidence_for_name(capability_name, match_count, min_matches):
    if is_soft_capability(capability_name):
        if match_count >= (min_matches + 2):
            return "medium"
        if match_count >= (min_matches + 1):
            return "low"
        return "low"

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
        "analysis_mode": ANALYSIS_MODE,
        "rule_contract_version": RULE_CONTRACT_VERSION,
        "rules_metadata": LOADED_RULES_METADATA,
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
        except Exception:
            continue

        if not value:
            continue

        value = clean_string_value(str(value))

        if len(value) < 4:
            continue

        if len(value) > MAX_STRING_LENGTH:
            value = value[:MAX_STRING_LENGTH]

        results.append({"address": str(data.getAddress()), "value": value})

        if len(results) >= MAX_STRINGS:
            break

    return results


def get_base_functions():
    functions = []
    function_manager = currentProgram.getFunctionManager()

    for func in function_manager.getFunctions(True):
        functions.append(
            {
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
                "risk_level": "low",
            }
        )

    return functions


def get_function_symbol_name(func):
    try:
        symbol = func.getSymbol()
        if symbol is None:
            return None

        symbol_name = symbol.getName()
        if symbol_name is None:
            return None

        symbol_name = str(symbol_name).strip()
        return symbol_name if symbol_name else None
    except Exception:
        return None


def get_function_section_name(func):
    try:
        memory = currentProgram.getMemory()
        block = memory.getBlock(func.getEntryPoint())
        if block is None:
            return None

        block_name = block.getName()
        if block_name is None:
            return None

        block_name = str(block_name).strip()
        return block_name if block_name else None
    except Exception:
        return None


def get_function_size(func):
    try:
        body = func.getBody()
        if body is None:
            return None

        size = body.getNumAddresses()
        if size is None:
            return None

        return int(size)
    except Exception:
        return None


def _resolve_external_api_function(func):
    """Return the terminal external function represented by func, if any.

    Direct external functions are APIs. Internal thunks are also treated as API
    proxies when Ghidra resolves their recursive thunk destination to an
    external function. Internal thunks that ultimately target internal code
    remain FUNCTION nodes.
    """

    if func is None:
        return None

    try:
        if bool(func.isExternal()):
            return func
    except Exception:
        return None

    try:
        if not bool(func.isThunk()):
            return None
    except Exception:
        return None

    try:
        thunk_target = func.getThunkedFunction(True)
    except Exception:
        thunk_target = None

    if thunk_target is None or thunk_target is func:
        return None

    try:
        if bool(thunk_target.isExternal()):
            return thunk_target
    except Exception:
        return None

    return None


def _is_typed_internal_function(func):
    if func is None:
        return False

    try:
        if bool(func.isExternal()):
            return False
    except Exception:
        return False

    if _resolve_external_api_function(func) is not None:
        return False

    return True


def get_typed_function_nodes():
    """Return only real internal FUNCTION nodes for the seeded graph.

    Step 2.5 separates external APIs from FUNCTION nodes. Import thunks whose
    recursive destination is external are therefore represented through API
    nodes/edges instead of duplicating the same semantic target as FUNCTION.
    """

    function_manager = currentProgram.getFunctionManager()
    nodes = []

    for func in function_manager.getFunctions(True):
        if not _is_typed_internal_function(func):
            continue

        node = build_function_node(
            entry_address=str(func.getEntryPoint()),
            ghidra_name=func.getName(),
            symbol_name=get_function_symbol_name(func),
            external=False,
            thunk=bool(func.isThunk()),
            section=get_function_section_name(func),
            size=get_function_size(func),
        )
        nodes.append(node)

    return sorted(nodes, key=lambda node: node["id"])


def _is_call_instruction(instr):
    try:
        flow_type = instr.getFlowType()
        return flow_type is not None and bool(flow_type.isCall())
    except Exception:
        return False


def _is_indirect_call_instruction(instr):
    try:
        flow_type = instr.getFlowType()
        return flow_type is not None and bool(flow_type.isComputed())
    except Exception:
        return False


def _is_call_reference(ref):
    try:
        reference_type = ref.getReferenceType()
        if reference_type is None:
            return True
        return bool(reference_type.isCall())
    except Exception:
        return True


def _resolve_function_target(function_manager, to_addr):
    try:
        target_func = function_manager.getFunctionAt(to_addr)
        if target_func is not None:
            return target_func
    except Exception:
        pass

    try:
        return function_manager.getFunctionContaining(to_addr)
    except Exception:
        return None


def _get_api_observation(target_func):
    external_func = _resolve_external_api_function(target_func)
    if external_func is None:
        return None

    try:
        original_name = str(external_func.getName()).strip()
    except Exception:
        return None

    if not original_name:
        return None

    normalized_name = canonicalize_api_name(original_name)
    if normalized_name is None:
        return None

    normalized_name = str(normalized_name).strip()
    if not normalized_name:
        return None

    return {
        "id": build_api_id(normalized_name),
        "normalized_name": normalized_name,
        "original_name": original_name,
    }


def _is_string_data(data):
    if data is None:
        return False

    try:
        data_type = data.getDataType()
        if data_type is None:
            return False

        type_name = str(data_type.getName()).lower()
    except Exception:
        return False

    return "string" in type_name or "unicode" in type_name or "terminated" in type_name


def _resolve_referenced_string_data(listing, to_addr):
    try:
        data = listing.getDataContaining(to_addr)
    except Exception:
        data = None

    if data is None:
        try:
            data = listing.getDataAt(to_addr)
        except Exception:
            data = None

    if not _is_string_data(data):
        return None

    return data


def _is_valid_ipv4(value):
    try:
        parts = value.split(".")
        if len(parts) != 4:
            return False

        for part in parts:
            if not part.isdigit():
                return False
            if int(part) < 0 or int(part) > 255:
                return False

        return True
    except Exception:
        return False


def categorize_typed_string(value):
    """Return deterministic semantic categories for a referenced string."""

    text = "" if value is None else str(value)
    lower_value = text.lower()
    categories = set()

    if URL_RE.search(text):
        categories.add("url")

    for match in IPV4_RE.finditer(text):
        if _is_valid_ipv4(match.group(0)):
            categories.add("ip_address")
            break

    if any(hint in lower_value for hint in REGISTRY_HINTS):
        categories.add("registry_path")

    if "powershell" in lower_value or "pwsh" in lower_value or ".ps1" in lower_value:
        categories.add("powershell")

    if any(hint in lower_value for hint in SHELL_COMMAND_HINTS):
        categories.add("shell_command")

    if WINDOWS_PATH_RE.search(text) or UNIX_PATH_RE.search(text):
        categories.add("file_path")

    if "user-agent" in lower_value or "user_agent" in lower_value or "mozilla/" in lower_value:
        categories.add("user_agent")

    if any(hint in lower_value for hint in DEBUGGER_NAME_HINTS):
        categories.add("debugger_name")

    if any(hint in lower_value for hint in VM_INDICATOR_HINTS):
        categories.add("vm_indicator")

    return [category for category in STRING_CATEGORY_ORDER if category in categories]


def _get_typed_string_payload(data):
    try:
        raw_value = data.getDefaultValueRepresentation()
        address = data.getAddress()
    except Exception:
        return None

    if raw_value is None or address is None:
        return None

    raw_value = str(raw_value)
    value = clean_string_value(raw_value)

    if not value:
        return None

    categories = categorize_typed_string(value)

    return {
        "id": build_string_id(str(address)),
        "address": str(address),
        "value": value,
        "raw_value": raw_value,
        "category": categories[0] if categories else None,
        "categories": categories,
    }


def _decode_exact_or_bitmask(value, exact_values, flag_values):
    if value in exact_values:
        return list(exact_values[value])

    remaining = value
    names = []

    for flag_value, flag_name in sorted(flag_values.items()):
        if flag_value != 0 and (remaining & flag_value) == flag_value:
            names.append(flag_name)
            remaining &= ~flag_value

    if names and remaining == 0:
        return names

    return []


def _decode_memory_protection(value):
    base_value = value & 0xFF
    base_name = MEMORY_PROTECTION_BASE_FLAGS.get(base_value)

    if base_name is None:
        return []

    remaining = value & ~0xFF
    names = [base_name]

    for flag_value, flag_name in sorted(MEMORY_PROTECTION_MODIFIERS.items()):
        if (remaining & flag_value) == flag_value:
            names.append(flag_name)
            remaining &= ~flag_value

    if remaining != 0:
        return []

    return names


def _classify_constant_for_api(api_name, value):
    """Return semantic constant interpretations supported by an API context."""

    interpretations = []

    if api_name in MEMORY_PROTECTION_APIS:
        names = _decode_memory_protection(value)
        if names:
            interpretations.append(
                {
                    "category": "memory_protection",
                    "symbolic_names": names,
                }
            )

    if api_name in ALLOCATION_FLAG_APIS:
        names = _decode_exact_or_bitmask(
            value,
            {},
            ALLOCATION_FLAGS,
        )
        if names:
            interpretations.append(
                {
                    "category": "allocation_flags",
                    "symbolic_names": names,
                }
            )

    if api_name in PROCESS_RIGHTS_APIS:
        names = _decode_exact_or_bitmask(
            value,
            PROCESS_RIGHTS_EXACT,
            PROCESS_RIGHT_FLAGS,
        )
        if names:
            interpretations.append(
                {
                    "category": "process_rights",
                    "symbolic_names": names,
                }
            )

    if api_name in REGISTRY_FLAG_APIS:
        names = _decode_exact_or_bitmask(
            value,
            REGISTRY_RIGHTS_EXACT,
            REGISTRY_RIGHT_FLAGS,
        )
        if names:
            interpretations.append(
                {
                    "category": "registry_flags",
                    "symbolic_names": names,
                }
            )

    return interpretations


def _extract_instruction_scalars(instr):
    """Extract unsigned Scalar operands without importing Java classes."""

    results = []

    try:
        operand_count = int(instr.getNumOperands())
    except Exception:
        return results

    for operand_index in range(operand_count):
        try:
            objects = instr.getOpObjects(operand_index)
        except Exception:
            continue

        for obj in objects or []:
            get_unsigned = getattr(obj, "getUnsignedValue", None)
            if get_unsigned is None or not callable(get_unsigned):
                continue

            try:
                value = int(get_unsigned())
            except Exception:
                continue

            bit_length = None
            get_bit_length = getattr(obj, "bitLength", None)

            if get_bit_length is not None and callable(get_bit_length):
                try:
                    bit_length = int(get_bit_length())
                except Exception:
                    bit_length = None

            results.append(
                {
                    "value": value,
                    "bit_length": bit_length,
                    "operand_index": operand_index,
                }
            )

    return results


def _record_constants_for_api_call(
    caller_id,
    api_name,
    instructions,
    call_index,
    constant_nodes,
    constant_uses,
):
    """Collect relevant constants from the local instruction window before an API call."""

    first_index = max(
        0,
        call_index - CONSTANT_LOOKBACK_INSTRUCTIONS,
    )

    seen_observations = set()

    for candidate_instr in instructions[first_index : call_index + 1]:
        try:
            use_site = str(candidate_instr.getAddress())
        except Exception:
            continue

        for scalar in _extract_instruction_scalars(candidate_instr):
            value = scalar["value"]

            for interpretation in _classify_constant_for_api(
                api_name,
                value,
            ):
                category = interpretation["category"]
                constant_id = build_constant_id(
                    category,
                    value,
                )

                observation_key = (
                    constant_id,
                    use_site,
                    api_name,
                    scalar["operand_index"],
                )

                if observation_key in seen_observations:
                    continue

                seen_observations.add(observation_key)

                node_record = constant_nodes.setdefault(
                    constant_id,
                    {
                        "category": category,
                        "value": value,
                        "symbolic_names": set(),
                        "bit_lengths": set(),
                    },
                )

                node_record["symbolic_names"].update(interpretation["symbolic_names"])

                if scalar["bit_length"] is not None:
                    node_record["bit_lengths"].add(scalar["bit_length"])

                edge_key = (
                    caller_id,
                    constant_id,
                )

                edge_record = constant_uses.setdefault(
                    edge_key,
                    {
                        "use_sites": set(),
                        "occurrences": 0,
                        "context_apis": set(),
                    },
                )

                edge_record["use_sites"].add(use_site)
                edge_record["occurrences"] += 1
                edge_record["context_apis"].add(api_name)


def _parse_hex_address(value):
    if value is None:
        return None

    text = str(value).strip().lower()

    if not text:
        return None

    if ":" in text:
        text = text.rsplit(":", 1)[-1]

    if text.startswith("0x"):
        text = text[2:]

    try:
        return int(text, 16)
    except Exception:
        return None


def _find_section_record_for_function(function_node, section_info):
    section_name = function_node.get("section")
    function_address = _parse_hex_address(function_node.get("address"))

    candidates = [record for record in (section_info or []) if record.get("name") == section_name]

    if function_address is not None:
        for record in candidates:
            start = _parse_hex_address(record.get("start"))
            end = _parse_hex_address(record.get("end"))

            if start is not None and end is not None and start <= function_address <= end:
                return record

    if len(candidates) == 1:
        return candidates[0]

    return None


def _build_typed_section_evidence(function_nodes, section_info):
    section_nodes = {}
    section_edges = []

    for function_node in function_nodes:
        record = _find_section_record_for_function(
            function_node,
            section_info,
        )

        if record is None:
            continue

        try:
            section_id = build_section_id(record["start"])

            if section_id not in section_nodes:
                section_nodes[section_id] = build_section_node(
                    name=record["name"],
                    start=record["start"],
                    end=record["end"],
                    size=int(record["size"]),
                    read=bool(record["read"]),
                    write=bool(record["write"]),
                    execute=bool(record["execute"]),
                    initialized=bool(record["initialized"]),
                    entropy=record.get("entropy"),
                    entropy_class=record.get(
                        "entropy_class",
                        "unknown",
                    ),
                    entropy_sampled_bytes=int(
                        record.get(
                            "entropy_sampled_bytes",
                            0,
                        )
                    ),
                    suspicious=bool(
                        record.get(
                            "suspicious",
                            False,
                        )
                    ),
                    reasons=record.get(
                        "reasons",
                        [],
                    ),
                )

            section_edges.append(
                build_function_section_edge(
                    function_id=function_node["id"],
                    section_id=section_id,
                )
            )
        except Exception:
            continue

    return (
        [section_nodes[section_id] for section_id in sorted(section_nodes)],
        sorted(
            section_edges,
            key=lambda edge: (
                edge["source"],
                edge["target"],
            ),
        ),
    )


def build_seeded_typed_graph(section_info=None):
    """Build the complete Step 2 seeded Typed Evidence Graph.

    The graph is built directly from Ghidra function/instruction/reference facts.
    It does not consume the legacy visual callgraph and applies no legacy
    250-node/800-edge truncation. Step 2.10 also adds conservative indirect-call
    visibility evidence.
    """

    listing = currentProgram.getListing()
    reference_manager = currentProgram.getReferenceManager()
    function_manager = currentProgram.getFunctionManager()

    function_nodes = get_typed_function_nodes()
    function_node_ids = set(node["id"] for node in function_nodes)

    function_calls = {}
    api_calls = {}
    api_nodes = {}
    string_records = {}
    string_references = {}
    string_categories = {}
    string_category_edges = set()
    constant_records = {}
    constant_uses = {}
    unresolved_calls = []
    call_visibility = {}

    for caller_func in function_manager.getFunctions(True):
        if not _is_typed_internal_function(caller_func):
            continue

        caller_id = build_stable_function_id(caller_func.getEntryPoint())
        if caller_id not in function_node_ids:
            continue

        try:
            body = caller_func.getBody()
        except Exception:
            body = None

        if body is None:
            continue

        try:
            instructions = list(
                listing.getInstructions(
                    body,
                    True,
                )
            )
        except Exception:
            continue

        for instruction_index, instr in enumerate(instructions):
            try:
                instruction_address = instr.getAddress()
                callsite = str(instruction_address)
            except Exception:
                continue

            try:
                refs = list(reference_manager.getReferencesFrom(instruction_address))
            except Exception:
                refs = []

            # ---------------------------------------------------------
            # Step 2.4 + 2.5:
            # function calls and API calls
            # ---------------------------------------------------------
            if _is_call_instruction(instr):
                indirect = _is_indirect_call_instruction(instr)
                resolved_call_target = False

                internal_targets = set()
                api_targets = {}

                for ref in refs:
                    if not _is_call_reference(ref):
                        continue

                    try:
                        to_addr = ref.getToAddress()
                    except Exception:
                        to_addr = None

                    if to_addr is None:
                        continue

                    target_func = _resolve_function_target(
                        function_manager,
                        to_addr,
                    )

                    if target_func is None:
                        continue

                    api_observation = _get_api_observation(target_func)

                    if api_observation is not None:
                        resolved_call_target = True

                        api_id = api_observation["id"]
                        api_targets[api_id] = api_observation

                        continue

                    if not _is_typed_internal_function(target_func):
                        continue

                    callee_id = build_stable_function_id(target_func.getEntryPoint())

                    if callee_id not in function_node_ids:
                        continue

                    resolved_call_target = True
                    internal_targets.add(callee_id)

                resolved_target_ids = sorted(set(internal_targets) | set(api_targets.keys()))

                if indirect:
                    visibility_record = call_visibility.setdefault(
                        caller_id,
                        {
                            "indirect_callsites": set(),
                            "resolved_indirect_callsites": set(),
                            "unresolved_indirect_callsites": set(),
                            "dynamic_dispatch_callsites": set(),
                            "dynamic_dispatch_targets": set(),
                        },
                    )
                    visibility_record["indirect_callsites"].add(callsite)

                    if resolved_call_target:
                        visibility_record["resolved_indirect_callsites"].add(callsite)
                    else:
                        visibility_record["unresolved_indirect_callsites"].add(callsite)

                    # Conservative Step 2.10 dynamic-dispatch recognition:
                    # a computed callsite must expose multiple resolved call
                    # targets. A normal single-target indirect call is not
                    # promoted to dynamic_dispatch.
                    if len(resolved_target_ids) >= 2:
                        visibility_record["dynamic_dispatch_callsites"].add(callsite)
                        visibility_record["dynamic_dispatch_targets"].update(resolved_target_ids)

                for callee_id in sorted(internal_targets):
                    key = (
                        caller_id,
                        callee_id,
                        indirect,
                    )

                    function_calls.setdefault(
                        key,
                        set(),
                    ).add(callsite)

                for api_id in sorted(api_targets):
                    observation = api_targets[api_id]

                    node_record = api_nodes.setdefault(
                        api_id,
                        {
                            "normalized_name": observation["normalized_name"],
                            "original_names": set(),
                        },
                    )

                    node_record["original_names"].add(observation["original_name"])

                    key = (
                        caller_id,
                        api_id,
                        indirect,
                    )

                    edge_record = api_calls.setdefault(
                        key,
                        {
                            "callsites": set(),
                            "original_names": set(),
                        },
                    )

                    edge_record["callsites"].add(callsite)

                    edge_record["original_names"].add(observation["original_name"])

                    _record_constants_for_api_call(
                        caller_id=caller_id,
                        api_name=observation["normalized_name"],
                        instructions=instructions,
                        call_index=instruction_index,
                        constant_nodes=constant_records,
                        constant_uses=constant_uses,
                    )

                if not resolved_call_target:
                    unresolved_calls.append(
                        build_unresolved_function_call(
                            caller_id=caller_id,
                            callsite=callsite,
                            indirect=indirect,
                        )
                    )

            # ---------------------------------------------------------
            # Step 2.6:
            # referenced string evidence
            # ---------------------------------------------------------
            for ref in refs:
                try:
                    to_addr = ref.getToAddress()
                except Exception:
                    to_addr = None

                if to_addr is None:
                    continue

                string_data = _resolve_referenced_string_data(
                    listing,
                    to_addr,
                )

                if string_data is None:
                    continue

                payload = _get_typed_string_payload(string_data)

                if payload is None:
                    continue

                string_id = payload["id"]

                node_record = string_records.setdefault(
                    string_id,
                    {
                        "address": payload["address"],
                        "value": payload["value"],
                        "raw_value": payload["raw_value"],
                        "categories": set(),
                        "reference_count": 0,
                    },
                )

                node_record["categories"].update(payload["categories"])
                node_record["reference_count"] += 1

                for category in payload["categories"]:
                    category_id = build_string_category_id(category)

                    string_categories[category_id] = category
                    string_category_edges.add(
                        (
                            string_id,
                            category_id,
                        )
                    )

                key = (
                    caller_id,
                    string_id,
                )

                edge_record = string_references.setdefault(
                    key,
                    {
                        "reference_sites": set(),
                        "reference_count": 0,
                    },
                )

                edge_record["reference_sites"].add(callsite)
                edge_record["reference_count"] += 1

    # -------------------------------------------------------------
    # Build deterministic FUNCTION -> FUNCTION edges
    # -------------------------------------------------------------
    resolved_function_edges = []

    for caller_id, callee_id, indirect in sorted(function_calls):
        resolved_function_edges.append(
            build_function_call_edge(
                caller_id=caller_id,
                callee_id=callee_id,
                callsites=function_calls[
                    (
                        caller_id,
                        callee_id,
                        indirect,
                    )
                ],
                indirect=indirect,
            )
        )

    # -------------------------------------------------------------
    # Build deterministic API nodes
    # -------------------------------------------------------------
    typed_api_nodes = []

    for api_id in sorted(api_nodes):
        record = api_nodes[api_id]

        typed_api_nodes.append(
            build_api_node(
                normalized_name=record["normalized_name"],
                original_names=record["original_names"],
            )
        )

    # -------------------------------------------------------------
    # Build deterministic FUNCTION -> API edges
    # -------------------------------------------------------------
    resolved_api_edges = []

    for caller_id, api_id, indirect in sorted(api_calls):
        record = api_calls[
            (
                caller_id,
                api_id,
                indirect,
            )
        ]

        resolved_api_edges.append(
            build_api_call_edge(
                caller_id=caller_id,
                api_id=api_id,
                callsites=record["callsites"],
                original_names=record["original_names"],
                indirect=indirect,
            )
        )

    # -------------------------------------------------------------
    # Build deterministic STRING nodes
    # -------------------------------------------------------------
    typed_string_nodes = []

    for string_id in sorted(string_records):
        record = string_records[string_id]

        typed_string_nodes.append(
            build_string_node(
                address=record["address"],
                value=record["value"],
                raw_value=record["raw_value"],
                categories=[category for category in STRING_CATEGORY_ORDER if category in record["categories"]],
                reference_count=record["reference_count"],
            )
        )

    # -------------------------------------------------------------
    # Build deterministic FUNCTION -> STRING edges
    # -------------------------------------------------------------
    string_edges = []

    for function_id, string_id in sorted(string_references):
        record = string_references[
            (
                function_id,
                string_id,
            )
        ]

        string_edges.append(
            build_string_reference_edge(
                function_id=function_id,
                string_id=string_id,
                reference_sites=record["reference_sites"],
                reference_count=record["reference_count"],
            )
        )

    # -------------------------------------------------------------
    # Build deterministic STRING_CATEGORY nodes and edges
    # -------------------------------------------------------------
    typed_string_category_nodes = [build_string_category_node(string_categories[category_id]) for category_id in sorted(string_categories)]

    typed_string_category_edges = [
        build_string_category_edge(
            string_id=string_id,
            category_id=category_id,
        )
        for string_id, category_id in sorted(string_category_edges)
    ]

    # -------------------------------------------------------------
    # Build deterministic CONSTANT nodes and FUNCTION -> CONSTANT edges
    # -------------------------------------------------------------
    typed_constant_nodes = []

    for constant_id in sorted(constant_records):
        record = constant_records[constant_id]

        typed_constant_nodes.append(
            build_constant_node(
                category=record["category"],
                value=record["value"],
                symbolic_names=record["symbolic_names"],
                bit_lengths=record["bit_lengths"],
            )
        )

    typed_constant_edges = []

    for function_id, constant_id in sorted(constant_uses):
        record = constant_uses[
            (
                function_id,
                constant_id,
            )
        ]

        typed_constant_edges.append(
            build_constant_use_edge(
                function_id=function_id,
                constant_id=constant_id,
                use_sites=record["use_sites"],
                occurrences=record["occurrences"],
                context_apis=record["context_apis"],
            )
        )

    # -------------------------------------------------------------
    # Build deterministic SECTION nodes and FUNCTION -> SECTION edges
    # -------------------------------------------------------------
    typed_section_nodes, typed_section_edges = _build_typed_section_evidence(
        function_nodes,
        section_info,
    )

    # -------------------------------------------------------------
    # Step 2.10: explicit indirect-call visibility evidence
    # -------------------------------------------------------------
    typed_visibility_nodes = []
    typed_visibility_edges = []

    for function_id in sorted(call_visibility):
        record = call_visibility[function_id]
        indicator_node = build_call_visibility_indicator_node(
            function_id=function_id,
            indirect_callsites=record["indirect_callsites"],
            resolved_indirect_callsites=record["resolved_indirect_callsites"],
            unresolved_indirect_callsites=record["unresolved_indirect_callsites"],
            dynamic_dispatch_callsites=record["dynamic_dispatch_callsites"],
            dynamic_dispatch_targets=record["dynamic_dispatch_targets"],
        )
        typed_visibility_nodes.append(indicator_node)
        typed_visibility_edges.append(
            build_indirect_call_indicator_edge(
                function_id=function_id,
                indicator_id=build_call_visibility_indicator_id(function_id),
            )
        )

    unresolved_calls = sorted(
        unresolved_calls,
        key=lambda item: (
            item["caller"],
            item["callsite"],
            item["indirect"],
        ),
    )

    typed_nodes = function_nodes + typed_api_nodes + typed_string_nodes + typed_string_category_nodes + typed_constant_nodes + typed_section_nodes + typed_visibility_nodes

    typed_edges = resolved_function_edges + resolved_api_edges + string_edges + typed_string_category_edges + typed_constant_edges + typed_section_edges + typed_visibility_edges

    node_type_counts = {}
    for node in typed_nodes:
        node_type_counts[node["type"]] = node_type_counts.get(node["type"], 0) + 1

    edge_type_counts = {}
    for edge in typed_edges:
        edge_type_counts[edge["type"]] = edge_type_counts.get(edge["type"], 0) + 1

    return {
        "model_version": TYPED_GRAPH_MODEL_VERSION,
        "metadata": {
            "scope": "complete_seeded_evidence_graph",
            "callgraph_source": "ghidra_instruction_references",
            "legacy_callgraph_used": False,
            "legacy_callgraph_limits_applied": False,
            "truncated": False,
            "node_count": len(typed_nodes),
            "edge_count": len(typed_edges),
            "unresolved_call_count": len(unresolved_calls),
            "node_type_counts": {key: node_type_counts[key] for key in sorted(node_type_counts)},
            "edge_type_counts": {key: edge_type_counts[key] for key in sorted(edge_type_counts)},
        },
        "nodes": typed_nodes,
        "edges": typed_edges,
        "unresolved_calls": unresolved_calls,
    }


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
            aggregated[canonical] = {"name": canonical, "weight": weight, "variants": set([api_name])}
        else:
            aggregated[canonical]["variants"].add(api_name)

    results = []
    for item in aggregated.values():
        results.append({"name": item["name"], "weight": item["weight"], "variants": sorted(item["variants"])})

    return sorted(results, key=lambda x: (-x["weight"], x["name"]))


def count_capability_string_support(capability_name, interesting_strings):
    capability_tag_map = {
        "networking": set(["networking"]),
        "persistence": set(["persistence"]),
        "crypto": set(["crypto"]),
        "anti_analysis": set(["anti_analysis"]),
    }

    wanted_tags = capability_tag_map.get(capability_name, set())
    if len(wanted_tags) == 0:
        return 0

    count = 0
    for item in interesting_strings or []:
        if item.get("benign_hint", False):
            continue

        tags = set(item.get("tags", []))
        if len(tags & wanted_tags) > 0:
            count += 1

    return count


def collect_capability_support(functions, top_functions, capability_name, rule):
    rule_api_set = set(normalize_api_list(rule["apis"]))

    local_function_support = 0
    high_risk_function_support = 0
    top_function_support = 0
    local_api_hits = set()

    for func in functions or []:
        func_caps = set(func.get("matched_capabilities", []))
        func_hits = set(normalize_api_list(func.get("local_api_hits", [])))
        overlap = rule_api_set & func_hits

        qualifies = capability_name in func_caps or len(overlap) >= max(1, rule["min_matches"] - 1)
        if not qualifies:
            continue

        local_function_support += 1
        local_api_hits.update(overlap)

        if func.get("risk_level") in ["high", "critical"]:
            high_risk_function_support += 1

    for func in top_functions or []:
        tf_caps = set(func.get("matched_capabilities", []))
        tf_tags = set(func.get("tags", []))
        tf_hits = set(normalize_api_list(func.get("local_api_hits", [])))
        overlap = rule_api_set & tf_hits

        qualifies = capability_name in tf_caps or capability_name in tf_tags or len(overlap) >= max(1, rule["min_matches"] - 1)
        if not qualifies:
            continue

        top_function_support += 1
        local_api_hits.update(overlap)

    return {
        "local_function_support": local_function_support,
        "high_risk_function_support": high_risk_function_support,
        "top_function_support": top_function_support,
        "local_api_hits": sorted(local_api_hits),
    }


def reconcile_capabilities_with_local_evidence(capabilities, functions, top_functions, external_symbols):
    capability_map = {}
    for item in capabilities:
        capability_map[item["name"]] = dict(item)

    local_support = {}
    medium_or_higher_support = {}
    top_support = {}

    for func in functions:
        matched = set(func.get("matched_capabilities", []))
        tags = set(func.get("tags", []))
        roles = set(func.get("roles", []))

        implied = set(matched) | set(tags)

        if "network" in roles:
            implied.add("networking")
        if "injection" in roles:
            implied.add("process_injection")
        if "loader" in roles:
            implied.add("dynamic_loading")

        for cap_name in implied:
            local_support[cap_name] = local_support.get(cap_name, 0) + 1
            if func.get("risk_level") in ["medium", "high", "critical"]:
                medium_or_higher_support[cap_name] = medium_or_higher_support.get(cap_name, 0) + 1

    for func in top_functions:
        matched = set(func.get("matched_capabilities", [])) | set(func.get("tags", []))
        roles = set(func.get("roles", []))

        if "network" in roles:
            matched.add("networking")
        if "injection" in roles:
            matched.add("process_injection")
        if "loader" in roles:
            matched.add("dynamic_loading")

        for cap_name in matched:
            top_support[cap_name] = top_support.get(cap_name, 0) + 1

    for capability_name, rule in NORMALIZED_CAPABILITY_RULES.items():
        support = local_support.get(capability_name, 0)
        support_medium = medium_or_higher_support.get(capability_name, 0)
        support_top = top_support.get(capability_name, 0)

        if capability_name in capability_map:
            current = capability_map[capability_name]

            if is_soft_capability(capability_name):
                if support <= 1 and current["match_count"] <= current["min_matches"]:
                    current["confidence"] = "low"
                    current["score"] = max(4, min(current["score"], rule["score"]))
                    current["source"] = current.get("source", "global_import_surface") + "+weak_local_support"
                elif support >= 2:
                    current["confidence"] = "medium"
                    current["score"] = max(current["score"], rule["score"] + 3)
                    current["source"] = current.get("source", "global_import_surface") + "+multi_function_local_evidence"

            else:
                if support >= 2 and support_top >= 1:
                    if current["confidence"] == "low":
                        current["confidence"] = "medium"
                    current["score"] = max(current["score"], rule["score"] + 6)
                    current["source"] = current.get("source", "global_import_surface") + "+multi_function_local_evidence"

            capability_map[capability_name] = current
            continue

        if capability_name == "networking":
            if support >= 2 and support_medium >= 1:
                matched = count_matching_apis(external_symbols, rule["apis"])
                capability_map[capability_name] = {
                    "name": capability_name,
                    "matched_apis": sorted(matched),
                    "match_count": len(matched),
                    "min_matches": rule["min_matches"],
                    "confidence": "medium" if support_top == 0 else "high",
                    "score": rule["score"] + 6,
                    "source": "multi_function_network_evidence",
                }

        elif capability_name == "process_injection":
            if support >= 2 and support_medium >= 1:
                matched = count_matching_apis(external_symbols, rule["apis"])
                strong_injection_hits = [x for x in matched if x in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtWriteVirtualMemory", "NtCreateThreadEx"]]
                if len(strong_injection_hits) >= 1:
                    capability_map[capability_name] = {
                        "name": capability_name,
                        "matched_apis": sorted(matched),
                        "match_count": max(len(matched), support),
                        "min_matches": rule["min_matches"],
                        "confidence": "medium",
                        "score": rule["score"] + 5,
                        "source": "multi_function_local_injection_evidence",
                    }

        elif capability_name == "dynamic_loading":
            if support >= 2 and support_top >= 1:
                matched = count_matching_apis(external_symbols, rule["apis"])
                capability_map[capability_name] = {
                    "name": capability_name,
                    "matched_apis": sorted(matched),
                    "match_count": len(matched),
                    "min_matches": rule["min_matches"],
                    "confidence": "medium",
                    "score": rule["score"] + 2,
                    "source": "multi_function_loader_evidence",
                }

    out = list(capability_map.values())
    out = sorted(out, key=lambda x: (-x["score"], x["name"]))
    return out


def detect_capabilities(external_symbols):
    normalized_symbols = normalize_api_list(external_symbols)
    symbol_set = set(normalized_symbols)
    capabilities = []

    for capability_name, rule in NORMALIZED_CAPABILITY_RULES.items():
        matched = []

        for api_name in rule["apis"]:
            if api_name in symbol_set:
                matched.append(api_name)

        if len(matched) < rule["min_matches"]:
            continue

        confidence = get_capability_confidence_for_name(
            capability_name,
            len(matched),
            rule["min_matches"],
        )

        score = rule["score"]
        if confidence == "medium":
            score += 3
        elif confidence == "high":
            score += 8

        capabilities.append(
            {
                "name": capability_name,
                "matched_apis": sorted(matched),
                "match_count": len(matched),
                "min_matches": rule["min_matches"],
                "confidence": confidence,
                "score": score,
                "source": "global_import_surface",
            }
        )

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
                reasons.append({"rule": rule_name, "keywords": sorted(set(matched_keywords)), "score": rule_score})

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
            reasons.append({"rule": "benign_ui_or_vendor_hint", "keywords": [], "score": -benign_penalty})

        if score > 0:
            interesting.append({"address": item["address"], "value": value, "tags": sorted(matched_tags), "score": score, "reasons": reasons, "benign_hint": benign_hits > 0})

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
                        score_breakdown.append({"type": "suspicious_api", "name": canonical_target, "delta": api_weight, "reason": "local reference to suspicious API"})
                        local_api_hits.add(canonical_target)
                    elif canonical_target in SUSPICIOUS_API_WEIGHTS:
                        api_weight = SUSPICIOUS_API_WEIGHTS[canonical_target]
                        local_score += api_weight
                        score_breakdown.append({"type": "suspicious_api", "name": canonical_target, "delta": api_weight, "reason": "local reference to suspicious API variant"})
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

                    referenced_string_values.append({"address": string_item["address"], "value": string_item["value"], "score": string_item["score"], "tags": string_item["tags"], "benign_hint": string_item.get("benign_hint", False)})
                    seen_string_addresses.add(to_addr_str)

                    if not string_item.get("benign_hint", False):
                        local_score += string_score
                        score_breakdown.append({"type": "interesting_string", "name": string_item["value"][:80], "delta": string_score, "reason": "function references interesting string"})

                    for tag in string_item["tags"]:
                        referenced_string_tags.add(tag)

        local_capability_bonus = 0
        for capability_name in sorted(local_capabilities):
            local_capability_bonus += 3

        local_capability_bonus = min(local_capability_bonus, 9)
        if local_capability_bonus > 0:
            local_score += local_capability_bonus
            score_breakdown.append({"type": "local_capabilities", "name": ",".join(sorted(local_capabilities)), "delta": local_capability_bonus, "reason": "multiple capability-related local signals"})

        all_tags = set(local_capabilities) | set(referenced_string_tags)
        roles = detect_function_roles(external_calls, all_tags)

        connectivity_bonus = 0
        if len(internal_calls) >= 15:
            connectivity_bonus += 2
        if len(external_calls) >= 30:
            connectivity_bonus += 2
        if connectivity_bonus > 0:
            local_score += connectivity_bonus
            score_breakdown.append({"type": "connectivity", "name": func.getName(), "delta": connectivity_bonus, "reason": "high local fan-out"})

        local_benign_adjustment = 0
        if "persistence" in local_capabilities and len(local_api_hits) <= 2:
            local_benign_adjustment -= 12

        if "anti_analysis" in local_capabilities and len(local_api_hits) <= 2:
            local_benign_adjustment -= 10

        if "dynamic_loading" in local_capabilities and "loader" in roles and len(local_api_hits) <= 3:
            local_benign_adjustment -= 10

        # dispatcher molto ampi ma con pochi segnali reali spesso sono normali orchestratori GUI/app
        if len(internal_calls) >= 20 and len(external_calls) >= 20 and len(local_api_hits) <= 2 and len(local_capabilities) <= 1 and len(referenced_string_values) == 0:
            local_benign_adjustment -= 10

        if local_benign_adjustment != 0:
            local_score += local_benign_adjustment
            score_breakdown.append({"type": "benign_adjustment", "name": func.getName(), "delta": local_benign_adjustment, "reason": "weak isolated signal adjusted downward"})

        if local_score < 0:
            local_score = 0

        if local_score > 45:
            local_score = 45

        enriched.append(
            {
                "name": func.getName(),
                "entry": str(func.getEntryPoint()),
                "external": func.isExternal(),
                "thunk": func.isThunk(),
                "internal_calls": sorted(internal_calls),
                "external_calls": sorted(external_calls),
                "incoming_calls": 0,
                "referenced_strings": sorted(referenced_string_values, key=lambda x: (-x["score"], x["value"]))[:MAX_REFERENCED_STRINGS_PER_FUNCTION],
                "matched_capabilities": sorted(local_capabilities),
                "roles": roles,
                "structure_role": "unknown",
                "tags": sorted(all_tags),
                "local_api_hits": sorted(local_api_hits),
                "score_breakdown": score_breakdown,
                "score": local_score,
                "risk_level": get_function_risk_level(local_score),
            }
        )

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
        if func["score"] <= 0:
            continue

        reasoning = build_top_function_reasoning(func)

        ranked.append(
            {
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
                "tags": func["tags"],
                "matched_capabilities": func.get("matched_capabilities", []),
                "local_api_hits": func.get("local_api_hits", []),
                "primary_reason": reasoning["primary_reason"],
                "reason_summary": reasoning["reason_summary"],
                "score_driver_summary": reasoning["score_driver_summary"],
                "evidence": reasoning["evidence"],
            }
        )

    return ranked[:MAX_TOP_FUNCTIONS]


def build_callgraph(functions):
    nodes = []
    edges = []

    for func in functions:
        nodes.append({"name": func["name"], "entry": func["entry"], "score": func["score"], "risk_level": func["risk_level"], "roles": func["roles"], "structure_role": func["structure_role"], "incoming_calls": func["incoming_calls"]})

        for callee in func["internal_calls"]:
            edges.append({"from": func["name"], "to": callee, "type": "internal_call"})

        for callee in func["external_calls"]:
            edges.append({"from": func["name"], "to": callee, "type": "external_call"})

    return {"node_count": len(nodes), "edge_count": len(edges), "nodes": nodes[:250], "edges": edges[:800]}


def build_behavior_clusters(functions):
    clusters = {}
    for role_name in ROLE_API_MAP.keys():
        clusters[role_name] = []

    for func in functions:
        for role in func["roles"]:
            if role not in clusters:
                clusters[role] = []
            clusters[role].append({"name": func["name"], "entry": func["entry"], "score": func["score"], "risk_level": func["risk_level"], "structure_role": func["structure_role"]})

    for role_name in clusters.keys():
        clusters[role_name] = sorted(clusters[role_name], key=lambda x: (-x["score"], x["name"]))[:10]

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

            description_parts = [f"{func['name']} -> {callee['name']}", f"combined_score={path_score}", f"from_structure={func['structure_role']}", f"to_structure={callee['structure_role']}"]

            if path_roles:
                description_parts.append(f"roles={safe_join(path_roles)}")

            paths.append(
                {"from": func["name"], "to": callee["name"], "combined_score": path_score, "from_roles": func["roles"], "to_roles": callee["roles"], "path_roles": path_roles, "from_structure_role": func["structure_role"], "to_structure_role": callee["structure_role"], "description": "; ".join(description_parts)}
            )

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

                flows.append({"path": [a["name"], b["name"], c["name"]], "combined_score": combined_score, "roles": roles, "structure_roles": [a["structure_role"], b["structure_role"], c["structure_role"]]})

    flows = sorted(flows, key=lambda x: (-x["combined_score"], x["path"][0], x["path"][1], x["path"][2]))
    return flows[:MAX_THREE_HOP_FLOWS]


def build_function_role_summary(functions):
    summary = {"by_structure_role": {}, "by_behavior_role": {}}

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
            high_risk_functions.append({"name": func["name"], "score": func["score"], "risk_level": func["risk_level"], "roles": func["roles"], "structure_role": func["structure_role"]})

        connectivity = len(func["internal_calls"]) + len(func["external_calls"])
        if connectivity >= 12 and (func["score"] >= 15 or len(func["roles"]) > 0):
            hub_functions.append({"name": func["name"], "score": func["score"], "risk_level": func["risk_level"], "roles": func["roles"], "structure_role": func["structure_role"], "connectivity": connectivity, "incoming_calls": func["incoming_calls"]})

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
        "inferred_behaviors": inferred_behaviors,
    }


def build_behavior_story(functions, flow_hypotheses, three_hop_flows):
    story = {
        "entry_candidates": [],
        "primary_dispatchers": [],
        "notable_workers": [],
        "storyline": [],
        "story_summary": [],
        "confidence_notes": [],
    }

    initializers = sorted(
        [f for f in functions if f["structure_role"] == "initializer"],
        key=lambda x: (-x["score"], -len(x["internal_calls"]), x["name"]),
    )

    dispatchers = sorted(
        [f for f in functions if f["structure_role"] == "dispatcher"],
        key=lambda x: (-(len(x["internal_calls"]) + len(x["external_calls"])), -x["score"], x["name"]),
    )

    workers = sorted(
        [f for f in functions if f["structure_role"] == "worker" and (f["score"] >= 10 or len(f["roles"]) > 0)],
        key=lambda x: (-x["score"], -x["incoming_calls"], x["name"]),
    )

    for f in initializers[:8]:
        reasoning = build_top_function_reasoning(f)
        story["entry_candidates"].append(
            {
                "name": f["name"],
                "score": f["score"],
                "roles": f["roles"],
                "structure_role": f["structure_role"],
                "incoming_calls": f["incoming_calls"],
                "fan_out": len(f["internal_calls"]) + len(f["external_calls"]),
                "primary_reason": reasoning["primary_reason"],
            }
        )

    for f in dispatchers[:8]:
        reasoning = build_top_function_reasoning(f)
        story["primary_dispatchers"].append(
            {
                "name": f["name"],
                "score": f["score"],
                "roles": f["roles"],
                "structure_role": f["structure_role"],
                "fan_out": len(f["internal_calls"]) + len(f["external_calls"]),
                "incoming_calls": f["incoming_calls"],
                "primary_reason": reasoning["primary_reason"],
            }
        )

    for f in workers[:12]:
        reasoning = build_top_function_reasoning(f)
        story["notable_workers"].append(
            {
                "name": f["name"],
                "score": f["score"],
                "roles": f["roles"],
                "structure_role": f["structure_role"],
                "incoming_calls": f["incoming_calls"],
                "primary_reason": reasoning["primary_reason"],
            }
        )

    for flow in three_hop_flows[:10]:
        story["storyline"].append(
            build_storyline_record(
                flow["path"],
                flow["roles"],
                flow["structure_roles"],
                flow["combined_score"],
                "three_hop_flow",
            )
        )

    if len(story["storyline"]) == 0:
        for flow in flow_hypotheses[:10]:
            story["storyline"].append(
                build_storyline_record(
                    [flow["from"], flow["to"]],
                    flow["path_roles"],
                    [flow["from_structure_role"], flow["to_structure_role"]],
                    flow["combined_score"],
                    "two_hop_flow",
                )
            )

    if len(three_hop_flows) > 0:
        story["confidence_notes"].append("Story reconstruction confidence improved by the presence of multi-stage three-hop paths.")
    else:
        story["confidence_notes"].append("Story reconstruction fell back to two-hop paths and should be treated as more approximate.")

    if len(story["entry_candidates"]) > 0:
        first_entry = story["entry_candidates"][0]
        story["story_summary"].append(f"Likely execution starts around {first_entry['name']} (score={first_entry['score']}, fan_out={first_entry['fan_out']}) because it looks like an early-stage control node.")

    if len(story["primary_dispatchers"]) > 0:
        first_dispatcher = story["primary_dispatchers"][0]
        story["story_summary"].append(f"Primary dispatcher candidate is {first_dispatcher['name']} ({first_dispatcher['primary_reason']}).")

    if len(story["notable_workers"]) > 0:
        top_workers = [w["name"] for w in story["notable_workers"][:3]]
        story["story_summary"].append(f"Most notable worker functions: {safe_join(top_workers)}.")

    if len(story["storyline"]) > 0:
        first_line = story["storyline"][0]
        story["story_summary"].append(f"Best reconstructed flow: {first_line['description']}.")

    return story


def detect_benign_contexts(external_symbols, interesting_strings, functions):
    contexts = []
    symbol_count = len(external_symbols)

    ui_hits = len([x for x in external_symbols if canonicalize_api_name(x) in BENIGN_UI_APIS])
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

    persistence_functions = len([f for f in functions if "persistence" in f.get("roles", [])])
    anti_analysis_functions = len([f for f in functions if "anti_analysis" in f.get("roles", [])])
    injection_functions = len([f for f in functions if "injection" in f.get("roles", [])])
    network_functions = len([f for f in functions if "network" in f.get("roles", [])])

    if ui_hits >= 8 and symbol_count > 120:
        contexts.append(
            {
                "name": "rich_windows_gui_context",
                "score_adjustment": -35,
                "reason": "many GUI/UI APIs usually associated with benign Windows applications",
            }
        )

    if loader_hits >= 2 and microsoft_urls > 0:
        contexts.append(
            {
                "name": "benign_dynamic_loading_context",
                "score_adjustment": -20,
                "reason": "dynamic loading appears together with Microsoft-related strings",
            }
        )

    if create_file_hits >= 2 and ui_hits >= 5:
        contexts.append(
            {
                "name": "desktop_app_file_io_context",
                "score_adjustment": -12,
                "reason": "file I/O appears together with a desktop GUI profile",
            }
        )

    if persistence_functions > 0 and persistence_functions <= 3 and injection_functions == 0 and network_functions == 0:
        contexts.append(
            {
                "name": "weak_persistence_signal",
                "score_adjustment": -18,
                "reason": "persistence-like APIs appear but only in a limited and non-cohesive way",
            }
        )

    if anti_analysis_functions > 0 and anti_analysis_functions <= 3 and high_risk_function_count == 0:
        contexts.append(
            {
                "name": "weak_anti_analysis_signal",
                "score_adjustment": -15,
                "reason": "debug-related APIs may reflect diagnostics or normal defensive logic",
            }
        )

    if high_risk_function_count == 0:
        contexts.append(
            {
                "name": "no_high_risk_functions",
                "score_adjustment": -15,
                "reason": "no function reached a high local risk threshold",
            }
        )

    if medium_or_higher_count <= 2 and benign_string_count >= 2:
        contexts.append(
            {
                "name": "benign_string_context",
                "score_adjustment": -10,
                "reason": "interesting strings contain multiple benign vendor/UI hints",
            }
        )

    if ui_hits >= 10 and symbol_count >= 150:
        contexts.append(
            {
                "name": "microsoft_desktop_app_profile",
                "score_adjustment": -25,
                "reason": "strong desktop/UI profile consistent with benign Microsoft desktop software",
            }
        )

    if injection_functions == 0 and network_functions == 0 and high_risk_function_count == 0 and (persistence_functions > 0 or anti_analysis_functions > 0):
        contexts.append(
            {
                "name": "soft_capability_only_profile",
                "score_adjustment": -15,
                "reason": "only soft capability-like signals are present without stronger offensive behavior",
            }
        )

    return contexts


def compute_raw_score(suspicious_apis, capabilities, interesting_strings, top_functions, packer_analysis):
    score = 0

    for item in suspicious_apis[:12]:
        score += min(item["weight"], 12)

    for capability in capabilities:
        cap_score = capability["score"]

        if capability["name"] in SOFT_CAPABILITIES:
            cap_score = min(cap_score, 12)
        else:
            cap_score = min(cap_score, 30)

        score += cap_score

    for string_item in interesting_strings[:25]:
        if not string_item.get("benign_hint", False):
            score += min(string_item["score"], 12)

    for func in top_functions[:6]:
        score += min(func["score"], 14)

    strong_function_signals = len([f for f in top_functions[:6] if f["score"] >= 15])
    high_impact_caps = len([c for c in capabilities if c["name"] in HIGH_IMPACT_CAPABILITIES and c.get("confidence") in ["medium", "high"]])

    if packer_analysis.get("likely_packed", False) and (strong_function_signals + high_impact_caps) >= 2:
        score += 6

    return score


def apply_score_adjustments(raw_score, benign_contexts):
    adjusted = raw_score
    adjustments = []

    for ctx in benign_contexts:
        adjusted += ctx["score_adjustment"]
        adjustments.append({"name": ctx["name"], "delta": ctx["score_adjustment"], "reason": ctx["reason"]})

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
        packed_warning = "This file appears to be packed. Static risk level, score, strings, and behavioral inference should be interpreted with caution because packing can hide or distort the program's real behavior."

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
        "packing_likelihood_score": packer_analysis.get("packed_likelihood_score", 0),
        "packer_confidence": packer_analysis.get("confidence", "low"),
        "packer_family_hint": packer_analysis.get("packer_family_hint", "unknown"),
        "top_indicators": build_top_indicators(suspicious_apis, capabilities, interesting_strings, top_functions),
        "contract_version": SCHEMA_VERSION,
    }


def build_analyst_summary(summary, behavior_summary, capabilities, top_functions, score_adjustments):
    key_points = []

    if summary.get("packed_warning"):
        key_points.append("Packed-sample caution: static findings may not fully reflect the program's real runtime behavior.")
        key_points.append(f"Packing/obfuscation indicators are tracked separately (packing score={summary.get('packing_likelihood_score', 0)}, family={summary.get('packer_family_hint', 'unknown')}).")

    key_points.append(f"Overall malware-risk classified as {summary['risk_level']} with final score {summary['overall_score']}.")

    if len(capabilities) > 0:
        cap_names = [c["name"] for c in capabilities[:5]]
        key_points.append(f"Detected capabilities: {safe_join(cap_names)}.")

    if len(behavior_summary["inferred_behaviors"]) > 0:
        key_points.append(f"Behavioral inference: {'; '.join(behavior_summary['inferred_behaviors'][:4])}.")

    if len(score_adjustments) > 0:
        key_points.append("Score adjusted by contextual benign indicators.")

    if len(top_functions) > 0:
        names = [f["name"] for f in top_functions[:3]]
        key_points.append(f"Priority functions for review: {safe_join(names)}.")
        key_points.append(f"Top function rationale: {top_functions[0]['name']} -> {top_functions[0].get('primary_reason', 'high local score')}.")

    primary_conclusion = f"Overall malware-risk classified as {summary['risk_level']} with final score {summary['overall_score']}."
    if summary.get("packed_warning"):
        primary_conclusion = f"Sample appears packed ({summary.get('packer_family_hint', 'unknown')}); static visibility may be incomplete while malware-risk remains {summary['risk_level']}."

    return {"key_points": key_points, "primary_conclusion": primary_conclusion}


def safe_block_name(block):
    if block is None:
        return "unknown"
    try:
        return block.getName()
    except Exception:
        return "unknown"


def is_standard_code_section_name(section_name):
    lower_name = (section_name or "").lower()
    return lower_name in STANDARD_CODE_SECTION_NAMES


def is_standard_common_section_name(section_name):
    lower_name = (section_name or "").lower()
    return lower_name in STANDARD_COMMON_SECTION_NAMES


def get_section_record(section_info, section_name):
    for sec in section_info:
        if sec.get("name") == section_name:
            return sec
    return None


def sample_block_bytes(block, max_bytes=MAX_SECTION_ENTROPY_SAMPLE_BYTES):
    if block is None:
        return []

    try:
        if not block.isInitialized():
            return []
    except Exception:
        return []

    memory = currentProgram.getMemory()

    try:
        size = int(block.getSize())
    except Exception:
        return []

    sample_size = min(size, max_bytes)
    if sample_size <= 0:
        return []

    data = []
    addr = block.getStart()

    for _ in range(sample_size):
        try:
            value = memory.getByte(addr)
            data.append(value & 0xFF)
            addr = addr.add(1)
        except Exception:
            break

    return data


def compute_shannon_entropy(byte_values):
    if not byte_values:
        return None

    total = float(len(byte_values))
    if total <= 0:
        return None

    counts = {}
    for b in byte_values:
        counts[b] = counts.get(b, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log(p, 2)

    return round(entropy, 4)


def classify_entropy(entropy):
    if entropy is None:
        return "unknown"
    if entropy >= VERY_HIGH_ENTROPY_THRESHOLD:
        return "very_high"
    if entropy >= HIGH_ENTROPY_THRESHOLD:
        return "high"
    if entropy >= 6.80:
        return "elevated"
    return "normal"


def get_previous_mnemonics(instr, max_items=PREV_MNEMONIC_WINDOW):
    mnemonics = []
    current = instr.getPrevious()

    count = 0
    while current is not None and count < max_items:
        try:
            mnemonics.append(current.getMnemonicString().upper())
        except Exception:
            break
        current = current.getPrevious()
        count += 1

    return mnemonics


def add_or_replace_candidate(candidate_map, candidate):
    current = candidate_map.get(candidate["address"])
    if current is None or candidate["score"] > current["score"]:
        candidate_map[candidate["address"]] = candidate


def build_path_role_narrative(roles, structure_roles):
    role_set = set(roles)
    structure_set = set(structure_roles)

    notes = []

    if "loader" in role_set and "execution" in role_set:
        notes.append("possible loader-to-execution handoff")
    if "injection" in role_set:
        notes.append("possible injection-oriented control path")
    if "network" in role_set and "persistence" in role_set:
        notes.append("possible network-and-persistence chain")
    if "anti_analysis" in role_set:
        notes.append("analysis-aware stage present")
    if "crypto" in role_set:
        notes.append("crypto-related processing stage present")

    if not notes and "dispatcher" in structure_set:
        notes.append("control likely fans out through dispatcher-like logic")

    if not notes:
        notes.append("control-flow relationship reconstructed without explicit behavioral role evidence")

    return "; ".join(notes[:2])


def build_storyline_record(path, roles, structure_roles, combined_score, flow_type):
    role_text = safe_join(roles) if roles else "no explicit behavioral roles"
    structure_text = " -> ".join(structure_roles)
    narrative = build_path_role_narrative(roles, structure_roles)

    return {
        "type": flow_type,
        "path": path,
        "combined_score": combined_score,
        "roles": roles,
        "structure_roles": structure_roles,
        "narrative": narrative,
        "description": f"{' -> '.join(path)} | score={combined_score} | roles: {role_text} | structure: {structure_text} | narrative: {narrative}",
    }


def get_top_score_drivers(func, limit=4):
    drivers = list(func.get("score_breakdown", []))
    drivers = sorted(
        drivers,
        key=lambda x: (-abs(x.get("delta", 0)), x.get("type", ""), x.get("name", "")),
    )
    return drivers[:limit]


def build_top_function_reasoning(func):
    reasons = []

    api_hits = func.get("local_api_hits", [])
    matched_capabilities = func.get("matched_capabilities", [])
    roles = func.get("roles", [])
    referenced_strings = func.get("referenced_strings", [])

    internal_call_count = len(func.get("internal_calls", []))
    external_call_count = len(func.get("external_calls", []))

    if api_hits:
        reasons.append("suspicious API mix: {}".format(safe_join(api_hits[:4])))

    if matched_capabilities:
        reasons.append("local capability evidence: {}".format(safe_join(matched_capabilities[:3])))

    if roles:
        reasons.append("behavior roles: {}".format(safe_join(roles[:3])))

    if referenced_strings:
        string_samples = [s["value"][:40] for s in referenced_strings[:2]]
        reasons.append("interesting strings: {}".format(safe_join(string_samples, " | ")))

    if func.get("structure_role") == "dispatcher" and internal_call_count >= 8:
        reasons.append("dispatcher-like high fan-out control node")

    if func.get("structure_role") == "initializer":
        reasons.append("possible bootstrap or early execution function")

    if external_call_count >= 6:
        reasons.append("large external API surface concentrated in one function")

    if not reasons:
        reasons.append("high local score driven by aggregated weak signals")

    top_score_drivers = []
    for item in get_top_score_drivers(func):
        top_score_drivers.append(
            {
                "type": item.get("type", "unknown"),
                "name": item.get("name", ""),
                "delta": item.get("delta", 0),
                "reason": item.get("reason", ""),
            }
        )

    score_driver_summary = []
    if api_hits:
        score_driver_summary.append("apis={}".format(safe_join(api_hits[:3])))
    if matched_capabilities:
        score_driver_summary.append("capabilities={}".format(safe_join(matched_capabilities[:3])))
    if referenced_strings:
        score_driver_summary.append("strings={}".format(safe_join([s["value"][:25] for s in referenced_strings[:2]], " | ")))

    return {
        "primary_reason": reasons[0],
        "reason_summary": "; ".join(reasons[:3]),
        "score_driver_summary": "; ".join(score_driver_summary),
        "evidence": {
            "local_api_hits": api_hits[:6],
            "matched_capabilities": matched_capabilities[:4],
            "referenced_string_samples": [s["value"][:80] for s in referenced_strings[:3]],
            "top_score_drivers": top_score_drivers,
        },
    }


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
        except Exception:
            continue

        suspicious = False
        reasons = []

        sampled_bytes = sample_block_bytes(block)
        entropy = compute_shannon_entropy(sampled_bytes)
        entropy_class = classify_entropy(entropy)

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

        if entropy is not None:
            if entropy >= VERY_HIGH_ENTROPY_THRESHOLD:
                reasons.append("very high entropy")
                if execute or not is_standard_common_section_name(name):
                    suspicious = True
            elif entropy >= HIGH_ENTROPY_THRESHOLD:
                reasons.append("high entropy")
                if execute:
                    suspicious = True

        if not is_standard_common_section_name(name):
            if execute and size < 1024:
                suspicious = True
                reasons.append("small executable non-standard section")

        results.append(
            {
                "name": name,
                "start": start,
                "end": end,
                "size": size,
                "read": read,
                "write": write,
                "execute": execute,
                "initialized": initialized,
                "entropy": entropy,
                "entropy_class": entropy_class,
                "entropy_sampled_bytes": len(sampled_bytes),
                "suspicious": suspicious,
                "reasons": reasons,
            }
        )

    return results


def get_program_entrypoint():
    symbol_table = currentProgram.getSymbolTable()

    try:
        entry_iter = symbol_table.getExternalEntryPointIterator()
        for addr in entry_iter:
            if addr is not None:
                return addr
    except Exception:
        pass

    try:
        image_base = currentProgram.getImageBase()
        if image_base is not None:
            return image_base
    except Exception:
        pass

    try:
        min_addr = currentProgram.getMinAddress()
        if min_addr is not None:
            return min_addr
    except Exception:
        pass

    return None


def get_entrypoint_info():
    entry = get_program_entrypoint()
    memory = currentProgram.getMemory()

    if entry is None:
        return {"address": None, "section": "unknown", "section_is_executable": False, "section_is_writable": False}

    block = memory.getBlock(entry)

    return {"address": str(entry), "section": safe_block_name(block), "section_is_executable": bool(block.isExecute()) if block else False, "section_is_writable": bool(block.isWrite()) if block else False}


def collect_entrypoint_instruction_window(max_instructions=25):
    listing = currentProgram.getListing()
    entry = get_program_entrypoint()

    results = []

    if entry is None:
        return results

    instr = listing.getInstructionAt(entry)

    count = 0
    while instr is not None and count < max_instructions:
        results.append({"address": str(instr.getAddress()), "mnemonic": instr.getMnemonicString(), "text": str(instr)})
        instr = instr.getNext()
        count += 1

    return results


def detect_classic_unpacking_patterns(entry_window):
    findings = []

    mnemonics = [item["mnemonic"].upper() for item in entry_window]
    transfer_indexes = [idx for idx, mnemonic in enumerate(mnemonics) if mnemonic in ["JMP", "CALL"]]

    pushad_index = -1
    popad_index = -1

    for idx, mnemonic in enumerate(mnemonics):
        if pushad_index == -1 and mnemonic in ["PUSHAD", "PUSHA"]:
            pushad_index = idx
        if popad_index == -1 and mnemonic in ["POPAD", "POPA"]:
            popad_index = idx

    if pushad_index != -1:
        findings.append(
            {
                "name": "pushad_pusha_near_entry",
                "score": 20,
                "reason": "classic packer stub pattern near entrypoint",
            }
        )

    if popad_index != -1:
        findings.append(
            {
                "name": "popad_popa_near_entry",
                "score": 20,
                "reason": "classic unpacking transition pattern near entrypoint",
            }
        )

    if pushad_index != -1 and popad_index != -1 and popad_index > pushad_index:
        findings.append(
            {
                "name": "pushad_to_popad_transition",
                "score": 15,
                "reason": "entrypoint window shows a classic stub-to-transfer register save/restore pattern",
            }
        )

    if len(transfer_indexes) >= 4:
        findings.append(
            {
                "name": "dense_transfer_stub",
                "score": 10,
                "reason": "entrypoint window contains many jump/call transfers typical of loader or stub logic",
            }
        )

    if len(mnemonics) >= 4 and any(m in ["JMP", "CALL"] for m in mnemonics[-4:]):
        findings.append(
            {
                "name": "tail_transfer_near_entry_window_end",
                "score": 10,
                "reason": "entrypoint window ends with a transfer instruction, consistent with stub handoff behavior",
            }
        )

    return findings


def find_oep_candidates(entrypoint_info):
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    function_manager = currentProgram.getFunctionManager()
    entry = get_program_entrypoint()

    candidate_map = {}

    if entry is None:
        return []

    instr = listing.getInstructionAt(entry)
    scanned = 0

    while instr is not None and scanned < MAX_OEP_SCAN_INSTRUCTIONS:
        mnemonic = instr.getMnemonicString().upper()

        if mnemonic in ["JMP", "CALL"]:
            try:
                flows = instr.getFlows()
            except Exception:
                flows = []

            prev_mnemonics = get_previous_mnemonics(instr)

            for target in flows:
                if target is None:
                    continue

                target_str = str(target)
                if target_str.startswith("EXTERNAL:"):
                    continue

                target_block = memory.getBlock(target)
                if target_block is None:
                    continue

                if not target_block.isExecute():
                    continue

                target_section = safe_block_name(target_block)
                same_section = target_section == entrypoint_info["section"]

                score = 0
                reason_parts = []

                if not same_section:
                    if mnemonic == "JMP":
                        score += 35
                        reason_parts.append("unconditional cross-section jump from entry stub")
                    else:
                        score += 18
                        reason_parts.append("cross-section call from entry stub")

                    if target_section == ".text" or is_standard_code_section_name(target_section):
                        score += 20
                        reason_parts.append("target section looks like real code (.text/code)")
                    elif target_section not in SUSPICIOUS_SECTION_NAMES and target_section != "unknown":
                        score += 10
                        reason_parts.append("target section is executable and non-stub-like")
                    else:
                        score -= 6
                        reason_parts.append("target section still looks stub-like or suspicious")

                    if entrypoint_info["section"] in SUSPICIOUS_SECTION_NAMES and target_section not in SUSPICIOUS_SECTION_NAMES:
                        score += 12
                        reason_parts.append("transition leaves suspicious entry section")
                else:
                    if mnemonic == "JMP":
                        score += 3
                        reason_parts.append("same-section jump")
                    else:
                        score += 1
                        reason_parts.append("same-section call")

                    if target_block.isExecute():
                        score += 1
                        reason_parts.append("same-section executable target")

                if target_block.isWrite():
                    score -= 8
                    reason_parts.append("target section is writable, which weakens OEP confidence")

                target_func = function_manager.getFunctionContaining(target)
                target_func_name = None
                if target_func is not None and not target_func.isExternal():
                    target_func_name = target_func.getName()
                    score += 6
                    reason_parts.append("target resolves into a concrete memory-backed function")

                late_transfer = scanned >= LATE_TRANSFER_MIN_INDEX
                if late_transfer and mnemonic == "JMP":
                    score += 8
                    reason_parts.append("late transfer deeper in entry stub window")

                popad_nearby = "POPAD" in prev_mnemonics or "POPA" in prev_mnemonics
                pushad_nearby = "PUSHAD" in prev_mnemonics or "PUSHA" in prev_mnemonics

                if popad_nearby:
                    score += 18
                    reason_parts.append("POPAD/POPA seen immediately before transfer")
                elif pushad_nearby:
                    score += 8
                    reason_parts.append("PUSHAD/PUSHA seen immediately before transfer")

                if score <= 0:
                    continue

                transition_kind = "same_section_call"
                if mnemonic == "JMP" and not same_section:
                    transition_kind = "cross_section_jump"
                elif mnemonic == "CALL" and not same_section:
                    transition_kind = "cross_section_call"
                elif mnemonic == "JMP" and same_section:
                    transition_kind = "same_section_jump"

                add_or_replace_candidate(
                    candidate_map,
                    {
                        "address": target_str,
                        "section": target_section,
                        "score": score,
                        "instruction": str(instr),
                        "reason": "; ".join(reason_parts),
                        "transition_kind": transition_kind,
                        "late_transfer": late_transfer,
                        "popad_nearby": popad_nearby,
                        "pushad_nearby": pushad_nearby,
                        "target_function": target_func_name,
                        "memory_backed": True,
                        "target_is_executable": True,
                    },
                )

        instr = instr.getNext()
        scanned += 1

    entry_str = str(entry)
    if entry_str not in candidate_map:
        candidate_map[entry_str] = {
            "address": entry_str,
            "section": entrypoint_info["section"],
            "score": 1,
            "instruction": "entrypoint",
            "reason": "fallback entrypoint candidate",
            "transition_kind": "fallback_entrypoint",
            "late_transfer": False,
            "popad_nearby": False,
            "pushad_nearby": False,
            "target_function": None,
            "memory_backed": True,
            "target_is_executable": entrypoint_info.get("section_is_executable", False),
        }

    candidates = list(candidate_map.values())
    candidates = sorted(candidates, key=lambda x: (-x["score"], x["address"]))
    return candidates[:10]


def detect_packer_family_hint(section_info, external_symbols, entrypoint_info, classic_patterns):
    section_names = set([sec["name"] for sec in section_info])
    symbol_set = set(external_symbols)

    if "UPX0" in section_names or "UPX1" in section_names or "UPX2" in section_names:
        return "UPX-like"

    if ".aspack" in section_names:
        return "ASPack-like"

    if len(classic_patterns) > 0 and ("VirtualAlloc" in symbol_set or "VirtualProtect" in symbol_set or "GetProcAddress" in symbol_set or "LoadLibraryW" in symbol_set or "LoadLibraryA" in symbol_set):
        return "generic runtime unpacking"

    if entrypoint_info["section"] in SUSPICIOUS_SECTION_NAMES:
        return "packed/loader stub section"

    return "unknown"


def build_packer_analysis(section_info, entrypoint_info, external_symbols, suspicious_apis):
    indicators = []
    score = 0

    suspicious_sections = [sec for sec in section_info if sec["suspicious"]]
    executable_nonstandard = [sec for sec in section_info if sec["execute"] and not is_standard_code_section_name(sec["name"])]

    high_entropy_sections = [sec for sec in section_info if sec.get("entropy") is not None and sec["entropy"] >= HIGH_ENTROPY_THRESHOLD]

    high_entropy_executable = [sec for sec in high_entropy_sections if sec["execute"]]

    entrypoint_section_record = get_section_record(section_info, entrypoint_info["section"])

    if len(suspicious_sections) > 0:
        indicators.append(
            {
                "name": "suspicious_sections",
                "score": 20,
                "reason": "one or more sections look packer-like or executable+writable",
                "sections": [sec["name"] for sec in suspicious_sections[:8]],
            }
        )
        score += 20

    if entrypoint_info["section"] in SUSPICIOUS_SECTION_NAMES:
        indicators.append(
            {
                "name": "entrypoint_in_suspicious_section",
                "score": 25,
                "reason": "entrypoint located inside suspicious section",
            }
        )
        score += 25

    if entrypoint_info["section_is_writable"] and entrypoint_info["section_is_executable"]:
        indicators.append(
            {
                "name": "entrypoint_in_rwx_section",
                "score": 20,
                "reason": "entrypoint section is writable and executable",
            }
        )
        score += 20

    if len(external_symbols) < 20:
        indicators.append(
            {
                "name": "very_small_import_surface",
                "score": 15,
                "reason": "few external symbols may indicate packing or stub behavior",
            }
        )
        score += 15
    elif len(external_symbols) < 40:
        indicators.append(
            {
                "name": "small_import_surface",
                "score": 8,
                "reason": "reduced import surface may indicate loader/stub behavior",
            }
        )
        score += 8

    normalized_external = normalize_api_list(external_symbols)
    normalized_packer_hints = normalize_api_list(list(PACKER_API_HINTS))

    packer_api_hits = [api_name for api_name in normalized_external if api_name in normalized_packer_hints]

    if ("GetProcAddress" in packer_api_hits or "LoadLibrary" in packer_api_hits) and ("VirtualAlloc" in packer_api_hits or "VirtualAllocEx" in packer_api_hits or "VirtualProtect" in packer_api_hits or "VirtualProtectEx" in packer_api_hits):
        indicators.append(
            {
                "name": "runtime_unpacking_apis",
                "score": 20,
                "reason": "memory allocation/protection plus dynamic resolver APIs detected",
                "matched_apis": sorted(packer_api_hits),
            }
        )
        score += 20

    if len(executable_nonstandard) > 0:
        indicators.append(
            {
                "name": "nonstandard_executable_sections",
                "score": 10,
                "reason": "non-standard executable sections present",
                "count": len(executable_nonstandard),
                "sections": [sec["name"] for sec in executable_nonstandard[:8]],
            }
        )
        score += 10

    if len(high_entropy_sections) > 0:
        indicators.append(
            {
                "name": "high_entropy_sections",
                "score": 12,
                "reason": "high entropy sections may indicate compression, encryption, or packing",
                "sections": [sec["name"] for sec in high_entropy_sections[:8]],
            }
        )
        score += 12

    if len(high_entropy_executable) > 0:
        indicators.append(
            {
                "name": "high_entropy_executable_sections",
                "score": 18,
                "reason": "executable sections with high entropy are strongly consistent with stub or packed code",
                "sections": [sec["name"] for sec in high_entropy_executable[:8]],
            }
        )
        score += 18

    if entrypoint_section_record is not None and entrypoint_section_record.get("entropy") is not None:
        ep_entropy = entrypoint_section_record["entropy"]
        if ep_entropy >= HIGH_ENTROPY_THRESHOLD:
            indicators.append(
                {
                    "name": "high_entropy_entrypoint_section",
                    "score": 15,
                    "reason": "entrypoint section entropy is unusually high",
                    "entropy": ep_entropy,
                    "section": entrypoint_section_record["name"],
                }
            )
            score += 15

    if len(high_entropy_sections) > 0 and len(external_symbols) < 40:
        indicators.append(
            {
                "name": "high_entropy_plus_small_import_surface",
                "score": 10,
                "reason": "small import surface combined with high entropy is strongly packer-like",
            }
        )
        score += 10

    confidence = "low"
    if score >= 75:
        confidence = "high"
    elif score >= 40:
        confidence = "medium"

    return {
        "packed_likelihood_score": score,
        "likely_packed": score >= 45,
        "confidence": confidence,
        "indicators": indicators,
        "suspicious_section_count": len(suspicious_sections),
        "high_entropy_section_count": len(high_entropy_sections),
        "high_entropy_executable_count": len(high_entropy_executable),
        "entrypoint_section_entropy": entrypoint_section_record.get("entropy") if entrypoint_section_record else None,
    }


def enrich_packer_analysis_with_patterns(packer_analysis, classic_patterns, oep_candidates, packer_family_hint):
    score = packer_analysis["packed_likelihood_score"]
    indicators = list(packer_analysis["indicators"])
    analysis_notes = []

    for pattern in classic_patterns:
        indicators.append(pattern)
        score += pattern["score"]

    top_candidate = oep_candidates[0] if len(oep_candidates) > 0 else None

    if top_candidate is not None and top_candidate["score"] >= 35:
        indicators.append(
            {
                "name": "strong_oep_candidate",
                "score": 15,
                "reason": "cross-section transfer based OEP candidate found near entrypoint",
                "candidate": top_candidate["address"],
            }
        )
        score += 15

    if top_candidate is not None and top_candidate.get("popad_nearby", False):
        indicators.append(
            {
                "name": "popad_backed_oep_transition",
                "score": 10,
                "reason": "top OEP candidate is preceded by POPAD/POPA-like transfer behavior",
                "candidate": top_candidate["address"],
            }
        )
        score += 10

    if top_candidate is not None and top_candidate.get("late_transfer", False):
        indicators.append(
            {
                "name": "late_stub_handoff",
                "score": 8,
                "reason": "top candidate appears as a later transfer deeper in the entry stub window",
                "candidate": top_candidate["address"],
            }
        )
        score += 8

    likely_packed = score >= 45

    confidence = "low"
    if score >= 75:
        confidence = "high"
    elif score >= 40:
        confidence = "medium"

    status = "packer-like indicators detected" if likely_packed else "executable does not appear packed"

    family = packer_family_hint
    if not likely_packed and family == "unknown":
        family = "none"

    if likely_packed:
        analysis_notes.append("Static view may be dominated by unpacking or loader stub logic rather than the final payload logic.")

    if top_candidate is not None:
        analysis_notes.append(
            "Top OEP candidate: {} in section {} ({})".format(
                top_candidate["address"],
                top_candidate["section"],
                top_candidate["reason"],
            )
        )

    result = dict(packer_analysis)
    result.update(
        {
            "packed_likelihood_score": score,
            "likely_packed": likely_packed,
            "confidence": confidence,
            "packer_family_hint": family,
            "status": status,
            "indicators": indicators,
            "oep_candidate_summary": top_candidate,
            "analysis_notes": analysis_notes,
        }
    )

    return result


def apply_benign_packer_adjustments(packer_analysis, section_info, entrypoint_info, external_symbols, functions):
    updated = dict(packer_analysis)

    score = int(updated.get("packed_likelihood_score", 0))
    notes = list(updated.get("analysis_notes", []))

    ui_hits = len([x for x in external_symbols if x in BENIGN_UI_APIS])
    high_risk_function_count = len([f for f in functions if f.get("risk_level") in ["high", "critical"]])

    resource_like_high_entropy = [sec for sec in section_info if sec.get("entropy_class") == "high" and str(sec.get("name", "")).lower() in [".rsrc", "rsrc", "resource"]]
    non_resource_high_entropy = [sec for sec in section_info if sec.get("entropy_class") == "high" and str(sec.get("name", "")).lower() not in [".rsrc", "rsrc", "resource"]]
    high_entropy_exec = [sec for sec in section_info if sec.get("entropy_class") == "high" and sec.get("execute", False)]

    if len(resource_like_high_entropy) > 0 and len(non_resource_high_entropy) == 0:
        score -= 10
        notes.append("Resource-only entropy was de-emphasized because high entropy limited to resource-like sections is common in benign software.")

    if ui_hits >= 10 and entrypoint_info.get("section") == ".text" and len(high_entropy_exec) == 0:
        score -= 8
        notes.append("Desktop GUI entrypoint profile in .text without executable high-entropy sections reduced packing confidence.")

    if ui_hits >= 8 and high_risk_function_count == 0 and updated.get("packer_family_hint") == "generic runtime unpacking":
        updated["packer_family_hint"] = "none"
        notes.append("Generic runtime unpacking hint was cleared because only benign startup/loader-like transfers were observed.")

    if score < 0:
        score = 0

    updated["packed_likelihood_score"] = score
    updated["likely_packed"] = score >= 45

    if score >= 55:
        updated["confidence"] = "high"
    elif score >= 30:
        updated["confidence"] = "medium"
    else:
        updated["confidence"] = "low"

    if not updated["likely_packed"] and updated.get("packer_family_hint") in ["unknown", "generic runtime unpacking", "", None]:
        updated["packer_family_hint"] = "none"

    updated["analysis_notes"] = notes

    if updated["likely_packed"]:
        updated["status"] = "packer-like indicators detected"
    else:
        updated["status"] = "executable does not appear packed"

    return updated


def build_analyst_targets(top_functions):
    targets = []

    for func in top_functions[:8]:
        reasons = []
        checks = []

        if func.get("reason_summary"):
            reasons.append(func["reason_summary"])
        elif func.get("primary_reason"):
            reasons.append(func["primary_reason"])

        if func["structure_role"] == "dispatcher":
            checks.append("follow the highest fan-out internal branches first")

        if func["structure_role"] == "initializer":
            checks.append("inspect bootstrap/setup logic and first-stage callees")

        evidence = func.get("evidence", {})

        if evidence.get("local_api_hits"):
            checks.append("validate suspicious API call sites and argument flow")

        if evidence.get("referenced_string_samples"):
            checks.append("inspect string xrefs and nearby basic blocks")

        if evidence.get("top_score_drivers"):
            checks.append("confirm the top local score drivers in disassembly and decompiler")

        if not reasons:
            reasons.append("high local score")

        if not checks:
            checks.append("inspect core control flow and first-level callees")

        targets.append(
            {
                "name": func["name"],
                "entry": func["entry"],
                "score": func["score"],
                "risk_level": func["risk_level"],
                "why": "; ".join(reasons) + ".",
                "what_to_check": "; ".join(checks) + ".",
            }
        )

    return targets


def build_analyst_playbook(behavior_story, top_functions, summary, oep_candidates=None):
    steps = []
    oep_candidates = oep_candidates or []

    if summary.get("packed_warning"):
        steps.append("Treat static score and behavior inference with caution because the sample appears packed; prioritize unpacking stub review and likely OEP recovery.")

        if len(oep_candidates) > 0:
            top_oep = oep_candidates[0]
            steps.append(f"Validate top OEP candidate {top_oep['address']} in section {top_oep['section']} ({top_oep['reason']}).")

    if len(behavior_story["entry_candidates"]) > 0:
        first_entry = behavior_story["entry_candidates"][0]
        steps.append(f"Start from entry candidate {first_entry['name']} and inspect its outgoing internal calls.")

    if len(behavior_story["primary_dispatchers"]) > 0:
        first_dispatcher = behavior_story["primary_dispatchers"][0]
        steps.append(f"Open dispatcher {first_dispatcher['name']} and follow its highest fan-out branches.")

    if len(top_functions) > 0:
        first_target = top_functions[0]
        reason = first_target.get("primary_reason")
        if reason:
            steps.append(f"Review top scored function {first_target['name']} first because {reason}.")
        else:
            steps.append(f"Review top scored function {first_target['name']} for suspicious API combinations.")

    if len(behavior_story["storyline"]) > 0:
        first_story = behavior_story["storyline"][0]["path"]
        steps.append(f"Trace storyline path: {' -> '.join(first_story)}.")

    steps.append("Validate whether registry, debugger, dynamic loading, or crypto indicators reflect benign application logic or suspicious behavior.")
    steps.append("Confirm suspicious findings in Ghidra GUI through xrefs, decompiler view, and call graph inspection.")

    return {"steps": steps}


def attach_seeded_typed_graph(report, seeded_enabled, typed_graph):
    """Attach the complete graph only for explicit seeded analyses.

    This small boundary is intentionally testable so Step 2.12 can guarantee
    that legacy raw reports remain unchanged when ``-seeded`` is absent.
    """

    if seeded_enabled:
        if typed_graph is None:
            raise ValueError("seeded analysis requires a typed_graph payload")
        report["typed_graph"] = typed_graph

    return report


def build_report(seeded_enabled=False):
    analysis_metadata = build_analysis_metadata()

    program_name = currentProgram.getName()
    executable_path = currentProgram.getExecutablePath()
    executable_format = currentProgram.getExecutableFormat()

    sample_name = str(program_name) if program_name else "unknown"
    sample_info = {
        "name": sample_name,
        "path": str(executable_path) if executable_path else "",
        "format": str(executable_format) if executable_format else "unknown",
    }

    external_symbols = get_external_symbols()
    suspicious_apis = get_suspicious_apis(external_symbols)
    strings = get_strings()
    interesting_strings = analyze_interesting_strings(strings)

    section_info = collect_section_info()
    entrypoint_info = get_entrypoint_info()
    entry_window = collect_entrypoint_instruction_window()
    classic_patterns = detect_classic_unpacking_patterns(entry_window)
    oep_candidates = find_oep_candidates(entrypoint_info)

    packer_family_hint = detect_packer_family_hint(
        section_info,
        external_symbols,
        entrypoint_info,
        classic_patterns,
    )

    packer_analysis = build_packer_analysis(
        section_info,
        entrypoint_info,
        external_symbols,
        suspicious_apis,
    )

    packer_analysis = enrich_packer_analysis_with_patterns(
        packer_analysis,
        classic_patterns,
        oep_candidates,
        packer_family_hint,
    )

    capabilities = detect_capabilities(external_symbols)

    typed_graph = build_seeded_typed_graph(section_info=section_info) if seeded_enabled else None

    functions = get_base_functions()
    functions = enrich_functions(functions, interesting_strings)
    functions = apply_incoming_call_counts(functions)
    functions = assign_structure_roles(functions)

    top_functions = build_top_functions(functions)

    capabilities = reconcile_capabilities_with_local_evidence(
        capabilities,
        functions,
        top_functions,
        external_symbols,
    )

    callgraph = build_callgraph(functions)
    behavior_clusters = build_behavior_clusters(functions)
    execution_flow_hypotheses = build_execution_flow_hypotheses(functions)
    three_hop_flows = build_three_hop_flows(functions)
    function_role_summary = build_function_role_summary(functions)
    behavior_summary = build_behavior_summary(
        functions,
        capabilities,
        execution_flow_hypotheses,
        three_hop_flows,
    )
    behavior_story = build_behavior_story(
        functions,
        execution_flow_hypotheses,
        three_hop_flows,
    )

    packer_analysis = apply_benign_packer_adjustments(
        packer_analysis,
        section_info,
        entrypoint_info,
        external_symbols,
        functions,
    )

    raw_score = compute_raw_score(
        suspicious_apis,
        capabilities,
        interesting_strings,
        top_functions,
        packer_analysis,
    )

    benign_contexts = detect_benign_contexts(
        external_symbols,
        interesting_strings,
        functions,
    )

    adjusted_score, score_adjustments = apply_score_adjustments(
        raw_score,
        benign_contexts,
    )

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
        packer_analysis,
    )

    analyst_summary = build_analyst_summary(
        summary,
        behavior_summary,
        capabilities,
        top_functions,
        score_adjustments,
    )

    analyst_targets = build_analyst_targets(top_functions)

    analyst_playbook = build_analyst_playbook(
        behavior_story,
        top_functions,
        summary,
        oep_candidates,
    )

    report = {
        "analysis_metadata": analysis_metadata,
        "rule_contract": build_rule_contract(),
        "sample": sample_info,
        "summary": summary,
        "global_analysis": {
            "external_symbols": external_symbols,
            "suspicious_apis": suspicious_apis,
            "capabilities": capabilities,
            "interesting_strings": interesting_strings,
            "strings": strings,
            "benign_contexts": benign_contexts,
            "score_adjustments": score_adjustments,
        },
        "function_analysis": {
            "functions": functions,
            "top_functions": top_functions,
            "function_role_summary": function_role_summary,
        },
        "behavior_analysis": {
            "callgraph": callgraph,
            "behavior_clusters": behavior_clusters,
            "execution_flow_hypotheses": execution_flow_hypotheses,
            "three_hop_flows": three_hop_flows,
            "behavior_summary": behavior_summary,
            "behavior_story": behavior_story,
        },
        "binary_structure": {
            "packer_analysis": packer_analysis,
            "entrypoint_info": entrypoint_info,
            "entrypoint_window": entry_window,
            "oep_candidates": oep_candidates,
            "section_info": section_info,
        },
        "analyst_output": {
            "analyst_summary": analyst_summary,
            "analyst_targets": analyst_targets,
            "analyst_playbook": analyst_playbook,
        },
    }

    attach_seeded_typed_graph(
        report,
        seeded_enabled,
        typed_graph,
    )

    return report


def parse_seeded_script_arg(script_args):
    if len(script_args) <= 2:
        return False

    seeded_args = [str(arg).strip().lower() for arg in script_args[2:]]
    return "seeded=true" in seeded_args


def main():
    script_args = getScriptArgs()
    output_dir = script_args[0] if len(script_args) > 0 else "."
    output_path = os.path.join(output_dir, "raw_report.json")

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    load_external_rules(script_args)

    seeded_enabled = parse_seeded_script_arg(script_args)
    report = build_report(seeded_enabled=seeded_enabled)

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print("[+] Report written to: {}".format(output_path))


if __name__ == "__main__":
    main()
