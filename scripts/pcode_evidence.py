"""Independent experimental P-code evidence contract; no legacy graph imports."""

import copy
import json
import re

SCHEMA = "osgf.pcode-evidence/0.1.0"
FAMILIES = {
    "arithmetic": "INT_ADD INT_SUB INT_MULT INT_DIV INT_SDIV INT_REM INT_SREM INT_NEGATE INT_2COMP INT_CARRY INT_SCARRY INT_SBORROW",
    "bitwise": "INT_AND INT_OR INT_XOR INT_LEFT INT_RIGHT INT_SRIGHT",
    "boolean": "BOOL_AND BOOL_OR BOOL_XOR BOOL_NEGATE",
    "predicate": "INT_EQUAL INT_NOTEQUAL INT_LESS INT_SLESS INT_LESSEQUAL INT_SLESSEQUAL",
    "memory": "LOAD STORE PTRADD PTRSUB",
    "control": "BRANCH CBRANCH BRANCHIND CALL CALLIND RETURN",
    "transfer": "COPY CAST INT_ZEXT INT_SEXT PIECE SUBPIECE",
    "analysis": "MULTIEQUAL INDIRECT",
}
OP_FAMILY = {op: family for family, ops in FAMILIES.items() for op in ops.split()}
SIGNED = {"INT_SDIV", "INT_SREM", "INT_SRIGHT", "INT_SLESS", "INT_SLESSEQUAL", "INT_SEXT", "INT_SCARRY", "INT_SBORROW"}
UNSIGNED = {"INT_DIV", "INT_REM", "INT_RIGHT", "INT_LESS", "INT_LESSEQUAL", "INT_ZEXT", "INT_CARRY"}
STATES = {"complete", "partial", "unavailable", "timeout", "cancelled", "failed"}
CONTROL_BARRIERS = {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "CALLOTHER", "RETURN", "UNIMPLEMENTED"}


def raw_links(operations):
    """Reconstruct only straight-line instruction-prefix unique-storage links."""
    local, links, address, straight = {}, set(), None, True
    for op in sorted(operations, key=lambda op: int(op["id"].split(":")[1])):
        if op["origin"]["address"] != address:
            local, address, straight = {}, op["origin"]["address"], True
        for slot, value in enumerate(op["inputs"]):
            key = (value["space"], value["offset"], value["width"])
            if value["kind"] == "unique" and key in local:
                links.add((local[key], op["id"], slot))
        if op["opcode"] in CONTROL_BARRIERS:
            local, straight = {}, False
        output = op["output"]
        if output is not None:
            start = int(output["offset"], 16)
            local = {key: owner for key, owner in local.items() if key[0] != output["space"] or int(key[1], 16) + key[2] <= start or start + output["width"] <= int(key[1], 16)}
            if output["kind"] == "unique" and straight:
                local[(output["space"], output["offset"], output["width"])] = op["id"]
    return links


def require(condition, message):
    if not condition:
        raise ValueError(message)


def semantics(opcode):
    return {"family": OP_FAMILY.get(opcode, "unsupported"), "signedness": "signed" if opcode in SIGNED else "unsigned" if opcode in UNSIGNED else "not_asserted"}


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected.split()), "invalid object fields: " + expected)


def operand(value):
    keys(value, "kind width space offset")
    require(value["kind"] in {"constant", "register", "unique", "memory", "other"}, "invalid operand kind")
    require(integer(value["width"], 1), "invalid width")
    require(isinstance(value["space"], str) and bool(value["space"]), "missing address space")
    require(isinstance(value["offset"], str) and re.fullmatch(r"[0-9a-f]+", value["offset"]), "invalid operand offset")
    if value["kind"] == "constant":
        require(int(value["offset"], 16).bit_length() <= value["width"] * 8, "constant exceeds width")


def validate(doc):
    keys(doc, "schema_version source function environment representation configuration operations dependencies observability warnings")
    require(doc["schema_version"] == SCHEMA, "unsupported schema version")
    keys(doc["source"], "binary sha256")
    require(isinstance(doc["source"]["binary"], str) and bool(doc["source"]["binary"]), "missing binary")
    require(isinstance(doc["source"]["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", doc["source"]["sha256"]), "invalid source hash")
    keys(doc["function"], "id entry name")
    require(isinstance(doc["function"]["entry"], str) and bool(re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]*:)?[0-9a-fA-F]+", doc["function"]["entry"])), "invalid function entry")
    require(doc["function"]["id"] == "fn:" + doc["function"]["entry"], "inconsistent function identity")
    require(bool(doc["function"]["entry"]) and isinstance(doc["function"]["name"], str), "invalid function")
    keys(doc["environment"], "ghidra_version ghidra_revision language compiler_spec analysis_policy")
    require(all(isinstance(v, str) and v for v in doc["environment"].values()), "missing environment identity")
    require(doc["representation"] in {"raw", "high"}, "invalid representation")
    keys(doc["configuration"], "max_operations max_dependencies timeout_seconds simplification override_policy")
    for field in ("max_operations", "max_dependencies", "timeout_seconds"):
        require(integer(doc["configuration"][field], 1), "invalid budget")
    require(doc["configuration"]["simplification"] == "decompile" and doc["configuration"]["override_policy"] == "instruction-default", "unsupported extraction policy")
    keys(doc["observability"], "state reason operations_seen dependencies_seen unresolved_inputs truncated")
    obs = doc["observability"]
    require(obs["state"] in STATES and isinstance(obs["reason"], str) and type(obs["truncated"]) is bool, "invalid observability")
    for field in ("operations_seen", "dependencies_seen", "unresolved_inputs"):
        require(integer(obs[field]), "invalid observation count")
    require(isinstance(doc["warnings"], list) and all(isinstance(w, str) for w in doc["warnings"]) and len(set(doc["warnings"])) == len(doc["warnings"]), "invalid warnings")
    require(isinstance(doc["operations"], list) and isinstance(doc["dependencies"], list), "invalid collections")
    ops = {}
    for op in doc["operations"]:
        keys(op, "id opcode semantics inputs output origin")
        require(isinstance(op["id"], str) and re.fullmatch(r"op:[0-9]+", op["id"]), "invalid operation ID")
        require(op["id"] not in ops, "duplicate operation")
        ops[op["id"]] = op
        require(isinstance(op["opcode"], str) and bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", op["opcode"])), "invalid opcode")
        require(op["semantics"] == semantics(op["opcode"]), "inconsistent opcode semantics")
        keys(op["origin"], "address sequence")
        require(isinstance(op["origin"]["address"], str) and bool(op["origin"]["address"]) and integer(op["origin"]["sequence"]), "invalid origin")
        require(isinstance(op["inputs"], list), "invalid inputs")
        for value in op["inputs"]:
            operand(value)
        if op["output"] is not None:
            operand(op["output"])
    origins = {(op["origin"]["address"], op["origin"]["sequence"]) for op in ops.values()}
    require(len(origins) == len(ops), "duplicate operation provenance")
    require(set(ops) == {"op:" + str(i) for i in range(len(ops))}, "noncontiguous operation IDs")
    edges = set()
    targets = set()
    for dep in doc["dependencies"]:
        keys(dep, "from to input basis")
        require(dep["from"] in ops and dep["to"] in ops, "dangling dependency")
        require(integer(dep["input"]) and dep["input"] < len(ops[dep["to"]]["inputs"]), "invalid input slot")
        require(dep["basis"] == ("instruction-local-unique" if doc["representation"] == "raw" else "recovered-ssa"), "invalid dependency basis")
        source, target = ops[dep["from"]], ops[dep["to"]]
        require(source["output"] is not None and source["output"] == target["inputs"][dep["input"]], "inconsistent dependency storage")
        if doc["representation"] == "raw":
            require(source["origin"]["address"] == target["origin"]["address"] and source["origin"]["sequence"] < target["origin"]["sequence"] and source["output"]["kind"] == "unique", "unproven raw dependency")
        edge = (dep["from"], dep["to"], dep["input"])
        require(edge not in edges and (dep["to"], dep["input"]) not in targets, "duplicate/conflicting dependency")
        edges.add(edge)
        targets.add((dep["to"], dep["input"]))
    if doc["representation"] == "raw":
        expected = raw_links(doc["operations"])
        require(edges <= expected, "raw dependency crosses a write or control barrier")
        if not obs["truncated"]:
            require(edges == expected, "missing proven raw dependency")
    require(len(ops) <= doc["configuration"]["max_operations"] and len(edges) <= doc["configuration"]["max_dependencies"], "budget exceeded")
    require(obs["operations_seen"] >= len(ops) and obs["dependencies_seen"] >= len(edges), "inconsistent observed counts")
    lost = obs["operations_seen"] > len(ops) or obs["dependencies_seen"] > len(edges)
    require(not lost or obs["truncated"], "missing truncation")
    require(not obs["truncated"] or obs["state"] == "partial", "truncation must be partial")
    if obs["state"] == "complete":
        require(not lost and not obs["truncated"], "inconsistent completeness")
    if obs["state"] in {"unavailable", "timeout", "failed", "cancelled"}:
        require(not ops and not edges and bool(obs["reason"]), "invalid unavailable evidence")
    return doc


def serialize(doc):
    validate(doc)
    result = copy.deepcopy(doc)
    result["operations"].sort(key=lambda op: int(op["id"].split(":")[1]))
    result["dependencies"].sort(key=lambda dep: (dep["from"], dep["to"], dep["input"]))
    result["warnings"].sort()
    return (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def loads(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    return validate(json.loads(data, object_pairs_hook=unique))
