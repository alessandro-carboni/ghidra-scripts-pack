"""Additive HighParam/CFG envelope. Associations are recovered evidence, not ABI truth."""

import hashlib
import json

try:
    from .pcode_evidence import keys, require, validate as validate_pcode, integer
except ImportError:
    from pcode_evidence import keys, require, validate as validate_pcode, integer

SCHEMA = "osgf.recovered-evidence/0.1.0"


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def validate(doc):
    keys(doc, "schema_version source source_digest parameters blocks operation_blocks cfg_status warnings")
    require(doc["schema_version"] == SCHEMA, "unknown recovered schema")
    source = validate_pcode(doc["source"])
    require(source["representation"] == "high", "recovered evidence requires High")
    require(doc["source_digest"] == digest(source), "source digest mismatch")
    require(isinstance(doc["warnings"], list) and doc["warnings"] == sorted(set(doc["warnings"])) and all(isinstance(v, str) for v in doc["warnings"]), "invalid warnings")
    ops = {op["id"]: op for op in source["operations"]}
    defined = {(d["to"], d["input"]) for d in source["dependencies"]}
    seen, storage, slots = set(), {}, {}
    require(isinstance(doc["parameters"], list), "invalid parameters")
    for p in doc["parameters"]:
        keys(p, "operation input slot width basis")
        require(p["operation"] in ops and integer(p["input"]) and p["input"] < len(ops[p["operation"]]["inputs"]), "invalid parameter occurrence")
        key = p["operation"], p["input"]
        require(key not in seen and key not in defined, "parameter is duplicate or has a producer")
        seen.add(key)
        v = ops[p["operation"]]["inputs"][p["input"]]
        require(v["kind"] != "constant" and integer(p["slot"]) and integer(p["width"], 1) and p["width"] == v["width"], "invalid parameter slot/width")
        require(p["basis"] == "HighParam+input+full-width+no-def", "unverified parameter basis")
        identity = v["kind"], v["space"], v["offset"], v["width"]
        require(identity not in storage or storage[identity] == p["slot"], "conflicting parameter storage")
        require(p["slot"] not in slots or slots[p["slot"]] == identity, "ambiguous parameter instances")
        storage[identity], slots[p["slot"]] = p["slot"], identity
    require(doc["cfg_status"] in {"complete", "unavailable", "partial"}, "unknown CFG status")
    require(isinstance(doc["blocks"], list) and isinstance(doc["operation_blocks"], dict), "invalid CFG")
    blocks = {}
    for block in doc["blocks"]:
        keys(block, "id successors")
        require(isinstance(block["id"], str) and block["id"] not in blocks, "duplicate block")
        require(isinstance(block["successors"], list) and block["successors"] == sorted(set(block["successors"])), "invalid CFG successors")
        blocks[block["id"]] = block
    require(all(s in blocks for b in blocks.values() for s in b["successors"]), "dangling CFG edge")
    require(set(doc["operation_blocks"]) <= set(ops) and all(b in blocks for b in doc["operation_blocks"].values()), "invalid operation block")
    if doc["cfg_status"] == "complete":
        require(set(doc["operation_blocks"]) == set(ops), "missing operation blocks")
    return doc


def envelope(source, parameters=(), blocks=(), operation_blocks=None, cfg_status="unavailable", warnings=()):
    doc = dict(schema_version=SCHEMA, source=source, source_digest=digest(source), parameters=sorted(parameters, key=lambda p: (p["operation"], p["input"])), blocks=sorted(blocks, key=lambda b: b["id"]), operation_blocks=operation_blocks or {}, cfg_status=cfg_status, warnings=sorted(set(warnings)))
    return validate(doc)
