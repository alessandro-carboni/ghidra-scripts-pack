"""Opt-in recovered-parameter, effect-slice, bitvector and role-family fingerprints."""

import argparse
import json
from pathlib import Path

try:
    from .recovered_evidence import digest, encoded, validate
    from .pcode_evidence import require
except ImportError:
    from recovered_evidence import digest, encoded, validate
    from pcode_evidence import require

SCHEMA = "osgf.semantic-flow-fingerprint/0.1.0"
DEPTH = 8
VISITS = 100000
COMMUTATIVE = {"INT_ADD", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR", "INT_EQUAL", "INT_NOTEQUAL"}
EFFECTS = {"RETURN", "STORE", "CALL", "CALLIND", "CALLOTHER", "LOAD", "INDIRECT", "UNIMPLEMENTED", "BRANCHIND"}


def control_dependencies(doc):
    """Postdominance with a virtual exit; non-exiting/partial CFG conservatively falls back."""
    ops = {o["id"]: o for o in doc["source"]["operations"]}
    branches = {i for i, o in ops.items() if o["opcode"] in {"CBRANCH", "BRANCHIND"}}
    blocks = {b["id"]: set(b["successors"]) for b in doc["blocks"]}
    if doc["cfg_status"] != "complete" or not blocks or len(blocks) > 512:
        return {i: set(branches) for i in ops}, "all-conditions-overapproximation"
    exits = {i for i, successors in blocks.items() if not successors}
    reaches = set(exits)
    while True:
        new = reaches | {i for i, successors in blocks.items() if successors & reaches}
        if new == reaches:
            break
        reaches = new
    if reaches != set(blocks):
        return {i: set(branches) for i in ops}, "non-exiting-CFG-overapproximation"
    end = "virtual-exit"
    universe = set(blocks) | {end}
    pd = {i: set(universe) for i in blocks}
    pd[end] = {end}
    for _ in range(len(blocks) + 1):
        updated = {i: {i} | set.intersection(*(pd[s] for s in successors or {end})) for i, successors in blocks.items()}
        updated[end] = {end}
        if updated == pd:
            break
        pd = updated
    else:
        return {i: set(branches) for i in ops}, "postdominance-budget-overapproximation"
    controls = {i: set() for i in ops}
    for branch in branches:
        b = doc["operation_blocks"][branch]
        dependent = set().union(*(pd[s] - pd[b] for s in blocks[b])) if blocks[b] else set()
        for ident in ops:
            if doc["operation_blocks"][ident] in dependent:
                controls[ident].add(branch)
    return controls, "recovered-CFG-postdominance"


def slice_effects(doc):
    ops = {o["id"]: o for o in doc["source"]["operations"]}
    roots = {i for i, o in ops.items() if o["opcode"] in EFFECTS or o["semantics"]["family"] == "unsupported" or (o["output"] and (o["output"]["kind"] == "memory" or o["output"]["space"] == "stack"))}
    predecessors = {i: set() for i in ops}
    for d in doc["source"]["dependencies"]:
        predecessors[d["to"]].add(d["from"])
    controls, policy = control_dependencies(doc)
    retained, work = set(roots), list(sorted(roots))
    while work:
        ident = work.pop()
        for upstream in sorted(predecessors[ident] | controls[ident]):
            if upstream not in retained:
                retained.add(upstream)
                work.append(upstream)
    guards = set().union(*(controls[i] for i in retained)) if retained else set()
    return roots, retained, guards, policy


def rewrite(opcode, width, args, nodes):
    """Only fixed-width integer identities; no casts, floating point, aliases or loops."""
    if not 1 <= width <= 8 or len(args) != 2:
        return None, None
    a, b = [nodes[h] for h in args]
    if a.get("width") != width or b.get("width") != width:
        return None, None
    mask = (1 << (8 * width)) - 1
    ca = a.get("bits") if a.get("kind") == "constant" else None
    cb = b.get("bits") if b.get("kind") == "constant" else None
    if opcode in {"INT_ADD", "INT_OR", "INT_XOR"}:
        if ca == 0:
            return args[1], "neutral-zero"
        if cb == 0:
            return args[0], "neutral-zero"
    if opcode == "INT_SUB" and cb == 0:
        return args[0], "subtract-zero"
    if opcode == "INT_MULT" and (ca == 1 or cb == 1):
        return args[1] if ca == 1 else args[0], "multiply-one"
    if opcode == "INT_AND" and (ca == mask or cb == mask):
        return args[1] if ca == mask else args[0], "and-full-mask"
    if ca is not None and cb is not None:
        functions = {"INT_ADD": lambda: ca + cb, "INT_SUB": lambda: ca - cb, "INT_MULT": lambda: ca * cb, "INT_AND": lambda: ca & cb, "INT_OR": lambda: ca | cb, "INT_XOR": lambda: ca ^ cb}
        if opcode in functions:
            value = dict(kind="constant", width=width, bits=functions[opcode]() & mask)
            h = digest(value)
            nodes[h] = value
            return h, "modular-constant-fold"
    return None, None


class Expressions:
    def __init__(self, doc, parameters, algebra):
        self.doc, self.parameters, self.algebra = doc, parameters, algebra
        self.ops = {o["id"]: o for o in doc["source"]["operations"]}
        self.links = {(d["to"], d["input"]): d["from"] for d in doc["source"]["dependencies"]}
        self.params = {(p["operation"], p["input"]): p for p in doc["parameters"]}
        self.nodes, self.ledger, self.barriers = {}, set(), set()
        self.visits = 0

    def intern(self, value):
        h = digest(value)
        self.nodes[h] = value
        return h

    def input(self, ident, slot, depth, seen):
        v = self.ops[ident]["inputs"][slot]
        if (ident, slot) in self.links:
            return self.operation(self.links[ident, slot], depth + 1, seen)
        if self.parameters and (ident, slot) in self.params:
            return self.intern(dict(kind="parameter", slot=self.params[ident, slot]["slot"], width=v["width"]))
        if v["kind"] == "constant":
            return self.intern(dict(kind="constant", width=v["width"], bits=int(v["offset"], 16)))
        return self.intern(dict(kind="unresolved", storage=v))

    def operation(self, ident, depth=0, seen=frozenset()):
        op = self.ops[ident]
        width = op["output"]["width"] if op["output"] else 0
        if ident in seen or depth >= DEPTH or self.visits >= VISITS:
            reason = "cycle" if ident in seen else "depth" if depth >= DEPTH else "visit-budget"
            self.barriers.add((ident, reason))
            return self.intern(dict(kind="cut", reason=reason, opcode=op["opcode"], width=width))
        self.visits += 1
        seen = seen | {ident}
        args = [self.input(ident, i, depth, seen) for i in range(len(op["inputs"]))]
        if op["opcode"] == "COPY" and len(args) == 1 and self.nodes[args[0]].get("width") == width:
            self.ledger.add((ident, "equal-width-copy"))
            return args[0]
        if self.algebra:
            result, rule = rewrite(op["opcode"], width, args, self.nodes)
            if result is not None:
                self.ledger.add((ident, rule))
                return result
        if op["opcode"] in COMMUTATIVE:
            args.sort()
        return self.intern(dict(kind="operation", opcode=op["opcode"], signedness=op["semantics"]["signedness"], width=width, inputs=args))

    def effect(self, ident):
        op = self.ops[ident]
        # RETURN input0 is the control target, not the returned value. Preserve its role separately.
        start = 1 if op["opcode"] == "RETURN" else 0
        args = [self.input(ident, i, 0, {ident}) for i in range(start, len(op["inputs"]))]
        out = op["output"]
        return dict(effect=op["opcode"], inputs=args, output_width=out["width"] if out else None, memory_destination=out if out and (out["kind"] == "memory" or out["space"] == "stack") else None, return_payload_recovered=bool(args) if start else None)


def fingerprint(doc):
    validate(doc)
    roots, retained, guards, control_policy = slice_effects(doc)
    ops = {o["id"]: o for o in doc["source"]["operations"]}
    views = {}
    for name, parameters, algebra, effects in [("physical", False, False, False), ("parameters", True, False, False), ("effects", True, False, True), ("algebra", True, True, True)]:
        builder = Expressions(doc, parameters, algebra)
        features = {}

        def add(descriptor, ident):
            key = digest(descriptor)
            features.setdefault(key, dict(descriptor=descriptor, occurrences=[]))["occurrences"].append(ident)

        if effects:
            for ident in sorted(roots):
                add(builder.effect(ident), ident)
            for ident in sorted(guards):
                add(dict(role="control-predicate", expression=builder.operation(ident)), ident)
        else:
            for ident in sorted(ops):
                add(dict(role="operation", expression=builder.operation(ident)), ident)
        features = [dict(id=k, descriptor=v["descriptor"], count=len(v["occurrences"]), occurrences=sorted(v["occurrences"])) for k, v in sorted(features.items())]
        views[name] = dict(features=features, expressions=builder.nodes, rewrites=[list(v) for v in sorted(builder.ledger)], barriers=[list(v) for v in sorted(builder.barriers)])
    families = {}
    for ident in sorted(retained):
        op = ops[ident]
        role = "effect" if ident in roots else "control" if ident in guards else "data"
        descriptor = dict(
            role=role,
            family=op["semantics"]["family"],
            opcode=op["opcode"],
            signedness=op["semantics"]["signedness"],
            input_widths=[v["width"] for v in op["inputs"]],
            output_width=op["output"]["width"] if op["output"] else None,
            constants=[dict(slot=i, width=v["width"], bits=int(v["offset"], 16)) for i, v in enumerate(op["inputs"]) if v["kind"] == "constant"],
        )
        key = digest(descriptor)
        families.setdefault(key, dict(descriptor=descriptor, occurrences=[]))["occurrences"].append(ident)
    views["families"] = dict(features=[dict(id=k, count=len(v["occurrences"]), **v) for k, v in sorted(families.items())], expressions={}, rewrites=[], barriers=[])
    science = {k: [dict(descriptor=f["descriptor"], count=f["count"]) for f in v["features"]] for k, v in views.items()}
    warnings = set(doc["warnings"])
    if any(o["opcode"] in {"LOAD", "STORE", "INDIRECT", "CALL", "CALLIND", "CALLOTHER"} for o in ops.values()):
        warnings.add("memory aliases, volatility and call effects are not proven; operations retained")
    if control_policy != "recovered-CFG-postdominance":
        warnings.add(control_policy)
    return dict(schema_version=SCHEMA, source=doc, views=views, slice=dict(roots=sorted(roots), retained=sorted(retained), guards=sorted(guards), control_policy=control_policy), warnings=sorted(warnings), semantic_digest=digest(dict(schema=SCHEMA, depth=DEPTH, visits=VISITS, views=science)))


def jaccard(q, r):
    keys = q.keys() | r.keys()
    if not keys:
        return dict(set_similarity=None, multiset_similarity=None)
    return dict(set_similarity=len(q.keys() & r.keys()) / len(keys), multiset_similarity=sum(min(q.get(k, 0), r.get(k, 0)) for k in keys) / sum(max(q.get(k, 0), r.get(k, 0)) for k in keys))


def compare(q, r):
    for f in (q, r):
        require(f == fingerprint(f["source"]), "fingerprint reconstruction mismatch")
    qs, rs = q["source"]["source"], r["source"]["source"]
    require(qs["environment"] == rs["environment"] and qs["configuration"] == rs["configuration"], "incompatible extraction domains")
    usable = all(d["observability"]["state"] in {"complete", "partial"} for d in (qs, rs))
    views = {}
    for key in q["views"]:
        counts = [{f["id"]: f["count"] for f in d["views"][key]["features"]} for d in (q, r)]
        score = jaccard(*counts) if usable else dict(set_similarity=None, multiset_similarity=None)
        score["comparison_complete"] = usable and all(d["source"]["source"]["observability"]["state"] == "complete" and not d["views"][key]["barriers"] and not d["warnings"] for d in (q, r))
        views[key] = score
    return dict(
        schema_version="osgf.semantic-flow-similarity/0.1.0",
        query_digest=q["semantic_digest"],
        reference_digest=r["semantic_digest"],
        views=views,
        warnings=sorted(set(q["warnings"] + r["warnings"])),
        decision=None,
        policy="Recovered associations and bounded expressions, not equivalence proofs; no memory or loop rewrites",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fingerprint", "compare"))
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(len(args.inputs) == (1 if args.action == "fingerprint" else 2), "wrong input count")
    inputs = [json.loads(p.read_bytes()) for p in args.inputs]
    result = fingerprint(inputs[0]) if args.action == "fingerprint" else compare(*inputs)
    with args.output.open("xb") as stream:
        stream.write(encoded(result))
