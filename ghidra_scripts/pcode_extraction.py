"""Bounded Raw/High extraction, with injectable Ghidra objects for failure tests."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pcode_evidence import SCHEMA, semantics, validate  # noqa: E402


def varnode(node):
    if node is None:
        return None
    kind = "constant" if node.isConstant() else "register" if node.isRegister() else "unique" if node.isUnique() else "memory" if node.isAddress() else "other"
    width = int(node.getSize())
    offset = int(node.getOffset()) & ((1 << (width * 8 if kind == "constant" else 64)) - 1)
    return dict(kind=kind, width=width, space=str(node.getAddress().getAddressSpace().getName()), offset=format(offset, "x"))


def sequence(op):
    seq = op.getSeqnum()
    return str(seq.getTarget()), int(seq.getTime())


def collect(doc, operations, monitor):
    """Iterator stops at budget + one; incomplete input discovery remains explicit."""
    retained = []
    for op in operations:
        if monitor.isCancelled():
            doc["observability"].update(state="partial", reason="analysis cancelled after partial extraction")
            break
        doc["observability"]["operations_seen"] += 1
        if len(retained) == doc["configuration"]["max_operations"]:
            doc["observability"].update(state="partial", reason="operation budget reached; seen count is a lower bound", truncated=True)
            break
        retained.append(op)
    mapping = {sequence(op): "op:" + str(i) for i, op in enumerate(retained)}
    local = {}
    current_address = None
    straight_line = True
    for op in retained:
        address, time = sequence(op)
        if current_address != address:
            local = {}
            current_address = address
            straight_line = True
        ident = mapping[(address, time)]
        inputs = list(op.getInputs())
        output = varnode(op.getOutput())
        opcode = str(op.getMnemonic())
        doc["operations"].append(dict(id=ident, opcode=opcode, semantics=semantics(opcode), inputs=[varnode(v) for v in inputs], output=output, origin=dict(address=address, sequence=time)))
        if semantics(opcode)["family"] == "unsupported":
            doc["warnings"].append("unsupported opcode: " + opcode)
        for slot, value in enumerate(inputs):
            node = varnode(value)
            source = None
            if doc["representation"] == "high":
                definition = value.getDef()
                if definition is not None:
                    source = mapping.get(sequence(definition))
            elif node["kind"] == "unique":
                source = local.get((node["space"], node["offset"], node["width"]))
            if source is not None:
                doc["observability"]["dependencies_seen"] += 1
                if len(doc["dependencies"]) < doc["configuration"]["max_dependencies"]:
                    doc["dependencies"].append(dict(**{"from": source, "to": ident, "input": slot}, basis="recovered-ssa" if doc["representation"] == "high" else "instruction-local-unique"))
                else:
                    doc["observability"].update(state="partial", reason="dependency budget reached", truncated=True)
            elif node["kind"] != "constant":
                doc["observability"]["unresolved_inputs"] += 1
        # Control transfers can skip local operations: do not infer through them.
        if opcode in {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "CALLOTHER", "RETURN", "UNIMPLEMENTED"}:
            local.clear()
            straight_line = False
        if output is not None:
            # Invalidate overlapping unique storage, not just exact-width writes.
            start = int(output["offset"], 16)
            local = {key: owner for key, owner in local.items() if key[0] != output["space"] or int(key[1], 16) + key[2] <= start or start + output["width"] <= int(key[1], 16)}
            if output["kind"] == "unique" and straight_line:
                local[(output["space"], output["offset"], output["width"])] = ident
    doc["warnings"] = sorted(set(doc["warnings"]))
    return validate(doc)


def extract(program, function, monitor, environment, representation="raw", max_operations=10000, max_dependencies=20000, timeout_seconds=30, decompiler_factory=None):
    entry = str(function.getEntryPoint())
    doc = dict(
        schema_version=SCHEMA,
        source=dict(binary=str(program.getName()), sha256=str(program.getExecutableSHA256()).lower()),
        function=dict(id="fn:" + entry, entry=entry, name=str(function.getName())),
        environment=environment,
        representation=representation,
        configuration=dict(max_operations=max_operations, max_dependencies=max_dependencies, timeout_seconds=timeout_seconds, simplification="decompile", override_policy="instruction-default"),
        operations=[],
        dependencies=[],
        observability=dict(state="complete", reason="", operations_seen=0, dependencies_seen=0, unresolved_inputs=0, truncated=False),
        warnings=["No memory alias or function argument/return ABI inference", "Raw dataflow is instruction-local only" if representation == "raw" else "High operations and SSA are decompiler-recovered associations"],
    )
    validate(doc)
    if monitor.isCancelled():
        doc["observability"].update(state="cancelled", reason="analysis cancelled")
        return validate(doc)
    if representation == "raw":
        instructions = program.getListing().getInstructions(function.getBody(), True)
        return collect(doc, (op for instruction in instructions for op in instruction.getPcode()), monitor)
    if decompiler_factory is None:
        raise ValueError("High extraction requires an explicit decompiler factory")
    interface = decompiler_factory()
    try:
        if not interface.setSimplificationStyle("decompile") or not interface.openProgram(program):
            doc["observability"].update(state="failed", reason="decompiler setup/openProgram failed")
            return validate(doc)
        result = interface.decompileFunction(function, timeout_seconds, monitor)
        if monitor.isCancelled() or result.isCancelled():
            state = "cancelled"
        elif result.isTimedOut():
            state = "timeout"
        elif not result.decompileCompleted():
            state = "failed"
        elif result.getHighFunction() is None:
            state = "unavailable"
        else:
            state = "complete"
        if state != "complete":
            doc["observability"].update(state=state, reason=str(result.getErrorMessage()) or state)
            return validate(doc)
        # Ghidra's sequence-ordered iterator, not a Python object identity order.
        return collect(doc, result.getHighFunction().getPcodeOps(), monitor)
    finally:
        interface.dispose()
