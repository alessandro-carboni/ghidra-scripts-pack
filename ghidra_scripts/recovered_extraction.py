"""Capture parameter and CFG evidence while the decompiler's HighFunction is alive."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
try:
    from .pcode_extraction import extract, sequence
except ImportError:
    from pcode_extraction import extract, sequence
from recovered_evidence import envelope  # noqa: E402


def parameter_candidate(value, is_high_param):
    high = value.getHigh()
    if high is None or not is_high_param(high) or value.getDef() is not None or not value.isInput():
        return None
    slot, width = int(high.getSlot()), int(value.getSize())
    if slot < 0 or int(high.getSize()) != width or int(high.getOffset()) != -1:
        # A whole variable has offset -1; pieces must not alias the whole parameter.
        return None
    return dict(slot=slot, width=width, basis="HighParam+input+full-width+no-def")


def extract_recovered(program, function, monitor, environment, decompiler_factory, is_high_param, max_operations=10000):
    captured = dict(parameters=[], blocks=[], operation_blocks={}, cfg_status="unavailable", warnings=[])

    class Capture:
        def __init__(self):
            self.interface = decompiler_factory()

        def __getattr__(self, name):
            return getattr(self.interface, name)

        def decompileFunction(self, *args):
            result = self.interface.decompileFunction(*args)
            high = result.getHighFunction() if result.decompileCompleted() else None
            if high is None:
                return result
            operations = []
            for op in high.getPcodeOps():
                if len(operations) >= max_operations:
                    break
                operations.append(op)
            mapping = {sequence(op): "op:" + str(i) for i, op in enumerate(operations)}
            for op in operations:
                for i, value in enumerate(op.getInputs()):
                    try:
                        p = parameter_candidate(value, is_high_param)
                        if p is not None:
                            captured["parameters"].append(dict(operation=mapping[sequence(op)], input=i, **p))
                    except Exception as error:
                        captured["warnings"].append("parameter recovery unavailable: " + type(error).__name__)
            try:
                blocks = list(high.getBasicBlocks())
                if len(blocks) > 512:
                    raise ValueError("CFG block budget exceeded")
                for b in blocks:
                    ident = "b:" + str(b.getIndex())
                    captured["blocks"].append(dict(id=ident, successors=sorted({"b:" + str(b.getOut(i).getIndex()) for i in range(b.getOutSize())})))
                captured["operation_blocks"] = {mapping[sequence(op)]: "b:" + str(op.getParent().getIndex()) for op in operations}
                captured["cfg_status"] = "complete"
            except Exception as error:
                captured.update(blocks=[], operation_blocks={}, cfg_status="unavailable")
                captured["warnings"].append("CFG recovery unavailable: " + type(error).__name__)
            return result

    source = extract(program, function, monitor, environment, "high", max_operations=max_operations, decompiler_factory=Capture)
    kept = {op["id"] for op in source["operations"]}
    captured["parameters"] = [p for p in captured["parameters"] if p["operation"] in kept]
    captured["operation_blocks"] = {k: v for k, v in captured["operation_blocks"].items() if k in kept}
    # Any conflicting mapping stays unresolved rather than accepting a guessed argument identity.
    ops = {op["id"]: op for op in source["operations"]}
    by_slot, by_storage = {}, {}
    for p in captured["parameters"]:
        v = ops[p["operation"]]["inputs"][p["input"]]
        storage = v["kind"], v["space"], v["offset"], v["width"]
        by_slot.setdefault(p["slot"], set()).add(storage)
        by_storage.setdefault(storage, set()).add(p["slot"])
    bad = {slot for slot, values in by_slot.items() if len(values) != 1 or any(len(by_storage[v]) != 1 for v in values)}
    if bad:
        captured["warnings"].append("ambiguous parameter slots retained as physical storage")
        captured["parameters"] = [p for p in captured["parameters"] if p["slot"] not in bad]
    if source["observability"]["state"] != "complete":
        captured["cfg_status"] = "partial"
    return envelope(source, **captured)
