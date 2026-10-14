"""Validate corpus provenance and independently check controlled behavior vectors."""

import json

try:
    from .controlled_corpus import DATA, ROOT, digest, pe_architecture
except ImportError:
    from controlled_corpus import DATA, ROOT, digest, pe_architecture


def expected(name, data):
    functions = {
        "sum_array": lambda p: sum(p),
        "find_max": lambda p: max(p, default=0),
        "count_matches": lambda p: p.count(32),
        "count_digits": lambda p: sum(48 <= b <= 57 for b in p),
        "count_letters": lambda p: sum(65 <= b <= 90 for b in p),
        "search_string": lambda p: next((i + 1 for i in range(len(p) - 1) if p[i : i + 2] == [65, 66]), 0),
        "copy_buffer": lambda p: sum(p),
        "weighted_buffer": lambda p: sum((i + 1) * b for i, b in enumerate(p)),
    }
    if name == "xor_buffer":
        result = 0
        for byte in data:
            result ^= byte
        return result
    return functions[name](data) if name in functions else None


def validate(catalog):
    if catalog["schema_version"] != "0.1.0":
        raise ValueError("Unsupported corpus schema")
    for sample in catalog["samples"]:
        path = ROOT / sample["path"]
        if digest(path) != sample["sha256"] or pe_architecture(path) != sample["architecture"]:
            raise ValueError(f"Sample integrity mismatch: {sample['sample_id']}")
    observed = {}
    for build in catalog["builds"]:
        if digest(ROOT / build["source_path"]) != build["source_hash"]:
            raise ValueError(f"Source integrity mismatch: {build['build_id']}")
        values = {}
        for row in build["behavior"]:
            name, case, result = row.split()
            case, result = int(case), int(result)
            data = [(j * 17 + case * 13) % 127 for j in range(case * 7)]
            reference = expected(name, data)
            if reference is not None and result != reference:
                raise ValueError(f"Behavior mismatch: {build['build_id']} {row}")
            if reference is None and result not in (0, 1):
                raise ValueError("System API probe must return boolean status")
            values[(name, case)] = result
        if len(values) != 48:
            raise ValueError("Expected 16 behavior cases for each of three routines")
        previous = observed.setdefault(build["artifact_group"], values)
        if previous != values:
            raise ValueError(f"Cross-build behavior mismatch: {build['build_id']}")
    for artifact in {routine["artifact_group"] for routine in catalog["routines"]}:
        levels = {b["optimization"] for b in catalog["builds"] if b["artifact_group"] == artifact}
        if not {"O0", "O2"}.issubset(levels):
            raise ValueError(f"Missing O0/O2 coverage: {artifact}")
    print(f"CORPUS VERIFIED: {len(catalog['samples'])} executable hashes/architectures; {len(catalog['builds'])} source/build mappings and behavior transcripts; compiler-independent oracle passed", flush=True)


if __name__ == "__main__":
    validate(json.loads((DATA / "corpus.json").read_text(encoding="utf-8")))
