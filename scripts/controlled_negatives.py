"""Build benign counterexamples and label pairs from executed output witnesses only."""

import argparse
import hashlib
from itertools import combinations
import json
from pathlib import Path

from controlled_corpus import BUILDS, DATA, ROOT, SOURCE, compiler_inventory, digest, execute, pe_architecture, save
from dataset_artifacts import analyze, merge_records, register_graph, save_manifest
from dataset_manifest import validate
from generate_dataset_pairs import make_pair, statistics

BODIES = {
    "api_length": "(void)n; return (unsigned)lstrlenA((const char*)p);",
    "api_length_wrapped": "(void)n; return length_helper(p)+1u;",
    "api_length_plus_one": "(void)n; return (unsigned)lstrlenA((const char*)p)+1u;",
    "api_compare": '(void)n; return lstrcmpA((const char*)p,"AB")==0;',
    "api_compare_inverted": '(void)n; return lstrcmpA((const char*)p,"AB")!=0;',
}


def build_negatives():
    compilers, _ = compiler_inventory()
    compiler = next((c for c in compilers if c["compiler"] == "msvc"), compilers[0])
    lines = ["#include <windows.h>", "#include <stdio.h>", "#define API __declspec(dllexport) __declspec(noinline)", "API unsigned length_helper(const unsigned char *p) { return (unsigned)lstrlenA((const char*)p); }"]
    routines = []
    for name, body in BODIES.items():
        lines.append(f"API unsigned {name}(const unsigned char *p,unsigned n) {{ {body} }}")
        routines.append(dict(routine_id=name, source_group_id=name, artifact_group="system_api", source_path="samples/controlled/source/negative_api.c", contract="bytes_0_255_trailing_nul", body_sha256=hashlib.sha256(body.encode()).hexdigest(), provenance="controlled_negative_source"))
    lines.append("int main(void) { unsigned i,j,n; unsigned char p[256]; for(i=0;i<16;i++) { n=i*7; for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[n]=0;")
    for name in BODIES:
        lines.append(f'printf("{name} %u %u\\n",i,{name}(p,n));')
    lines.append("} return 0; }")
    source = SOURCE / "negative_api.c"
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")
    build_id = f"negative-api-{compiler['compiler']}-O0"
    directory = BUILDS / build_id
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / (build_id + ".exe")
    flags = ["/nologo", "/Od", "/Brepro", str(source), f"/Fe{output}", "/link", "/INCREMENTAL:NO", "/OPT:NOICF", "kernel32.lib"] if compiler["compiler"] == "msvc" else ["-O0", "-Wl,--no-insert-timestamp", str(source), "-o", str(output)]
    execute([compiler["path"], *flags], cwd=directory, env=compiler["env"])
    behavior = execute([str(output)]).splitlines()
    for row in behavior:
        name, case, value = row.split()
        case = int(case)
        data = bytes((j * 17 + case * 13) % 127 for j in range(case * 7)).split(b"\0")[0]
        oracle = {"api_length": len(data), "api_length_wrapped": len(data) + 1, "api_length_plus_one": len(data) + 1, "api_compare": int(data == b"AB"), "api_compare_inverted": int(data != b"AB")}[name]
        if int(value) != oracle:
            raise ValueError("API negative independent oracle mismatch: " + row)
    if len(set(behavior)) != 80:
        raise ValueError("Incomplete API behavior coverage")
    arch = pe_architecture(output)
    build = dict(build_id=build_id, compiler=compiler["compiler"], compiler_version=compiler["version"], optimization="O0", architecture=arch, source_path=source.relative_to(ROOT).as_posix(), source_hash=digest(source), build_hash=digest(output), artifact_group="system_api", flags=flags, behavior=behavior)
    sample = dict(sample_id=build_id, build_id=build_id, path=output.relative_to(ROOT).as_posix(), filename=output.name, sha256=digest(output), architecture=arch, origin="controlled_source", provenance="controlled_benign", compiler=compiler["compiler"])
    return dict(samples=[sample], builds=[build], routines=routines)


def negative_pair(manifest, left, right, category, difficulty, rationale, tags):
    left, right = sorted((left, right), key=lambda g: g["graph_id"])
    # Same executable means identical case input generation, ABI and runtime context.
    if left["sample_id"] != right["sample_id"]:
        raise ValueError("Counterexample requires the same input harness")
    sample = next(s for s in manifest["samples"] if s["sample_id"] == left["sample_id"])
    build = next(b for b in manifest["builds"] if b["build_id"] == sample["build_id"])
    outputs = {(name, int(case)): int(result) for name, case, result in (row.split() for row in build["behavior"])}
    for case in range(16):
        lv, rv = (outputs[(g["routine_id"], case)] for g in (left, right))
        if lv != rv:
            truth = dict(method="behavior_counterexample", label="non_equivalent", case=case, left_result=lv, right_result=rv, input_bytes=[(j * 17 + case * 13) % 127 for j in range(case * 7)], evidence=rationale)
            pair = make_pair(manifest, left, right, "non_equivalent", "controlled_negative", "none", truth)
            pair.update(negative_category=category, negative_tags=tags, difficulty=difficulty)
            return pair
    raise ValueError("No observed counterexample; refusing a negative label")


def generate(manifest):
    pairs = []
    for sample in manifest["samples"]:
        graphs = [g for g in manifest["graphs"] if g["sample_id"] == sample["sample_id"] and g["variant"] == "original"]
        if sample["sample_id"].startswith(("numeric-", "text-", "memory-")) and "variants" not in sample["sample_id"]:
            for left, right in combinations(graphs, 2):
                pairs.append(negative_pair(manifest, left, right, "same_binary_different_routine", "hard", "Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.", ["same_functional_category", "similar_constants", "controlled_hard_negative"]))
    names = {g["routine_id"]: g for g in manifest["graphs"] if g["routine_id"] in BODIES}
    specifications = [
        ("api_length", "api_length_wrapped", "similar_api_different_structure", "hard", "Both call lstrlenA; api_length_wrapped introduces a helper call and adds one to the result."),
        ("api_length", "api_compare", "similar_topology_different_evidence", "hard", "Single API call topology; lstrlenA length versus lstrcmpA equality with literal AB."),
        ("api_length", "api_length_plus_one", "benign_lookalike", "hard", "Identical API call and arguments; one result is incremented."),
        ("api_compare", "api_compare_inverted", "similar_constants_different_behavior", "hard", "Same AB literal and lstrcmpA call; opposite predicates."),
        ("api_length_plus_one", "api_compare", "different_behavior", "easy", "Length plus one versus string equality: different operation, API and string evidence."),
    ]
    for left, right, category, difficulty, rationale in specifications:
        pairs.append(negative_pair(manifest, names[left], names[right], category, difficulty, rationale, [category, "controlled_" + difficulty + "_negative"]))
    return pairs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--reuse-extraction", action="store_true")
    args = parser.parse_args()
    prepared = json.loads((DATA / "negatives.json").read_text()) if args.reuse_extraction else build_negatives()
    save(DATA / "negatives.json", prepared)
    raw = analyze(prepared["samples"], args.ghidra_dir, "negative-imports", args.reuse_extraction)
    manifest = json.loads((DATA / "manifest.json").read_text())
    # Replace this generated stage atomically in memory; no stale labels on rebuild.
    old_samples = {s["sample_id"] for s in manifest["samples"] if s["sample_id"].startswith("negative-api-")}
    old_graphs = {g["graph_id"] for g in manifest["graphs"] if g["sample_id"] in old_samples}
    manifest["pairs"] = [p for p in manifest["pairs"] if p["pair_category"] != "controlled_negative"]
    manifest["graphs"] = [g for g in manifest["graphs"] if g["graph_id"] not in old_graphs]
    manifest["samples"] = [s for s in manifest["samples"] if s["sample_id"] not in old_samples]
    manifest["builds"] = [b for b in manifest["builds"] if b["build_id"] not in old_samples]
    graphs = [register_graph(prepared["samples"][0], r, raw, args.engine) for r in prepared["routines"]]
    for collection, key in (("samples", "sample_id"), ("builds", "build_id"), ("routines", "routine_id")):
        merge_records(manifest, collection, prepared[collection], key)
    merge_records(manifest, "graphs", graphs, "graph_id")
    merge_records(manifest, "pairs", generate(manifest), "pair_id")
    manifest["statistics"] = statistics(manifest)
    if "split_protocol" in manifest:
        from dataset_splits import apply_splits

        apply_splits(manifest, manifest["split_protocol"]["configuration"])
    print("NEGATIVE PAIRS PASS:", validate(manifest, ROOT), flush=True)
    save_manifest(manifest)


if __name__ == "__main__":
    main()
