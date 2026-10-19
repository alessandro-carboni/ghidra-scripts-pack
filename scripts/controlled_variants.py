"""Source-level transformations with explicit proofs and full length-domain execution checks."""

import argparse
import hashlib
import json
from pathlib import Path

from controlled_build import BuildFailure, build_pe
from controlled_corpus import BUILDS, DATA, ROOT, ROUTINES, SOURCE, compiler_inventory, digest, save
from dataset_artifacts import analyze, merge_records, register_graph, save_manifest
from dataset_manifest import validate
from generate_dataset_pairs import make_pair, statistics
from validate_controlled_corpus import expected

FAMILIES = {
    "transparent_wrapper": "Direct delegation with identical arguments and return value; no new observable effects.",
    "thunk": "Fixed local function pointer targets the original routine; no pointer mutation or alternate target.",
    "function_splitting": "Partition bytes into two disjoint halves; combine associative sum/max/xor reductions with the original identity for empty input.",
    "dead_branch": "Branch n>255 is unreachable under the explicit 0<=n<=255 input contract; reachable execution delegates unchanged.",
    "harmless_strand": "Added pure unsigned-arithmetic helper reads no external state, writes no memory and its result is discarded.",
    "linear_chain": "Two fixed pure delegation stages preserve arguments, return value and absence of external effects.",
}
SELECTED = {"numeric": ("sum_array", "find_max"), "text": ("count_digits", "count_letters"), "memory": ("copy_buffer", "xor_buffer")}


def variant_source(name, family):
    target = name + "__" + family
    prefix = "API unsigned "
    signature = "(const unsigned char *p,unsigned n)"
    if family == "transparent_wrapper":
        body = f"return {name}(p,n);"
    elif family == "thunk":
        body = f"unsigned (*target)(const unsigned char *,unsigned)={name}; return target(p,n);"
    elif family == "function_splitting":
        combine = "a>b?a:b" if name == "find_max" else "a^b" if name == "xor_buffer" else "a+b"
        body = f"unsigned middle=n/2; unsigned a={name}(p,middle); unsigned b={name}(p+middle,n-middle); return {combine};"
    elif family == "dead_branch":
        body = f"if(n>255) return 123; return {name}(p,n);"
    elif family == "harmless_strand":
        body = f"(void)harmless_helper(n); return {name}(p,n);"
    else:
        return f"{prefix}{target}_inner{signature} {{ return {name}(p,n); }}\n{prefix}{target}{signature} {{ return {target}_inner(p,n); }}"
    return f"{prefix}{target}{signature} {{ {body} }}"


def build_variants():
    compilers, _ = compiler_inventory()
    compiler = next((c for c in compilers if c["compiler"] == "gcc"), compilers[0])
    samples, builds, routines, transformations = [], [], [], []
    for group, names in SELECTED.items():
        lines = ["#include <stdio.h>", "#include <string.h>", "#define API __declspec(dllexport) __declspec(noinline)", "API unsigned harmless_helper(unsigned n) { return (n*17u)^91u; }"]
        exported = []
        for name in names:
            lines.append(f"API unsigned {name}(const unsigned char *p,unsigned n) {{ {ROUTINES[group][name]} }}")
            for family, proof in FAMILIES.items():
                code = variant_source(name, family)
                lines.append(code)
                target = name + "__" + family
                exported.append((name, target))
                record = dict(routine_id=target, source_group_id=name, artifact_group=group, source_path=f"samples/controlled/source/{group}_variants.c", contract="bytes_0_255_trailing_nul", body_sha256=hashlib.sha256(code.encode()).hexdigest(), provenance="controlled_source_transformation", variant=family)
                routines.append(record)
                transformations.append(dict(family=family, version="0.1.0", parameters=dict(max_length=255, unsigned_width=32), original_routine=name, transformed_routine=target, rationale=proof, validation_status="automatically_grounded", validation="passed", transformation_level="source", test_cases=1024))
        lines.append("int main(void) { unsigned n,s,j; unsigned char p[256]; for(n=0;n<=255;n++) for(s=0;s<4;s++) { for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+s*31+n)%127); p[n]=0;")
        for _, target in exported:
            lines.append(f'printf("{target} %u %u\\n",n*4+s,{target}(p,n));')
        lines.append("} return 0; }")
        source = SOURCE / f"{group}_variants.c"
        source.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\r\n")
        build_id = f"{group}-variants-{compiler['compiler']}-O0"
        directory = BUILDS / build_id
        directory.mkdir(parents=True, exist_ok=True)
        output = directory / f"{build_id}.exe"

        def flags_for_output(target):
            if compiler["compiler"] == "msvc":
                return ["/nologo", "/Od", "/Brepro", str(source), f"/Fe{target}", "/link", "/INCREMENTAL:NO", "/OPT:NOICF"]
            return ["-O0", "-Wl,--no-insert-timestamp", str(source), "-o", str(target)]

        def validate_behavior(transcript):
            seen = set()
            for row in transcript:
                target, case, value = row.split()
                name = target.split("__")[0]
                case = int(case)
                if target not in {t for _, t in exported} or not 0 <= case < 1024 or (target, case) in seen:
                    raise ValueError("Unexpected/duplicate transformation case")
                n, salt = divmod(case, 4)
                data = [(j * 17 + salt * 31 + n) % 127 for j in range(n)]
                if int(value) != expected(name, data):
                    raise ValueError(f"Transformation failed independent oracle: {row}")
                seen.add((target, case))
            if len(seen) != len(exported) * 1024:
                raise ValueError("Incomplete transformation test coverage")

        try:
            result = build_pe(compiler, build_id, "O0", output, flags_for_output, validate_behavior)
        except BuildFailure as error:
            save(DATA / "variant_build_failures.json", [error.record])
            raise
        architecture = result["architecture"]
        builds.append(
            dict(
                build_id=build_id,
                compiler=compiler["compiler"],
                compiler_version=compiler["version"],
                optimization="O0",
                source_path=source.relative_to(ROOT).as_posix(),
                source_hash=digest(source),
                build_hash=digest(output),
                artifact_group=group,
                **result,
                behavior_input="case=length*4+salt; byte[j]=(j*17+salt*31+length)%127",
            )
        )
        samples.append(dict(sample_id=build_id, build_id=build_id, path=output.relative_to(ROOT).as_posix(), filename=output.name, sha256=digest(output), architecture=architecture, origin="controlled_source", provenance="controlled_benign", compiler=compiler["compiler"]))
        print(f"VARIANTS PASS {group}: {len(exported)} functions, {len(result['behavior'])} oracle checks", flush=True)
    return samples, builds, routines, transformations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--reuse-extraction", action="store_true")
    args = parser.parse_args()
    if args.reuse_extraction:
        prepared = json.loads((DATA / "variants.json").read_text(encoding="utf-8"))
        samples, builds, routines, transformations = (prepared[k] for k in ("samples", "builds", "routines", "transformations"))
    else:
        samples, builds, routines, transformations = build_variants()
        save(DATA / "variants.json", dict(samples=samples, builds=builds, routines=routines, transformations=transformations))
    raw = analyze(samples, args.ghidra_dir, "variant-imports", args.reuse_extraction)
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    graphs = [register_graph(sample, routine, raw, args.engine) for sample, build in zip(samples, builds) for routine in routines if routine["artifact_group"] == build["artifact_group"]]
    for collection, records, key in (("samples", samples, "sample_id"), ("builds", builds, "build_id"), ("routines", routines, "routine_id"), ("graphs", graphs, "graph_id")):
        merge_records(manifest, collection, records, key)
    pairs = []
    build_index = {b["build_id"]: b for b in manifest["builds"]}
    sample_index = {s["sample_id"]: s for s in manifest["samples"]}
    for graph in graphs:
        transformation = next(t for t in transformations if t["transformed_routine"] == graph["routine_id"])
        variant_build = build_index[sample_index[graph["sample_id"]]["build_id"]]
        candidates = [g for g in manifest["graphs"] if g["routine_id"] == transformation["original_routine"] and g["variant"] == "original" and sample_index[g["sample_id"]]["architecture"] == sample_index[graph["sample_id"]]["architecture"]]

        def preference(candidate):
            build = build_index[sample_index[candidate["sample_id"]]["build_id"]]
            return (build["compiler"] != variant_build["compiler"], build["optimization"] != "O0", candidate["graph_id"])

        original = min(candidates, key=preference)
        truth = dict(method="source_transformation_proof", label="equivalent", proof=transformation["rationale"], validation="passed", transformation=transformation)
        pair = make_pair(manifest, original, graph, "equivalent", "source_transformation", graph["variant"], truth)
        pair["transformation_parameters"] = transformation["parameters"]
        pairs.append(pair)
    manifest["pairs"] = [p for p in manifest["pairs"] if p["pair_category"] != "source_transformation"]
    merge_records(manifest, "pairs", pairs, "pair_id")
    manifest["transformations"] = transformations
    manifest["statistics"] = statistics(manifest)
    if "split_protocol" in manifest:
        from dataset_splits import apply_splits

        apply_splits(manifest, manifest["split_protocol"]["configuration"])
    print("VARIANT MANIFEST:", validate(manifest, ROOT), flush=True)
    save_manifest(manifest)


if __name__ == "__main__":
    main()
