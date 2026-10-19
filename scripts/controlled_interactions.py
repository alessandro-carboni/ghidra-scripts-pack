"""Build three predeclared benign interaction artifacts and independent-ground-truth pairs."""

import argparse
import ctypes
import json
from pathlib import Path
import socket

from controlled_build import BuildFailure, build_pe
from controlled_corpus import BUILDS, DATA, ROOT, SOURCE, compiler_inventory, digest, save
from controlled_negatives import negative_pair
from dataset_artifacts import analyze, merge_records, register_graph, save_manifest
from dataset_manifest import validate
from dataset_splits import apply_splits
from generate_dataset_pairs import make_pair, same_source_pairs, statistics
from interaction_sources import DESIGNS, source, validate_behavior


def observe_environment(group):
    if group == "file_metadata":
        call = ctypes.windll.kernel32.GetFileAttributesA
        call.restype = ctypes.c_uint32
        call.argtypes = [ctypes.c_char_p]
        value = call(b"C:\\Windows\\System32\\kernel32.dll")
        return 0 if value == 0xFFFFFFFF else value & 65535
    if group == "registry_summary":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft", 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                return winreg.QueryInfoKey(key)[0]
        except OSError:
            return 0
    if group == "socket_kind":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as connection:
                return connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        except OSError:
            return 0
    raise ValueError("unknown environment probe")


def build_interactions():
    compilers, _ = compiler_inventory()
    if not compilers:
        raise ValueError("No supported compiler is available for the interaction corpus")
    compiler = next((c for c in compilers if c["compiler"] == "msvc"), compilers[0])
    samples, builds, routines, transformations, failures = [], [], [], [], []
    for group in DESIGNS:
        artifact = "interaction_" + group
        text, records, registry = source(group)
        path = SOURCE / (artifact + ".c")
        path.write_text(text, encoding="utf-8")
        routines.extend(records)
        transformations.extend(registry)
        for optimization in ("O0", "O2"):
            build_id = f"{artifact}-{compiler['compiler']}-{optimization}"
            output = BUILDS / build_id / (build_id + ".exe")

            def flags(target):
                if compiler["compiler"] == "msvc":
                    return ["/nologo", "/Od" if optimization == "O0" else "/O2", "/Brepro", str(path), f"/Fe{target}", "/link", "/INCREMENTAL:NO", "/OPT:NOICF", "ws2_32.lib", "advapi32.lib"]
                return ["-" + optimization, "-Wl,--no-insert-timestamp", str(path), "-o", str(target), "-lws2_32", "-ladvapi32"]

            observation = observe_environment(group)
            try:
                result = build_pe(compiler, build_id, optimization, output, flags, lambda rows: validate_behavior(group, rows, observation))
            except BuildFailure as error:
                failures.append(error.record)
                continue
            build = dict(
                build_id=build_id,
                compiler=compiler["compiler"],
                compiler_version=compiler["version"],
                optimization=optimization,
                source_path=path.relative_to(ROOT).as_posix(),
                source_hash=digest(path),
                build_hash=digest(output),
                artifact_group=artifact,
                independent_environment_observation=observation,
                behavior_input="case=0..15; length=case*7; byte[j]=(j*17+case*13)%127; trailing NUL",
                **result,
            )
            builds.append(build)
            samples.append(dict(sample_id=build_id, build_id=build_id, path=output.relative_to(ROOT).as_posix(), filename=output.name, sha256=digest(output), architecture=result["architecture"], origin="controlled_source", provenance="controlled_benign", compiler=compiler["compiler"]))
            print(f"INTERACTION BUILD PASS {build_id}: 80 independent oracle outputs", flush=True)
    prepared = dict(samples=samples, builds=builds, routines=routines, transformations=transformations, build_failures=failures)
    save(DATA / "interactions.json", prepared)
    return prepared


def integrate(manifest, prepared, graphs):
    for group in DESIGNS:
        observations = {b["independent_environment_observation"] for b in prepared["builds"] if b["artifact_group"] == "interaction_" + group}
        if len(observations) > 1:
            raise ValueError("Read-only environment changed across builds; refusing cross-build labels: " + group)
    old_samples = {s["sample_id"] for s in manifest["samples"] if s["sample_id"].startswith("interaction_")}
    old_graphs = {g["graph_id"] for g in manifest["graphs"] if g["sample_id"] in old_samples}
    manifest["pairs"] = [p for p in manifest["pairs"] if not {p["left_graph_id"], p["right_graph_id"]} & old_graphs]
    manifest["graphs"] = [g for g in manifest["graphs"] if g["graph_id"] not in old_graphs]
    manifest["samples"] = [s for s in manifest["samples"] if s["sample_id"] not in old_samples]
    manifest["builds"] = [b for b in manifest["builds"] if b["build_id"] not in old_samples]
    for collection, key in (("samples", "sample_id"), ("builds", "build_id"), ("routines", "routine_id")):
        merge_records(manifest, collection, prepared[collection], key)
    merge_records(manifest, "graphs", graphs, "graph_id")
    registry = {t["transformed_routine"]: t for t in manifest.get("transformations", [])}
    registry.update({t["transformed_routine"]: t for t in prepared["transformations"]})
    manifest["transformations"] = sorted(registry.values(), key=lambda t: t["transformed_routine"])
    new_pairs = []
    for sample in prepared["samples"]:
        selected = {g["routine_id"]: g for g in graphs if g["sample_id"] == sample["sample_id"]}
        base_name = next(r["source_group_id"] for r in prepared["routines"] if r["routine_id"] in selected and r["variant"] == "transparent_wrapper")
        base, opposite = selected[base_name], selected[base_name + "_flipped"]
        for name, graph in sorted(selected.items()):
            if "__" in name:
                transformation = registry[name]
                truth = dict(method="source_transformation_proof", label="equivalent", proof=transformation["rationale"], validation="passed", transformation=transformation)
                pair = make_pair(manifest, base, graph, "equivalent", "interaction_transformation", graph["variant"], truth)
                pair["transformation_parameters"] = transformation["parameters"]
                new_pairs.append(pair)
            if name != base_name + "_flipped":
                new_pairs.append(
                    negative_pair(
                        manifest,
                        graph,
                        opposite,
                        "same_evidence_different_behavior",
                        "hard",
                        "Same read-only helper/API observation and input; the controlled negative toggles result bit zero. Executed outputs witness the difference independently of graph similarity.",
                        ["controlled_hard_negative", "interaction_corpus"],
                    )
                )
    # Recompute same-source combinations so new original routines get build pairs.
    manifest["pairs"] = [p for p in manifest["pairs"] if p["pair_category"] != "same_source"]
    merge_records(manifest, "pairs", same_source_pairs(manifest) + new_pairs, "pair_id")
    manifest["statistics"] = statistics(manifest)
    if "split_protocol" in manifest:
        apply_splits(manifest, json.loads((DATA / "split_config.json").read_text()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    prepared = build_interactions()
    raw = analyze(prepared["samples"], args.ghidra_dir, "interaction-imports")
    graphs = [register_graph(s, r, raw, args.engine) for s, b in zip(prepared["samples"], prepared["builds"]) for r in prepared["routines"] if r["artifact_group"] == b["artifact_group"]]
    manifest = json.loads((DATA / "manifest.json").read_text())
    integrate(manifest, prepared, graphs)
    print("INTERACTION MANIFEST:", validate(manifest, ROOT), flush=True)
    save_manifest(manifest)


if __name__ == "__main__":
    main()
