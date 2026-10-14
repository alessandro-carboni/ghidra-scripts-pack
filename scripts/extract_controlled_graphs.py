"""Extract real Ghidra graphs, map exported source routines, canonicalize explicit anchors."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess

from controlled_corpus import DATA, ROOT, digest, save
from dataset_manifest import stable_id, validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--reuse-extraction", action="store_true")
    parser.add_argument("--refresh-export", action="store_true", help="Re-export already analyzed project programs without rerunning analysis")
    args = parser.parse_args()
    corpus = json.loads((DATA / "corpus.json").read_text(encoding="utf-8"))
    work = ROOT / ".build-cache/dataset-extraction"
    imports, projects, raw = (work / name for name in ("imports", "projects", "raw"))
    for directory in (imports, projects, raw):
        directory.mkdir(parents=True, exist_ok=True)
    for sample in corpus["samples"]:
        if sample["build_id"]:
            shutil.copy2(ROOT / sample["path"], imports / sample["filename"])
    if args.refresh_export:
        subprocess.run([str(args.ghidra_dir / "support/pyghidraRun.bat"), "-H", str(projects), "ControlledDataset", "-process", "*.exe", "-recursive", "-noanalysis", "-scriptPath", str(ROOT / "ghidra_scripts"), "-postScript", "export_research_graph.py", str(raw)], check=True)
    elif not args.reuse_extraction:
        command = [str(args.ghidra_dir / "support/pyghidraRun.bat"), "-H", str(projects), "ControlledDataset", "-import", str(imports), "-recursive", "-overwrite", "-scriptPath", str(ROOT / "ghidra_scripts"), "-postScript", "export_research_graph.py", str(raw)]
        subprocess.run(command, check=True)
    graphs = []
    for sample in corpus["samples"]:
        if not sample["build_id"]:
            continue
        build = next(b for b in corpus["builds"] if b["build_id"] == sample["build_id"])
        symbols = json.loads((raw / (sample["filename"] + ".symbols.json")).read_text(encoding="utf-8"))
        typed = raw / (sample["filename"] + ".graph.json")
        extracted = json.loads(typed.read_text(encoding="utf-8"))
        if extracted["metadata"].get("research_binary_sha256") != sample["sha256"]:
            raise ValueError(f"Analyzed binary hash does not match catalog: {sample['sample_id']}; refresh export")
        for routine in corpus["routines"]:
            if routine["artifact_group"] != build["artifact_group"]:
                continue
            name = routine["routine_id"]
            anchor = symbols.get(name, symbols.get("_" + name))
            if not anchor:
                raise ValueError(f"Missing exported routine {name} in {sample['sample_id']}")
            graph_id = stable_id("graph", sample["sha256"], name, "caller0-callee3-v0.1")
            output = DATA / "graphs" / (graph_id.replace(":", "_") + ".json")
            output.parent.mkdir(parents=True, exist_ok=True)
            if not output.exists():
                subprocess.run([str(args.engine.resolve()), "canonicalize-research-anchor", str(typed), anchor, str(output)], check=True)
            canonical = json.loads(output.read_text(encoding="utf-8"))
            if canonical["source_document"]["anchor_function_id"] != anchor:
                raise ValueError(f"Cached canonical anchor mismatch: {output}")
            graphs.append(
                dict(
                    graph_id=graph_id,
                    sample_id=sample["sample_id"],
                    routine_id=name,
                    source_group_id=routine["source_group_id"],
                    variant="original",
                    path=output.relative_to(ROOT).as_posix(),
                    sha256=digest(output),
                    canonical_digest=canonical["canonical_digest"],
                    anchor_function_id=anchor,
                    mapping_provenance="PE exported symbol; identity metadata only",
                    typed_graph_sha256=digest(typed),
                )
            )
    manifest = {key: corpus[key] for key in ("schema_version", "samples", "builds", "routines")}
    manifest.update(graphs=graphs, pairs=[], ground_truth_policy=corpus["ground_truth_policy"])
    print("MANIFEST:", validate(manifest, ROOT), flush=True)
    save(DATA / "manifest.json", manifest)


if __name__ == "__main__":
    main()
