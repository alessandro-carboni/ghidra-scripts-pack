"""Shared helpers for additional controlled builds and real canonical graph registration."""

import json
from pathlib import Path
import shutil
import subprocess

from controlled_corpus import DATA, ROOT, digest, save
from dataset_manifest import stable_id


def analyze(samples, ghidra_dir, batch, reuse=False):
    work = ROOT / ".build-cache/dataset-extraction"
    imports = work / batch
    raw = work / "raw"
    imports.mkdir(parents=True, exist_ok=True)
    for sample in samples:
        shutil.copy2(ROOT / sample["path"], imports / sample["filename"])
    if not reuse:
        subprocess.run([str(Path(ghidra_dir) / "support/pyghidraRun.bat"), "-H", str(work / "projects"), "ControlledDataset", "-import", str(imports), "-recursive", "-overwrite", "-scriptPath", str(ROOT / "ghidra_scripts"), "-postScript", "export_research_graph.py", str(raw)], check=True)
    return raw


def register_graph(sample, routine, raw, engine):
    typed = raw / (sample["filename"] + ".graph.json")
    document = json.loads(typed.read_text(encoding="utf-8"))
    if document["metadata"].get("research_binary_sha256") != sample["sha256"]:
        raise ValueError("Ghidra input hash mismatch")
    symbols = json.loads((raw / (sample["filename"] + ".symbols.json")).read_text(encoding="utf-8"))
    name = routine["routine_id"]
    anchor = symbols.get(name, symbols.get("_" + name))
    if not anchor:
        raise ValueError(f"Missing controlled export: {name}")
    graph_id = stable_id("graph", sample["sha256"], name, "caller0-callee3-v0.1")
    path = DATA / "graphs" / (graph_id.replace(":", "_") + ".json")
    if not path.exists():
        subprocess.run([str(Path(engine).resolve()), "canonicalize-research-anchor", str(typed), anchor, str(path)], check=True)
    canonical = json.loads(path.read_text(encoding="utf-8"))
    if canonical["source_document"]["anchor_function_id"] != anchor:
        raise ValueError("Canonical anchor mismatch")
    return dict(
        graph_id=graph_id,
        sample_id=sample["sample_id"],
        routine_id=name,
        source_group_id=routine["source_group_id"],
        variant=routine.get("variant", "original"),
        path=path.relative_to(ROOT).as_posix(),
        sha256=digest(path),
        canonical_digest=canonical["canonical_digest"],
        anchor_function_id=anchor,
        mapping_provenance="PE export; identity metadata only",
        typed_graph_sha256=digest(typed),
    )


def merge_records(manifest, collection, records, key):
    current = {record[key]: record for record in manifest[collection]}
    for record in records:
        current[record[key]] = record
    manifest[collection] = sorted(current.values(), key=lambda record: record[key])


def save_manifest(manifest):
    save(DATA / "manifest.json", manifest)
