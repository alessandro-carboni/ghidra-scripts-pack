"""Read-only Step 9 gate: verify the pinned, human-reviewed Step 8 baseline."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys

try:
    from .dataset_manifest import require, validate
    from .dataset_review import content_hash, validate_decisions
    from .validate_dataset_portability import verify
except ImportError:
    from dataset_manifest import require, validate
    from dataset_review import content_hash, validate_decisions
    from validate_dataset_portability import verify

ROOT = Path(__file__).resolve().parents[1]
DATA = "datasets/osgf_pairs_v0_1"
FREEZE = DATA + "/freezes/freeze-001.json"
FROZEN_DIGEST = "095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2"


def exact_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def safe_path(root, relative):
    require(isinstance(relative, str) and bool(relative), "missing relative path")
    parts = relative.split("/")
    require(not PurePosixPath(relative).is_absolute() and not any(p in {"", ".", ".."} for p in parts) and "\\" not in relative and ":" not in relative, "invalid repository-relative path")
    root = Path(root).resolve()
    path = root.joinpath(*parts)
    require(path.resolve().is_relative_to(root), "path escapes repository")
    require(path.resolve() == path.absolute(), "symlink/reparse redirection is not an artifact path")
    return path


def inventory(root):
    result = {}
    for prefix in (DATA, "samples/controlled/source", "rust_engine/tests/fixtures"):
        directory = safe_path(root, prefix)
        require(directory.is_dir(), "missing scientific directory: " + prefix)
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                safe_path(root, relative)
                result[relative] = exact_hash(path)
    return result


def frozen_baseline(root=ROOT):
    root = Path(root).resolve()
    freeze_path = safe_path(root, FREEZE)
    require(freeze_path.is_file(), "frozen baseline missing")
    frozen = json.loads(freeze_path.read_bytes())
    require(content_hash(frozen) == FROZEN_DIGEST, "frozen scientific digest mismatch")
    manifest = json.loads(safe_path(root, DATA + "/manifest.json").read_bytes())
    packet = json.loads(safe_path(root, DATA + "/review/review_packet.json").read_bytes())
    decisions = json.loads(safe_path(root, DATA + "/review/review_decisions.json").read_bytes())
    require(manifest == frozen["manifest_snapshot"] and content_hash(manifest) == frozen["manifest_sha256"], "manifest differs from freeze")
    require(packet == frozen["review_packet"], "review packet differs from freeze")
    require(validate_decisions(manifest, packet, decisions) == frozen["records"], "decisions differ from freeze")
    for graph in manifest["graphs"]:
        for key in ("path", "sha256", "canonical_digest", "typed_graph_sha256", "anchor_function_id", "mapping_provenance"):
            require(bool(graph.get(key)), "missing graph provenance: " + key)
        safe_path(root, graph["path"])
    for build in manifest["builds"]:
        safe_path(root, build["source_path"])
    validate(manifest, root)
    verify(root)
    return dict(
        freeze_reference=FREEZE,
        freeze_scientific_digest=FROZEN_DIGEST,
        freeze_file_sha256=exact_hash(freeze_path),
        manifest_file_sha256=exact_hash(root / DATA / "manifest.json"),
        manifest_scientific_digest=content_hash(manifest),
        counts={key: len(manifest[key]) for key in ("samples", "builds", "routines", "graphs", "pairs")},
        scientific_files=inventory(root),
    )


def repository_state(root=ROOT):
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()

    require(git("branch", "--show-current") == "codex", "Step 9 requires branch codex")
    return dict(branch="codex", head=git("rev-parse", "HEAD"), working_tree=git("status", "--porcelain").splitlines())


def environment(ghidra_dir=None):
    try:
        from .controlled_corpus import compiler_inventory
    except ImportError:
        from controlled_corpus import compiler_inventory
    try:
        compilers, unavailable = compiler_inventory()
        compiler_info = [{k: c[k] for k in ("compiler", "version", "optimizations")} for c in compilers]
    except ValueError:
        compiler_info, unavailable = [], ["no supported compiler found"]
    versions = {}
    for name, command in (("python", [sys.executable, "--version"]), ("cargo", ["cargo", "--version"]), ("rustc", ["rustc", "--version"]), ("pytest", [sys.executable, "-m", "pytest", "--version"]), ("ruff", [sys.executable, "-m", "ruff", "--version"])):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
            versions[name] = dict(status="available" if result.returncode == 0 else "unavailable", version=result.stdout.strip() if result.returncode == 0 else None)
        except (OSError, subprocess.TimeoutExpired):
            versions[name] = dict(status="unavailable", version=None)
    ghidra = dict(status="not_configured", version=None, launcher_verified=False)
    if ghidra_dir:
        path = Path(ghidra_dir)
        properties = path / "Ghidra/application.properties"
        launcher = path / "support/pyghidraRun.bat"
        if properties.is_file() and launcher.is_file():
            values = dict(line.split("=", 1) for line in properties.read_text().splitlines() if "=" in line)
            ghidra = dict(status="installation_verified_execution_not_yet_tested", version=values.get("application.version"), launcher_verified=True)
        else:
            ghidra["status"] = "unavailable"
    return dict(tools=versions, compilers=compiler_info, unavailable_compilers=unavailable, ghidra=ghidra)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--ghidra-dir", type=Path)
    args = parser.parse_args()
    baseline = frozen_baseline(args.root)
    if args.baseline:
        require(json.loads(args.baseline.read_bytes()) == baseline, "frozen baseline inventory changed")
    print("PREFLIGHT PASS:", json.dumps(dict(repository=repository_state(args.root), frozen={k: v for k, v in baseline.items() if k != "scientific_files"}, protected_files=len(baseline["scientific_files"]), environment=environment(args.ghidra_dir)), indent=2, sort_keys=True))
