"""Step 10.9: fresh-directory end-to-end replay with byte comparisons."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

try:
    from . import evaluation_galleries as g
except ImportError:
    import evaluation_galleries as g

SCIENTIFIC = ("graph_catalog.json", "pair_matrix.json", "judged_galleries.json", "discovery_thresholds.json", "primary_metrics.json", "feature_rank_stability.json", "stratified_results.json")


def compare_trees(left, right):
    def paths(base):
        return {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}

    names = paths(left)
    g.require(names == paths(right), "replay inventory mismatch")
    for name in sorted(names):
        g.require((left / name).read_bytes() == (right / name).read_bytes(), "replay bytes differ: " + name)
    return {name: g.pairs.catalog.exact_hash(left / name) for name in sorted(names)}


def replay():
    original = g.ROOT
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=original).decode().split("\0")
    paths = sorted({p for p in paths if p and (original / p).is_file()})
    binaries = [g.pairs.catalog.ENGINE, g.pairs.catalog.executable()]
    scientific_hashes = {name: g.pairs.catalog.exact_hash(original / g.AUDIT_DIR / name) for name in SCIENTIFIC}
    with tempfile.TemporaryDirectory(prefix="osgf-fresh-replay-") as temp:
        fresh = Path(temp)
        for name in paths + [p.relative_to(original).as_posix() for p in binaries]:
            source = g.pairs.safe_path(original, name)
            target = g.pairs.safe_path(fresh, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        # Generated runtime artifacts were ignored and are deliberately absent.
        for runtime in (g.pairs.catalog.DEFAULT_OUTPUT, g.pairs.OUTPUT):
            g.require(not (fresh / runtime).exists(), "fresh replay contains cached scientific runtime")
        commands = [
            ["scripts/evaluation_catalog.py", "--materialize"],
            ["scripts/evaluation_pairs.py", "--score"],
            ["scripts/evaluation_galleries.py"],
            ["scripts/evaluation_metrics.py"],
            ["scripts/evaluation_stability.py"],
            ["scripts/evaluation_stratification.py"],
        ]
        for command in commands:
            print("FRESH WORKSPACE:", " ".join(command), flush=True)
            subprocess.run([sys.executable, *command], cwd=fresh, check=True, timeout=1200)
        inventories = {}
        for runtime in (g.pairs.catalog.DEFAULT_OUTPUT, g.pairs.OUTPUT):
            inventories[runtime] = compare_trees(original / runtime, fresh / runtime)
        for name in SCIENTIFIC:
            g.require((original / g.AUDIT_DIR / name).read_bytes() == (fresh / g.AUDIT_DIR / name).read_bytes(), "derived scientific artifact changed: " + name)
    return dict(
        schema_version="0.1.0",
        status="PASS",
        generator_utf8_lf_sha256=g.pairs.sha(Path(__file__).read_text(encoding="utf-8").encode()),
        commands=commands,
        scientific_sha256=scientific_hashes,
        runtime_inventories=inventories,
        binary_sha256={p.relative_to(original).as_posix(): g.pairs.catalog.exact_hash(p) for p in binaries},
        scope="Fresh local directory, exact source files and pinned executable bytes; catalog and comparisons regenerated from canonical inputs. Not a fresh compiler build, git clone, hosted CI or new Ghidra extraction.",
    )


if __name__ == "__main__":
    result = replay()
    g.publish("fresh_workspace_replay.json", result)
    print("FRESH REPLAY PASS", sum(len(v) for v in result["runtime_inventories"].values()), "runtime files and", len(SCIENTIFIC), "scientific artifacts byte-identical", flush=True)
