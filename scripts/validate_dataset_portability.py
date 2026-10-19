"""Verify exact dataset bytes, optionally in fresh checkouts of the uncommitted candidate."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

try:
    from .audit_dataset_graph_signal import audit, serialize
    from .dataset_manifest import validate
    from .generate_evaluation_strata import generate
except ImportError:
    from audit_dataset_graph_signal import audit, serialize
    from dataset_manifest import validate
    from generate_evaluation_strata import generate

ROOT = Path(__file__).resolve().parents[1]


def verify(root):
    data = root / "datasets/osgf_pairs_v0_1"
    manifest_path = data / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    sources = set()
    for name in ("manifest.json", "corpus.json", "variants.json", "negatives.json", "interactions.json"):
        for build in json.loads((data / name).read_bytes())["builds"]:
            path = root / build["source_path"]
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != build["source_hash"]:
                raise ValueError("Exact compiled source hash mismatch: " + build["build_id"])
            if b"\r\n" not in raw or b"\n" in raw.replace(b"\r\n", b"") or b"\r" in raw.replace(b"\r\n", b""):
                raise ValueError("Source must use exact CRLF bytes: " + str(path))
            raw.decode("utf-8")
            sources.add(build["source_path"])
    for path in data.rglob("*.json"):
        raw = path.read_bytes()
        if b"\r" in raw or raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("Dataset JSON must be UTF-8 LF without BOM: " + str(path))
        raw.decode("utf-8")
    counts = validate(manifest, root)
    expected_audit = (data / "graph_signal_audit.json").read_bytes()
    first = serialize(audit(manifest_path, root)[0])
    second = serialize(audit(manifest_path, root)[0])
    if first != second or first != expected_audit:
        raise ValueError("Audit bytes/hash binding stale or nondeterministic")
    expected_strata = (data / "evaluation_strata.json").read_bytes()
    if serialize(generate(manifest_bytes, first)) != expected_strata or serialize(generate(manifest_bytes, second)) != expected_strata:
        raise ValueError("Strata bytes/hash binding stale or nondeterministic")
    return dict(**counts, exact_source_files=len(sources), manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest())


def clean_checkouts(root):
    """Use a disposable index, never the real index, branch, commit or worktree registration."""

    def git(*args, env=None):
        return subprocess.check_output(["git", *args], cwd=root, env=env, text=True).strip()

    before = (git("rev-parse", "HEAD"), git("branch", "--show-current"), git("diff", "--cached", "--binary"))
    with tempfile.TemporaryDirectory(prefix="osgf-checkout-") as temporary:
        directory = Path(temporary)
        env = dict(os.environ, GIT_INDEX_FILE=str(directory / "candidate-index"))
        git("read-tree", "HEAD", env=env)
        git("add", "--", ".gitattributes", "scripts", "tests", "datasets/osgf_pairs_v0_1", "samples/controlled/source", env=env)
        tree = git("write-tree", env=env)
        for autocrlf in ("false", "true"):
            checkout = directory / autocrlf
            checkout.mkdir()
            git("-c", "core.autocrlf=" + autocrlf, "checkout-index", "--all", "--force", "--prefix=" + checkout.as_posix() + "/", env=env)
            print("CLEAN CHECKOUT PASS", "candidate_tree=" + tree, "core.autocrlf=" + autocrlf, verify(checkout), flush=True)
    after = (git("rev-parse", "HEAD"), git("branch", "--show-current"), git("diff", "--cached", "--binary"))
    if before != after:
        raise ValueError("Unexpected HEAD/branch/real-index change")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--clean-checkouts", action="store_true")
    args = parser.parse_args()
    print("EXACT HASH / DETERMINISM PASS:", verify(args.root), flush=True)
    if args.clean_checkouts:
        clean_checkouts(args.root)
