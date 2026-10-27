"""Real tracked bytes must reproduce frozen inventories with Linux-style Git defaults."""

import json
import subprocess
import sys

from scripts.step9_preflight import ROOT


def test_clean_checkout_preserves_frozen_inventory(tmp_path):
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--no-checkout", str(ROOT), str(checkout)], check=True, capture_output=True)
    subprocess.run(["git", "-c", "core.autocrlf=false", "read-tree", "HEAD"], cwd=checkout, check=True, capture_output=True)
    # Apply the candidate attributes before checkout (also tests uncommitted fixes).
    (checkout / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=checkout).split(b"\0")
    names = [name for name in names if name and name != b".gitattributes"]
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "checkout-index", "--force", "-z", "--stdin"], input=b"\0".join(names) + b"\0", cwd=checkout, check=True, capture_output=True)
    # Run the production validators in the new checkout, not imported local modules.
    command = "from scripts.evaluation_protocol import load_protocol; p = load_protocol(); print(len(p['inputs']['scientific_files']))"
    result = subprocess.run([sys.executable, "-c", command], cwd=checkout, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "161"
    assert not (checkout / "datasets/osgf_baseline_evaluation_v0_1/runtime").exists()
    # Keep exact hash validation strict: even a line-ending-only mutation must fail.
    baseline = json.loads((checkout / "datasets/osgf_transformations_v0_1/baseline.json").read_bytes())
    target = checkout / "rust_engine/tests/fixtures/canonical_local_v0_1.json"
    assert target.relative_to(checkout).as_posix() in baseline["scientific_files"]
    raw = target.read_bytes()
    assert b"\r\n" in raw
    target.write_bytes(raw.replace(b"\r\n", b"\n"))
    rejected = subprocess.run([sys.executable, "-c", command], cwd=checkout, capture_output=True, text=True, timeout=120)
    assert rejected.returncode != 0 and "protected inventory changed" in rejected.stderr
