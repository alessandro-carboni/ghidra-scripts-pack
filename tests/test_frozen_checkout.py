"""Real tracked bytes must reproduce frozen inventories with Linux-style Git defaults."""

import json
import subprocess
import sys

import pytest

from scripts.step9_preflight import ROOT


@pytest.mark.parametrize("autocrlf", ["false", "true"])
def test_clean_checkout_preserves_frozen_inventory(tmp_path, autocrlf):
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--no-checkout", str(ROOT), str(checkout)], check=True, capture_output=True)
    subprocess.run(["git", "-c", "core.autocrlf=false", "read-tree", "HEAD"], cwd=checkout, check=True, capture_output=True)
    # Apply the candidate attributes before checkout (also tests uncommitted fixes).
    (checkout / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
    # Stage only the candidate checkpoint in the disposable clone, never the real index.
    checkpoint = "datasets/osgf_baseline_diagnostics_v0_1/CHECKPOINT.json"
    (checkout / checkpoint).parent.mkdir(parents=True, exist_ok=True)
    (checkout / checkpoint).write_bytes((ROOT / checkpoint).read_bytes())
    subprocess.run(["git", "add", "--", checkpoint], cwd=checkout, check=True, capture_output=True)
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=checkout).split(b"\0")
    names = [name for name in names if name and name != b".gitattributes"]
    subprocess.run(["git", "-c", "core.autocrlf=" + autocrlf, "-c", "core.eol=lf", "checkout-index", "--force", "-z", "--stdin"], input=b"\0".join(names) + b"\0", cwd=checkout, check=True, capture_output=True)
    # Check actual Git-materialized bytes for the complete Step 10A inventory.
    audit_command = f"import hashlib,json,pathlib; inventory=json.loads(pathlib.Path({checkpoint!r}).read_bytes())['preserved_inventory']; mismatches=[p for p,h in inventory.items() if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()!=h]; assert not mismatches,mismatches; print(len(inventory))"
    audit = subprocess.run([sys.executable, "-c", audit_command], cwd=checkout, capture_output=True, text=True, timeout=120)
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert audit.stdout.strip() == "291"
    # CRLF must now be rejected too: the correction is not hash normalization at validation time.
    attributes = checkout / "datasets/osgf_baseline_evaluation_v0_1/.gitattributes"
    original = attributes.read_bytes()
    assert original == b"* text eol=lf\n"
    attributes.write_bytes(original.replace(b"\n", b"\r\n"))
    rejected_audit = subprocess.run([sys.executable, "-c", audit_command], cwd=checkout, capture_output=True, text=True, timeout=120)
    assert rejected_audit.returncode != 0 and ".gitattributes" in rejected_audit.stderr
    attributes.write_bytes(original)
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
