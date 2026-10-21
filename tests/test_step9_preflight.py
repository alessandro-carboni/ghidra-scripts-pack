import json
import shutil
import subprocess

import pytest

from scripts.step9_preflight import DATA, FREEZE, ROOT, frozen_baseline, inventory, repository_state, safe_path


def test_real_freeze_and_read_only_inventory():
    before = inventory(ROOT)
    baseline = frozen_baseline(ROOT)
    assert baseline["counts"]["pairs"] == 218
    assert inventory(ROOT) == before == baseline["scientific_files"]


@pytest.fixture
def copied(tmp_path):
    for relative in (DATA, "samples/controlled/source", "rust_engine/tests/fixtures"):
        shutil.copytree(ROOT / relative, tmp_path / relative)
    return tmp_path


@pytest.mark.parametrize("failure", ["missing", "corrupt", "manifest", "provenance"])
def test_invalid_baselines_fail_closed(copied, failure):
    if failure == "missing":
        (copied / FREEZE).unlink()
    elif failure == "corrupt":
        (copied / FREEZE).write_text("{}")
    else:
        path = copied / DATA / "manifest.json"
        manifest = json.loads(path.read_bytes())
        if failure == "manifest":
            manifest["pairs"][0]["equivalence_label"] = "non_equivalent"
            manifest["pairs"][0]["notes"] = "tampered"
        else:
            del manifest["graphs"][0]["mapping_provenance"]
        path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        frozen_baseline(copied)


@pytest.mark.parametrize("relative", ["../escape", "/absolute", "C:/absolute", "x\\y", "a/../b", "a//b", ""])
def test_invalid_path(relative):
    with pytest.raises(ValueError):
        safe_path(ROOT, relative)


def test_unrelated_worktree_changes_are_reported_without_mutation(tmp_path):
    subprocess.run(["git", "init", "-b", "codex", str(tmp_path)], check=True, capture_output=True)
    # Reuse an existing commit object, without creating a commit or branch in the real repo.
    real_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    objects = subprocess.check_output(["git", "rev-parse", "--git-path", "objects"], cwd=ROOT, text=True).strip()
    (tmp_path / ".git/objects/info/alternates").write_text(str((ROOT / objects).resolve()).replace("\\", "/") + "\n", encoding="utf-8", newline="\n")
    subprocess.run(["git", "update-ref", "refs/heads/codex", real_head], cwd=tmp_path, check=True)
    path = tmp_path / "unrelated.txt"
    path.write_bytes(b"user work")
    state = repository_state(tmp_path)
    assert any("unrelated.txt" in item for item in state["working_tree"])
    assert path.read_bytes() == b"user work"
