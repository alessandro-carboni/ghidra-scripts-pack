import copy
import json
import os
import shutil
import subprocess

import pytest

from scripts.step9_preflight import DATA, ROOT, frozen_baseline, inventory
from scripts.transformation_harness import default_config, generate_run, load_run, plan
from scripts.transformation_schema import serialize


@pytest.fixture
def isolated(tmp_path):
    for relative in (DATA, "samples/controlled/source", "rust_engine/tests/fixtures"):
        shutil.copytree(ROOT / relative, tmp_path / relative)
    config = default_config(frozen_baseline(tmp_path))
    return tmp_path, config


def test_plan_order_determinism_and_seed_variation(isolated):
    root, config = isolated
    before = inventory(root)
    first, sources = plan(config, root)
    reordered = copy.deepcopy(config)
    reordered["transformations"].reverse()
    assert (first, sources) == plan(reordered, root)
    assert len(sources) == 6
    assert all(raw.count(b"\n") == raw.count(b"\r\n") for raw in sources.values())
    reordered["transformations"][0]["deterministic_seed"] += 1
    other, changed = plan(reordered, root)
    assert other["run_id"] != first["run_id"] and changed != sources
    assert before == inventory(root)


def test_atomic_publication_existing_run_and_corruption(isolated):
    root, config = isolated
    before = inventory(root)
    destination, first = generate_run(config, root)
    assert (destination, first) == generate_run(config, root)
    assert load_run(destination, root) == first
    assert before == inventory(root)
    source = root / first["executions"][0]["generated_source_path"]
    source.write_bytes(source.read_bytes() + b"/*tamper*/")
    with pytest.raises(ValueError):
        generate_run(config, root)


def test_interrupted_publication_never_admits_partial_run(isolated):
    root, config = isolated
    expected, _ = plan(config, root)

    def fail(stage, destination):
        assert (stage / "manifest.json").is_file()
        assert not destination.exists()
        raise OSError("simulated publication failure")

    with pytest.raises(OSError):
        generate_run(config, root, publish=fail)
    assert not (root / expected["run_path"]).exists()
    destination, _ = generate_run(config, root)
    assert destination.is_dir()


@pytest.mark.parametrize("failure", ["duplicate", "missing", "limit", "path", "freeze", "unsafe"])
def test_bad_configuration(isolated, failure):
    root, config = isolated
    if failure == "duplicate":
        config["transformations"].append(config["transformations"][0])
    elif failure == "missing":
        config["selected_source_routines"] = ["nonexistent"]
    elif failure == "limit":
        config["execution_limits"]["max_variants"] = 1
    elif failure == "path":
        config["output_policy"]["root"] = DATA
    elif failure == "freeze":
        config["frozen_dataset_reference"]["manifest_file_sha256"] = "0" * 64
    else:
        config["transformations"][0]["parameters"]["wrapper_depth"] = 999
    with pytest.raises(ValueError):
        generate_run(config, root)


def test_reject_existing_and_generation_metadata_tamper(isolated):
    root, config = isolated
    config["output_policy"]["existing"] = "reject"
    path, _ = generate_run(config, root)
    with pytest.raises(ValueError, match="already exists"):
        generate_run(config, root)
    document = json.loads((path / "manifest.json").read_bytes())
    document["executions"][0]["applied_parameters"] = {}
    (path / "manifest.json").write_text(json.dumps(document))
    with pytest.raises(ValueError, match="generation contract"):
        load_run(path, root)


def test_run_path_outside_isolation_rejected():
    with pytest.raises(ValueError):
        load_run(ROOT / DATA, ROOT)


@pytest.mark.parametrize("attack", ["frozen_digest", "references", "empty_build_pass"])
def test_run_scientific_state_cannot_be_forged(isolated, attack):
    root, config = isolated
    path, bundle = generate_run(config, root)
    run = bundle["runs"][0]
    if attack == "frozen_digest":
        run["frozen_manifest_digest"] = "0" * 64
    elif attack == "references":
        run["transformation_ids"] = []
    else:
        run["statuses"]["build"] = "passed"
    (path / "manifest.json").write_bytes(serialize(bundle))
    with pytest.raises(ValueError):
        load_run(path, root)


def test_symlink_destination_rejected(isolated):
    root, config = isolated
    parent = root / "datasets/osgf_transformations_v0_1"
    parent.mkdir()
    try:
        (parent / "runs").symlink_to(root / DATA, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("symlink creation unavailable")
        result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(parent / "runs"), str(root / DATA)], capture_output=True, check=False)
        if result.returncode:
            pytest.skip("neither symlink nor junction creation available")
    try:
        with pytest.raises(ValueError, match="redirection"):
            generate_run(config, root)
    finally:
        os.rmdir(parent / "runs")
