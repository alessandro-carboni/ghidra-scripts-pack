import subprocess

from scripts.validate_dataset_portability import ROOT, verify


def test_actual_versioned_dataset_bytes_and_bindings():
    subprocess.run(["git", "ls-files", "--error-unmatch", "datasets/osgf_pairs_v0_1/manifest.json", "samples/controlled/source/interaction_registry_summary.c"], cwd=ROOT, check=True, capture_output=True)
    result = verify(ROOT)
    assert result["builds"] == 27
    assert result["exact_source_files"] == 11
