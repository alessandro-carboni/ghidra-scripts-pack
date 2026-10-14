"""Rebuild Step 8 from controlled sources and installed tools; never infer human review."""

import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-dir", type=Path, required=True)
    parser.add_argument("--engine", type=Path, default=Path("rust_engine/target/debug/rust_engine.exe"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if list((root / "datasets/osgf_pairs_v0_1/freezes").glob("freeze-*.json")):
        raise SystemExit("Frozen dataset exists. Rebuild in a separate checkout; preserve this version and record an explicit review revision.")
    shared = ["--ghidra-dir", str(args.ghidra_dir.resolve()), "--engine", str(args.engine.resolve())]
    commands = [
        ["controlled_corpus.py"],
        ["validate_controlled_corpus.py"],
        ["extract_controlled_graphs.py", *shared],
        ["generate_dataset_pairs.py", "datasets/osgf_pairs_v0_1/manifest.json"],
        ["controlled_variants.py", *shared],
        ["validate_structural_variants.py"],
        ["controlled_negatives.py", *shared],
        ["dataset_splits.py", "datasets/osgf_pairs_v0_1/manifest.json", "--config", "datasets/osgf_pairs_v0_1/split_config.json"],
        ["validate_dataset_acceptance.py", "--technical-only", "--replay"],
    ]
    for script, *arguments in commands:
        print("RUN:", script, *arguments, flush=True)
        subprocess.run([sys.executable, str(root / "scripts" / script), *arguments], cwd=root, check=True)
    print("Technical rebuild complete. Human review is never regenerated automatically; compare the new manifest to the review packet before freezing.")


if __name__ == "__main__":
    main()
