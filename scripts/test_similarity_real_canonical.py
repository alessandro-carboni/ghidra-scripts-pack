"""Local smoke validation of real canonical graphs; intentionally not a CI dataset."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

VIEWS = ("rooted_topology", "typed_evidence", "interaction_motif")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_result(result):
    comparable = []
    for name in VIEWS:
        view = result[name]
        require(isinstance(view["comparable"], bool), f"{name}: invalid comparable flag")
        require(not view["missing_from_query"] and not view["missing_from_reference"], f"{name}: self-comparison contains missing features")
        if view["comparable"]:
            comparable.append(name)
            require(view["set_similarity"] == 1.0, f"{name}: set similarity is not 1")
            require(view["multiset_similarity"] == 1.0, f"{name}: multiset similarity is not 1")
        else:
            require(view["set_similarity"] is None and view["multiset_similarity"] is None, f"{name}: unavailable view must have null similarities")
    require(result["aggregate_requested"] is True, "aggregate was not requested")
    require(result["aggregate_components"] == comparable, "aggregate components differ from comparable semantic views")
    expected = 1.0 if comparable else None
    require(result["aggregate_set_similarity"] == expected, "incorrect aggregate set similarity")
    require(result["aggregate_multiset_similarity"] == expected, "incorrect aggregate multiset similarity")
    # Scores above are checked unconditionally, including when observability warns.
    return comparable, bool(result["observability_warnings"])


def run_engine(engine, *arguments):
    result = subprocess.run([str(engine), *map(str, arguments)], capture_output=True, text=True, timeout=120, check=False)
    require(result.returncode == 0, f"engine failed ({arguments[0]}):\n{result.stdout}\n{result.stderr}")


def validate_directory(engine, directory):
    require(directory.is_dir(), f"canonical directory does not exist or is not a directory: {directory}")
    sources = sorted(path for path in directory.glob("seed_fn_*.json") if path.is_file())
    require(bool(sources), f"no seed_fn_*.json files in canonical directory: {directory}")
    require(engine.is_file(), f"engine executable not found: {engine}")
    view_counts = dict.fromkeys(VIEWS, 0)
    passed = warnings = 0
    with tempfile.TemporaryDirectory(prefix="osgf-real-similarity-") as folder:
        work = Path(folder)
        for index, source in enumerate(sources):
            try:
                fingerprint = work / f"fingerprint-{index}.json"
                run_engine(engine, "fingerprint-canonical", source, fingerprint)
                payloads = []
                for repeat in range(2):
                    output = work / f"similarity-{index}-{repeat}.json"
                    run_engine(engine, "compare-fingerprints", source.stem, source, fingerprint, source.stem, source, fingerprint, output, "--aggregate")
                    payload = output.read_bytes()
                    comparable, has_warnings = validate_result(json.loads(payload))
                    payloads.append(payload)
                require(payloads[0] == payloads[1], "SimilarityResult bytes differ across identical reruns")
                for name in comparable:
                    view_counts[name] += 1
                warnings += has_warnings
                passed += 1
                print(f"PASS {source.name}: comparable={len(comparable)} observability_warnings={has_warnings} deterministic=yes", flush=True)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                raise ValueError(f"{source.name}: {error}; passed {passed}/{len(sources)} graphs before failure") from error
    print(f"SUMMARY graphs tested={len(sources)}; graphs passed={passed}; comparable view counts={view_counts}; graphs with observability warnings={warnings}; deterministic reruns=PASS ({passed}/{len(sources)})", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--canonical-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate_directory(args.engine.resolve(), args.canonical_dir.resolve())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"FAIL: {error}\n")


if __name__ == "__main__":
    main()
