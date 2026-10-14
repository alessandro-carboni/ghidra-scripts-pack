"""Verify variant registry, source/binary integrity and independent behavior oracle."""

import json
from collections import Counter
from pathlib import Path

try:
    from .validate_controlled_corpus import expected
except ImportError:
    from validate_controlled_corpus import expected


def validate(data):
    routines = {r["routine_id"]: r for r in data["routines"]}
    families = Counter()
    checks = 0
    for transformation in data["transformations"]:
        name = transformation["transformed_routine"]
        routine = routines[name]
        assert routine["source_group_id"] == transformation["original_routine"]
        assert routine["variant"] == transformation["family"]
        assert transformation["validation"] == "passed" and transformation["rationale"]
        families[transformation["family"]] += 1
        builds = [b for b in data["builds"] if b["artifact_group"] == routine["artifact_group"]]
        assert builds, "Missing variant build"
        for build in builds:
            rows = [row.split() for row in build["behavior"] if row.startswith(name + " ")]
            assert len(rows) == 1024 and {int(row[1]) for row in rows} == set(range(1024)), "Incomplete variant cases"
            for _, case, result in rows:
                length, salt = divmod(int(case), 4)
                values = [(j * 17 + salt * 31 + length) % 127 for j in range(length)]
                assert int(result) == expected(transformation["original_routine"], values), "Variant oracle mismatch"
                checks += 1
    assert len(families) == 6 and min(families.values()) >= 2, "Missing transformation coverage"
    return dict(families=dict(families), oracle_checks=checks)


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    print("STRUCTURAL VARIANTS PASS:", validate(json.loads((root / "datasets/osgf_pairs_v0_1/variants.json").read_text())))
