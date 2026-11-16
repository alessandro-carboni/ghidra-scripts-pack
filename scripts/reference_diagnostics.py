"""Additive diagnostics of registered reference experiments; no rescoring or calibration."""

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import math

try:
    from . import graph_first as g
    from . import reference_library as lib
    from . import reference_benchmark as bench
    from . import reference_coverage as coverage
except ImportError:
    import graph_first as g
    import reference_library as lib
    import reference_benchmark as bench
    import reference_coverage as coverage


def distribution(values):
    available = [v for v in values if v is not None]
    g.require(all(type(v) in (int, float) and math.isfinite(v) and 0 <= v <= 1 for v in available), "invalid similarity value")
    counts = Counter(available)
    return dict(
        total=len(values),
        comparable=len(available),
        unavailable=len(values) - len(available),
        minimum=min(available) if available else None,
        maximum=max(available) if available else None,
        mean=sum(available) / len(available) if available else None,
        empirical_distribution=[dict(score=s, count=n) for s, n in sorted(counts.items())],
    )


def scores(rows, condition):
    pos = [r["score"] for r in rows if r["positive"] and r["score"] is not None]
    neg = [r["score"] for r in rows if not r["positive"] and r["score"] is not None]
    comparisons = len(pos) * len(neg)
    return dict(
        positive=distribution([r["score"] for r in rows if r["positive"]]),
        negative=distribution([r["score"] for r in rows if not r["positive"]]),
        hard_negative=distribution([r["score"] for r in rows if r["hard_negative"]]),
        positive_negative_ordering=dict(
            pair_comparisons=comparisons, positive_below_negative=sum(p < n for p in pos for n in neg), equal=sum(p == n for p in pos for n in neg), positive_above_negative=sum(p > n for p in pos for n in neg), inversion_rate=sum(p < n for p in pos for n in neg) / comparisons if comparisons else None
        ),
        continuous=bench.metrics.roc(rows),
        retrieval=bench.metrics.retrieval(rows, condition),
    )


def grouped(rows, condition, fields):
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(row[f] for f in fields)].append(row)
    return [dict(group=dict(zip(fields, key)), metrics=scores(values, condition)) for key, values in sorted(groups.items())]


def build(a):
    g.require(not a.output.exists(), "new diagnostics output required")
    registered = g.load(a.registration)
    g.require(bench.inventory(a.dataset, a.library, a.engine, a.operational_engine) == registered["inventory"], "registered inputs/implementation changed")
    result = g.load(a.evaluation / "results.json")
    g.require(lib.sha((a.evaluation / "results.json").read_bytes()) == a.result_sha256, "result digest mismatch")
    g.require(result["registration_sha256"] == lib.sha(a.registration.read_bytes()), "registration binding mismatch")
    cases = bench.check_dataset(g.load(a.dataset))
    references = {row["reference_id"]: lib.read_entry(a.library, row, a.engine)[1] for row in lib.manifest(a.library)["entries"]}
    rankings = {}
    evidence = defaultdict(list)
    observability = {}
    input_hashes = {str(a.evaluation / "results.json"): a.result_sha256}
    for row in result["rows"]["D"]:
        q, r = cases[row["query"]], cases[row["reference"]]
        if row["score"] is None:
            continue
        path = a.evaluation / (lib.sha(row["query"].encode()) + ".json")
        if row["query"] not in rankings:
            rankings[row["query"]] = g.load(path)
            input_hashes[str(path)] = lib.sha(path.read_bytes())
        candidate = next(c for c in rankings[row["query"]]["candidates"] if c["reference"] == r["reference_id"])
        detail = candidate["coverage"]
        g.require(detail["sources"]["query"] == g.load(lib.safe_path(a.dataset.parent, q["query_artifact"])) and detail["sources"]["reference"] == references[r["reference_id"]], "ranking source differs from registered pair")
        coverage.validate_result(detail, a.engine)
        g.require(row["score"] == detail["reference_coverage"]["set"], "reported coverage score differs")
        for family, values in detail["evidence_value_coverage"]["per_family"].items():
            evidence[(row["split"], row["group"], family)].append(dict(positive=row["positive"], set=values["set"], multiset=values["multiset"]))
        for side, ident in (("query", row["query"]), ("reference", row["reference"])):
            support = detail["evidence_support"]["legacy"][side]
            key = (side, ident)
            observation = dict(
                split=row["split"],
                local_truncated=support["local_truncation"]["truncated"],
                motif_truncated=any(v["truncated"] for v in support["motif_truncation"].values()),
                unresolved_records=support["unresolved_records"],
                warnings=sorted(w for w in detail["evidence_support"]["warnings"] if w.startswith(side + ":")),
            )
            if key in observability:
                g.require(observability[key] == observation, "inconsistent per-region observability")
            observability[key] = observation
    obs = []
    for split in bench.SPLITS:
        for side in ("query", "reference"):
            selected = [v for (s, _), v in observability.items() if s == side and v["split"] == split]
            n = len(selected)
            obs.append(
                dict(
                    split=split,
                    side=side,
                    unique_observed_regions=n,
                    local_truncation_rate=sum(v["local_truncated"] for v in selected) / n if n else None,
                    motif_truncation_rate=sum(v["motif_truncated"] for v in selected) / n if n else None,
                    observed_unresolved_record_rate=sum(v["unresolved_records"] > 0 for v in selected) / n if n else None,
                    warning_rate=sum(bool(v["warnings"]) for v in selected) / n if n else None,
                    warnings=sorted({w for v in selected for w in v["warnings"]}),
                )
            )
    output = dict(
        schema_version="osgf.reference-diagnostics/0.1.0",
        inputs=input_hashes,
        conditions={
            c: dict(pooled=scores(rows, c), per_split=grouped(rows, c, ("split",)), per_family=grouped(rows, c, ("split", "group")), compiler_transfer=grouped(rows, c, ("split", "query_compiler", "reference_compiler")), optimization_transfer=grouped(rows, c, ("split", "query_optimization", "reference_optimization")))
            for c, rows in result["rows"].items()
        },
        evidence_families=[
            dict(
                split=key[0],
                group=key[1],
                family=key[2],
                positive_set=distribution([v["set"] for v in values if v["positive"]]),
                negative_set=distribution([v["set"] for v in values if not v["positive"]]),
                positive_multiset=distribution([v["multiset"] for v in values if v["positive"]]),
                negative_multiset=distribution([v["multiset"] for v in values if not v["positive"]]),
            )
            for key, values in sorted(evidence.items())
        ],
        observability=obs,
        interpretation="Conditional diagnostics, no tuning. Observability counts unique regions in comparable coverage pairs. Zero observed unresolved records does not prove complete resolution; retain warnings. Empty strata are unavailable. Correlated rows are not independent subjects.",
    )
    g.write(a.output, output)
    print("PASS diagnostics: registered inputs and source-bound coverage verified;", len(observability), "unique side/region observations", flush=True)
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("evaluation", "dataset", "library", "registration", "engine", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--operational-engine", type=Path)
    p.add_argument("--result-sha256", required=True)
    build(p.parse_args())


if __name__ == "__main__":
    main()
