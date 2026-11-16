"""Preregistered, opt-in cross-version evaluation; labels never enter extraction."""

import argparse
from collections import defaultdict
from pathlib import Path
import tempfile

try:
    from . import reference_library as lib
    from . import graph_first as graph
    from . import graph_first_evaluation as metrics
except ImportError:
    import reference_library as lib
    import graph_first as graph
    import graph_first_evaluation as metrics

SCHEMA = "osgf.reference-benchmark/0.1.0"
CONDITIONS = dict(A="frozen baseline aggregate set Jaccard", B="existing graph-first set Jaccard", C="original operational-only set Jaccard", D="directional base-evidence reference set coverage", E="existing graph-first top-5 operational slot refinement; graph score unchanged")
SPLITS = ("discovery", "validation", "heldout")


def check_dataset(data):
    lib.keys(data, "schema_version description cases pairs")
    graph.require(data["schema_version"] == SCHEMA, "unsupported benchmark schema")
    lib.text(data["description"])
    graph.require(isinstance(data["cases"], list) and data["cases"] and isinstance(data["pairs"], list) and data["pairs"], "nonempty cases and pairs required")
    cases = {}
    ownership = {}
    artifacts = set()
    for case in data["cases"]:
        lib.keys(case, "id split source_family near_duplicate_group binary_sha256 query_artifact reference_id operational_artifact group compiler optimization annotation_source")
        for name in ("id", "source_family", "near_duplicate_group", "group", "compiler", "optimization", "annotation_source"):
            lib.text(case[name])
        lib.hash_value(case["binary_sha256"])
        graph.require(case["id"] not in cases and case["split"] in SPLITS, "duplicate case or invalid split")
        graph.require((case["query_artifact"] is None) != (case["reference_id"] is None), "case must be query or reference")
        identity = ("query", case["query_artifact"]) if case["query_artifact"] is not None else ("reference", case["reference_id"])
        graph.require(identity not in artifacts, "duplicate benchmark artifact or reference")
        artifacts.add(identity)
        for kind in ("source_family", "near_duplicate_group", "binary_sha256"):
            key = (kind, case[kind])
            graph.require(key not in ownership or ownership[key] == case["split"], "cross-split leakage: " + kind)
            ownership[key] = case["split"]
        cases[case["id"]] = case
    pairs = set()
    query_roles, reference_roles = set(), set()
    for pair in data["pairs"]:
        lib.keys(pair, "query reference positive hard_negative annotation_source")
        graph.require(type(pair["positive"]) is bool and type(pair["hard_negative"]) is bool, "labels must be boolean")
        graph.require(not (pair["positive"] and pair["hard_negative"]), "positive cannot be hard negative")
        lib.text(pair["annotation_source"])
        q, r = cases[pair["query"]], cases[pair["reference"]]
        graph.require(q["query_artifact"] is not None and r["reference_id"] is not None, "incorrect pair roles")
        graph.require(q["split"] == r["split"], "cross-split gallery leakage")
        graph.require(q["binary_sha256"] != r["binary_sha256"], "identical binary query/reference leakage")
        key = (q["id"], r["id"])
        graph.require(key not in pairs, "duplicate pair")
        pairs.add(key)
        query_roles.add(q["binary_sha256"])
        reference_roles.add(r["binary_sha256"])
    graph.require(not query_roles.intersection(reference_roles), "binary reused across query/reference roles")
    # A complete explicit gallery prevents per-method or per-query label cherry-picking.
    for q in cases.values():
        if q["query_artifact"] is not None:
            expected = {r["id"] for r in cases.values() if r["reference_id"] is not None and r["split"] == q["split"]}
            graph.require(expected and {r for query, r in pairs if query == q["id"]} == expected, "incomplete registered gallery")
    return cases


def inventory(dataset, library, engine, operational_engine=None):
    data = graph.load(dataset)
    cases = check_dataset(data)
    paths = {Path(dataset).resolve(), Path(engine).resolve()}
    paths.update(Path(__file__).parent / n for n in ("reference_benchmark.py", "reference_library.py", "reference_coverage.py", "graph_first.py", "graph_first_evaluation.py", "evaluate_operational_baseline.py", "recovered_evidence.py"))
    if operational_engine:
        paths.add(Path(operational_engine).resolve())
    paths.add(lib.safe_path(library, "manifest.json"))
    entries = {e["reference_id"]: e for e in lib.validate(library, engine, operational_engine)}
    for row in lib.manifest(library)["entries"]:
        paths.add(lib.safe_path(library, row["path"]))
    for entry in entries.values():
        for artifact in (entry["fingerprint"]["artifact"], entry["fingerprint"]["optional_operational_artifact"]):
            if artifact:
                paths.add(lib.safe_path(library, artifact["path"]))
    for case in cases.values():
        if case["reference_id"]:
            graph.require(case["reference_id"] in entries, "unknown registered reference")
            graph.require(case["binary_sha256"] == entries[case["reference_id"]]["sample"]["sha256"], "reference binary binding mismatch")
        for key in ("query_artifact", "operational_artifact"):
            if case[key]:
                paths.add(lib.safe_path(Path(dataset).parent, case[key]))
    return {str(p.resolve()): lib.sha(p.read_bytes()) for p in sorted(paths, key=str)}


def preregister(dataset, library, engine, output, operational_engine=None):
    graph.write(output, dict(schema_version=SCHEMA, conditions=CONDITIONS, policy="balanced accuracy discovery-only threshold; largest threshold on ties; unavailable remains null; no tuning on validation/heldout", inventory=inventory(dataset, library, engine, operational_engine)))


def summarize(rows, condition):
    discovery = [r for r in rows if r["split"] == "discovery"]
    usable_labels = {r["positive"] for r in discovery if r["score"] is not None}
    threshold = metrics.calibrate(discovery) if usable_labels == {True, False} else None
    result = dict(discovery_threshold=threshold, threshold_status="calibrated" if threshold is not None else "unavailable: both comparable discovery labels required", splits={})
    for split in SPLITS:
        selected = [r for r in rows if r["split"] == split]
        groups = defaultdict(list)
        for row in selected:
            groups[row["group"]].append(row)
        group_metrics = {g: dict(continuous=metrics.roc(v), retrieval=metrics.retrieval(v, condition), classification=metrics.metrics(v, threshold) if threshold is not None else None) for g, v in sorted(groups.items())}
        aucs = [v["continuous"]["auc"] for v in group_metrics.values() if v["continuous"]["auc"] is not None]
        result["splits"][split] = dict(
            pair_count=len(selected),
            comparable_pairs=sum(r["score"] is not None for r in selected),
            continuous=metrics.roc(selected),
            retrieval=metrics.retrieval(selected, condition),
            classification=metrics.metrics(selected, threshold) if threshold is not None else None,
            per_group=group_metrics,
            group_macro_auc=sum(aucs) / len(aucs) if aucs else None,
            hard_negatives=[dict(query=r["query"], reference=r["reference"], score=r["score"]) for r in selected if r["hard_negative"]],
            structural_collision_count=sum(not r["positive"] and r["score"] == 1 for r in selected),
        )
    return result


def run(dataset, library, engine, registration, output, operational_engine=None):
    registered = graph.load(registration)
    graph.require(registered["schema_version"] == SCHEMA and registered["conditions"] == CONDITIONS, "incorrect registration")
    graph.require(inventory(dataset, library, engine, operational_engine) == registered["inventory"], "preregistered inputs or implementation changed")
    output = Path(output)
    graph.require(not output.exists(), "new benchmark output required")
    output.mkdir(parents=True)
    data = graph.load(dataset)
    cases = check_dataset(data)
    queries = {}
    eligibility = []
    for ident, case in cases.items():
        if case["query_artifact"] is None:
            continue
        fp = graph.load(lib.safe_path(Path(dataset).parent, case["query_artifact"]))
        if fp.get("schema_version") == "osgf.seed-search-index/0.1.0":
            # An absent seed is measured, not silently removed from the denominator.
            with tempfile.TemporaryDirectory(prefix="osgf-seed-audit-") as temporary:
                rebuilt = graph.extract(fp["source_graph"], engine, Path(temporary) / "extract")
            graph.require(graph.encoded(rebuilt) == graph.encoded(fp), "invalid seed index")
            graph.require(not rebuilt["eligible"], "eligible indexes must supply individual seed fingerprints")
            graph.require(fp["source_graph"].get("metadata", {}).get("research_binary_sha256") == case["binary_sha256"], "no-seed binary binding mismatch")
            queries[ident] = {}
            eligibility.append(dict(query=ident, split=case["split"], eligible=False, reason=rebuilt["missing_seed_reason"]))
            continue
        graph.validate(fp, engine)
        lib.bind_sample(fp, dict(sha256=case["binary_sha256"]))
        eligibility.append(dict(query=ident, split=case["split"], eligible=True, reason=None))
        op = lib.safe_path(Path(dataset).parent, case["operational_artifact"]) if case["operational_artifact"] else None
        ranking = lib.search(fp, library, engine, query_operational=op, operational_engine=operational_engine)
        graph.write(output / (lib.sha(ident.encode()) + ".json"), ranking)
        queries[ident] = {r["reference"]: r for r in ranking["candidates"]}
    rows = {condition: [] for condition in CONDITIONS}
    for pair in data["pairs"]:
        q, r = cases[pair["query"]], cases[pair["reference"]]
        match = queries[q["id"]].get(r["reference_id"])
        scores = dict.fromkeys(CONDITIONS)
        if match:
            scores.update(A=lib.score(match["coverage"], "baseline_set"), B=lib.score(match["coverage"], "graph_first_set"), C=match["operational_evidence"]["score"], D=match["score"])
            scores["E"] = scores["B"]
        for condition in CONDITIONS:
            rows[condition].append(dict(**pair, score=scores[condition], operational=scores["C"], split=q["split"], group=q["group"], query_compiler=q["compiler"], reference_compiler=r["compiler"], query_optimization=q["optimization"], reference_optimization=r["optimization"]))
    result = dict(
        schema_version=SCHEMA,
        registration_sha256=lib.sha(Path(registration).read_bytes()),
        conditions=CONDITIONS,
        seed_coverage=dict(query_regions=len(eligibility), eligible_regions=sum(r["eligible"] for r in eligibility), records=eligibility),
        rows=rows,
        summary={c: summarize(v, c) for c, v in rows.items()},
        interpretation="Explicit independent labels; no malware probability. Null results are unavailable, not negatives. E continuous metrics use unchanged B score; E retrieval uses refinement.",
    )
    graph.write(output / "results.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("preregister", "run"))
    for name in ("dataset", "library", "engine", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--registration", type=Path)
    p.add_argument("--operational-engine", type=Path)
    a = p.parse_args()
    if a.action == "preregister":
        preregister(a.dataset, a.library, a.engine, a.output, a.operational_engine)
    else:
        graph.require(a.registration is not None, "registration required")
        result = run(a.dataset, a.library, a.engine, a.registration, a.output, a.operational_engine)
        print({c: {s: v["retrieval"]["mrr"] for s, v in summary["splits"].items()} for c, summary in result["summary"].items()})


if __name__ == "__main__":
    main()
