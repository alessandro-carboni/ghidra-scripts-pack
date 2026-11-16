"""Step 10.8: frozen strata, source components and descriptive robustness."""

import json
from pathlib import Path

try:
    from . import evaluation_stability as s
except ImportError:
    import evaluation_stability as s

m, g = s.m, s.g
require, serialize = g.require, g.serialize


def clusters(manifest):
    graphs = {r["graph_id"]: r for r in manifest["graphs"]}
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    samples = {r["sample_id"]: r for r in manifest["samples"]}
    builds = {r["build_id"]: r for r in manifest["builds"]}
    parents = {gid: gid for gid in graphs}

    def root(gid):
        while parents[gid] != gid:
            gid = parents[gid]
        return gid

    claims = {}
    for gid, graph in sorted(graphs.items()):
        routine = routines[graph["routine_id"]]
        build = builds[samples[graph["sample_id"]]["build_id"]]
        keys = [("source_group", graph["source_group_id"]), ("artifact", routine["artifact_group"]), ("source_hash", build["source_hash"]), ("body_hash", routine["body_sha256"]), ("source_path", routine["source_path"])]
        keys += [("near_duplicate", i) for i, group in enumerate(manifest["split_protocol"]["configuration"]["near_duplicate_groups"]) if graph["source_group_id"] in group]
        for key in keys:
            if key in claims:
                a, b = sorted((root(gid), root(claims[key])))
                parents[b] = a
            claims[key] = gid
    result = {gid: root(gid) for gid in graphs}
    for component in set(result.values()):
        require(len({graphs[gid]["split"] for gid in graphs if result[gid] == component}) == 1, "cluster crosses frozen split")
    return result


def cells(manifest, strata, holdouts):
    pairs = manifest["pairs"]
    builds = {r["build_id"]: r for r in manifest["builds"]}
    result = []
    for split in ("discovery_train", "validation", "held_out_test"):
        selected = [p for p in pairs if p["split"] == split]
        result.append(dict(dimension="all", value="all", split=split, pair_ids=sorted(p["pair_id"] for p in selected)))
        for key in ("equivalence_label", "transformation_family"):
            for value in sorted({p[key] for p in pairs}):
                result.append(dict(dimension=key, value=value, split=split, pair_ids=sorted(p["pair_id"] for p in selected if p[key] == value)))
        for key in ("compiler", "optimization"):

            def combination(pair):
                return "+".join(sorted({builds[pair[k]][key] for k in ("left_build_id", "right_build_id")}))

            for value in sorted({combination(p) for p in pairs}):
                result.append(dict(dimension=key, value=value, split=split, pair_ids=sorted(p["pair_id"] for p in selected if combination(p) == value)))
        for name, ids in sorted(strata["strata"].items()):
            require(set(ids) <= {p["pair_id"] for p in pairs}, "unknown stratum pair")
            result.append(dict(dimension="signal_observability", value=name, split=split, pair_ids=sorted(p["pair_id"] for p in selected if p["pair_id"] in ids)))
        for holdout in holdouts:
            ids = holdout["pair_ids"][split]
            require(set(ids) <= {p["pair_id"] for p in selected}, "holdout remaps frozen split")
            expected = [p["pair_id"] for p in selected if (p["transformation_family"] == holdout["family"]) == (split == "held_out_test")]
            require(sorted(ids) == sorted(expected), "holdout family policy mismatch")
            result.append(dict(dimension="family_holdout", value=holdout["family"], split=split, pair_ids=sorted(ids)))
    return result


def evaluate(manifest, strata, holdouts, matrix, galleries, thresholds, stability):
    components = clusters(manifest)
    index = {(r["condition"], r["pair"]["pair_id"]): r for r in matrix["records"]}
    churn = {(r["condition"], r["pair"]["pair_id"]): r for r in stability["churn"]}
    result = []
    for cell in cells(manifest, strata, holdouts):
        ids = cell["pair_ids"]
        condition_results = {}
        for condition in ("A", "B"):
            rows = [index[condition, pid] for pid in ids]
            # Keep each original judged gallery intact; partial cell galleries are not ranked.
            queries = [r for r in galleries["records"] if r["condition"] == condition and r["split"] == cell["split"] and r["paired_eligible"] and all(c["pair_id"] in ids for c in r["candidates"])]
            cutoff = thresholds["conditions"][condition]
            if cell["dimension"] == "family_holdout":
                cutoff = dict(status="unsupported")
            condition_results[condition] = dict(
                pairwise=m.pair_summary(rows, cutoff),
                retrieval=m.retrieval(queries),
                churn={v: {metric: m.distribution(churn[condition, pid]["views"][v][metric] for pid in ids if (condition, pid) in churn) for metric in ("presence", "multiplicity")} for v in g.pairs.VIEWS},
                threshold_limitation="family-specific threshold not preregistered; global calibration includes this family" if cell["dimension"] == "family_holdout" else None,
            )
        deltas = []
        for pid in ids:
            a, b = index["A", pid], index["B", pid]
            if not matrix["paired_comparable_components"][pid] or a["primary_score"] is None or b["primary_score"] is None:
                continue
            pair = a["pair"]
            left, right = (components[pair[key]] for key in ("left_graph_id", "right_graph_id"))
            require(left == right, "pair spans independent source components; clustering requires revision")
            deltas.append(dict(pair_id=pid, cluster_id=left, B_minus_A=b["primary_score"] - a["primary_score"]))
        groups = sorted({r["cluster_id"] for r in deltas})
        cluster_means = [dict(cluster_id=key, mean=sum(r["B_minus_A"] for r in deltas if r["cluster_id"] == key) / sum(r["cluster_id"] == key for r in deltas)) for key in groups]
        require(len(groups) < 10, "inference threshold reached: implement preregistered cluster bootstrap before reporting")
        result.append(
            dict(
                **cell,
                status="descriptive" if ids else "unsupported_empty",
                pair_n=len(ids),
                conditions=condition_results,
                paired_deltas=deltas,
                paired_delta_distribution=m.distribution(r["B_minus_A"] for r in deltas),
                uncertainty=dict(independent_cluster_n=len(groups), cluster_means=cluster_means, cluster_macro=m.distribution(r["mean"] for r in cluster_means), interval=None, reason="fewer_than_10_independent_components; descriptive observed range only"),
            )
        )
    failures = []
    for row in matrix["records"]:
        cutoff = thresholds["conditions"][row["condition"]]
        if cutoff["status"] != "supported" or row["primary_score"] is None:
            continue
        predicted = not cutoff["reject_all"] and row["primary_score"] >= cutoff["value"]
        if predicted != (row["pair"]["equivalence_label"] == "equivalent"):
            failures.append(
                dict(
                    condition=row["condition"],
                    pair_id=row["pair"]["pair_id"],
                    split=row["pair"]["split"],
                    label=row["pair"]["equivalence_label"],
                    primary_score=row["primary_score"],
                    query_graph_id=row["query_graph_id"],
                    reference_graph_id=row["reference_graph_id"],
                    score_record_id=row["record_id"],
                    artifact=row["artifact"],
                )
            )
    return dict(
        schema_version="0.1.0",
        generator_utf8_lf_sha256=g.pairs.sha(Path(__file__).read_text(encoding="utf-8").encode()),
        input_sha256={name: g.pairs.sha(serialize(value)) for name, value in dict(matrix=matrix, galleries=galleries, thresholds=thresholds, stability=stability, strata=strata, holdouts=holdouts).items()},
        clusters=components,
        tables=result,
        failure_examples=failures,
        limitations=[
            "Overlapping strata are not independent and must not be summed.",
            "Controlled benign equivalence, not malware detection.",
            "No inferential claim with fewer than ten source components.",
            "Retrieval cells retain only whole original galleries; sparse cells can be unsupported.",
            "Holdout FPR unsupported without a preregistered family-excluded calibration; no held-out tuning.",
        ],
    )


def main():
    protocol, matrix, catalog = g.admitted_scores()
    galleries = g.galleries(protocol, matrix)
    thresholds = m.calibrate(matrix)
    stability = s.evaluate(matrix, galleries, catalog)
    for name, value in (("judged_galleries.json", galleries), ("discovery_thresholds.json", thresholds), ("feature_rank_stability.json", stability)):
        g.publish(name, value)
    folder = g.ROOT / "datasets/osgf_pairs_v0_1"
    manifest, strata, holdouts = (json.loads((folder / name).read_bytes()) for name in ("manifest.json", "evaluation_strata.json", "family_holdouts.json"))
    result = evaluate(manifest, strata, holdouts, matrix, galleries, thresholds, stability)
    result["frozen_file_sha256"] = {name: g.pairs.catalog.exact_hash(folder / name) for name in ("manifest.json", "evaluation_strata.json", "family_holdouts.json")}
    g.publish("stratified_results.json", result)
    print("Tables", len(result["tables"]), "source components", len(set(result["clusters"].values())), "failure examples", len(result["failure_examples"]), "inferential intervals: unsupported", flush=True)


if __name__ == "__main__":
    main()
