"""Independent Step 10A descriptive diagnostics. Never changes the frozen baseline."""

from collections import Counter, defaultdict
from fractions import Fraction
import json
import random

try:
    from . import evaluation_galleries as admitted
except ImportError:
    import evaluation_galleries as admitted

ROOT = admitted.ROOT
OUT = ROOT / "datasets/osgf_baseline_diagnostics_v0_1"
VIEWS = ("rooted_topology", "typed_evidence", "interaction_motif")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def counts(features):
    result = {}
    for feature in features:
        key = encoded(feature["descriptor"])
        if key in result or type(feature["count"]) is not int or not 0 < feature["count"] <= 2**64 - 1:
            raise ValueError("duplicate descriptor or invalid multiplicity")
        result[key] = feature["count"]
    return result


def jaccard(left, right):
    a, b = counts(left), counts(right)
    keys = a.keys() | b.keys()
    intersection = sum(min(a.get(k, 0), b.get(k, 0)) for k in keys)
    union = sum(max(a.get(k, 0), b.get(k, 0)) for k in keys)
    return dict(
        set_similarity=float(Fraction(len(a.keys() & b.keys()), len(keys))) if keys else None,
        multiset_similarity=float(intersection) / float(union) if union else None,
        set_intersection=len(a.keys() & b.keys()),
        set_union=len(keys),
        multiset_intersection=intersection,
        multiset_union=union,
        equal_sets=a.keys() == b.keys(),
        equal_multisets=a == b,
        matched=[json.loads(k) for k in sorted(a.keys() & b.keys())],
        left_only=[json.loads(k) for k in sorted(a.keys() - b.keys())],
        right_only=[json.loads(k) for k in sorted(b.keys() - a.keys())],
        count_differences=[dict(descriptor=json.loads(k), left=a.get(k, 0), right=b.get(k, 0)) for k in sorted(keys) if a.get(k, 0) != b.get(k, 0)],
    )


def distribution(values):
    v = sorted(x for x in values if x is not None)
    return dict(n=len(v), minimum=v[0] if v else None, maximum=v[-1] if v else None, mean=sum(v) / len(v) if v else None, median=(v[(len(v) - 1) // 2] + v[len(v) // 2]) / 2 if v else None)


def confusion(rows, threshold):
    c = Counter()
    for label, score in rows:
        if label not in ("equivalent", "non_equivalent"):
            raise ValueError("unknown judgment")
        if score is None:
            c["null"] += 1
            continue
        predicted = threshold is not None and score >= threshold
        c[("T" if predicted == (label == "equivalent") else "F") + ("P" if predicted else "N")] += 1
    tp, fp, tn, fn = (c[k] for k in ("TP", "FP", "TN", "FN"))
    tpr = tp / (tp + fn) if tp + fn else None
    tnr = tn / (tn + fp) if tn + fp else None
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, null=c["null"], positive_n=tp + fn, negative_n=tn + fp, TPR=tpr, TNR=tnr, FPR=1 - tnr if tnr is not None else None, precision=tp / (tp + fp) if tp + fp else None, balanced_accuracy=(tpr + tnr) / 2 if tpr is not None and tnr is not None else None)


def auc(rows):
    p = [v for label, v in rows if label == "equivalent" and v is not None]
    n = [v for label, v in rows if label == "non_equivalent" and v is not None]
    roc = sum((x > y) + 0.5 * (x == y) for x in p for y in n) / (len(p) * len(n)) if p and n else None
    previous, ap = 0, 0.0
    for cutoff in sorted(set(p + n), reverse=True):
        tp, fp = sum(v >= cutoff for v in p), sum(v >= cutoff for v in n)
        if p:
            ap += (tp - previous) / len(p) * tp / (tp + fp)
        previous = tp
    return dict(roc_auc=roc, pr_average_precision=ap if p and n else None, positive=distribution(p), negative=distribution(n), cross_label_equal_score_count=sum(x == y for x in p for y in n), scope="Exploratory descriptive; grouped-threshold average precision, not trapezoidal PR area or independent-sample inference")


def rank_metrics(candidates):
    positive = [i for i, c in enumerate(candidates, 1) if c["label"] == "equivalent"]
    if not positive:
        return dict(mrr=None, recall={str(k): None for k in (1, 3, 5)}, hit={str(k): None for k in (1, 3, 5)})
    return dict(mrr=1 / positive[0], recall={str(k): sum(i <= k for i in positive) / len(positive) if len(candidates) >= k else None for k in (1, 3, 5)}, hit={str(k): int(positive[0] <= k) if len(candidates) >= k else None for k in (1, 3, 5)})


def dump(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    path = OUT / name
    if path.exists() and path.read_bytes() != raw:
        raise ValueError("diagnostic replay differs: " + name)
    if not path.exists():
        path.write_bytes(raw)
    print(name, "sha256", admitted.pairs.sha(raw), flush=True)


def load():
    protocol, matrix, catalog = admitted.admitted_scores()
    manifest = json.loads((ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    fps, graphs, origins = {}, {}, {}
    for row in catalog["records"]:
        key = row["condition"], row["graph_id"]
        paths, fp, provenance = admitted.pairs.load_input(row, admitted.pairs.CATALOG)
        fps[key] = fp
        graphs[key] = json.loads(paths["bundle.json"].read_bytes())["graph"] if row["condition"] == "A" else json.loads((ROOT / row["canonical_path"]).read_bytes())
        origins[key] = dict(canonical_path=row["canonical_path"], canonical_sha256=row["canonical_sha256"], fingerprint_digest=fp["fingerprint_digest"], artifacts=row["artifacts"], catalog_record_id=row["record_id"], source_sha256=admitted.pairs.sha(admitted.serialize(provenance["source_document"])))
    return protocol, matrix, catalog, manifest, fps, graphs, origins


def analyze(data):
    protocol, matrix, catalog, manifest, fps, graphs, origins = data
    gm = {r["graph_id"]: r for r in manifest["graphs"]}
    routines = {r["routine_id"]: r for r in manifest["routines"]}
    builds = {r["build_id"]: r for r in manifest["builds"]}
    records, graph_rows, normalization = [], [], []
    freq = defaultdict(lambda: defaultdict(list))
    for (condition, gid), fp in sorted(fps.items()):
        graph = graphs[condition, gid]
        views = {}
        for view in VIEWS:
            c = counts(fp[view + "_view"])
            views[view] = dict(distinct=len(c), multiplicity=sum(c.values()), empty=not c, descriptors=[dict(descriptor=json.loads(k), count=v) for k, v in sorted(c.items())])
            for key in c:
                freq[condition, view][key].append(gid)
        graph_rows.append(
            dict(
                condition=condition,
                graph_id=gid,
                routine_id=gm[gid]["routine_id"],
                split=gm[gid]["split"],
                source_group=gm[gid]["source_group_id"],
                views=views,
                canonical_node_kinds=dict(Counter(n["kind"] for n in graph["nodes"])),
                source_node_kinds=dict(Counter(n["type"] for n in graph["source_document"]["nodes"])),
                raw_function_metadata=[n for n in graph["source_document"]["nodes"] if n["type"] == "FUNCTION"],
                local_truncation=graph["local_graph_truncation"],
                motif_truncation=fp["motif_truncation"],
                coverage=graph["coverage_ledger"],
                provenance=origins[condition, gid],
            )
        )
    for row in matrix["records"]:
        condition, pair = row["condition"], row["pair"]
        qid, rid = pair["left_graph_id"], pair["right_graph_id"]
        views = {view: jaccard(fps[condition, qid][view + "_view"], fps[condition, rid][view + "_view"]) for view in VIEWS}
        comparable = [v for v in VIEWS if views[v]["multiset_similarity"] is not None]
        for v in VIEWS:
            for metric in ("set_similarity", "multiset_similarity"):
                if views[v][metric] != row["views"][v][metric]:
                    raise ValueError("independent view oracle mismatch")
        primary = sum(views[v]["multiset_similarity"] for v in comparable) / len(comparable) if comparable else None
        secondary = sum(views[v]["set_similarity"] for v in comparable) / len(comparable) if comparable else None
        if secondary != row["aggregate_set_similarity"]:
            raise ValueError("independent set aggregate mismatch")
        if primary != row["primary_score"] or comparable != row["aggregate_components"]:
            raise ValueError("independent aggregate mismatch")
        negative = pair["equivalence_label"] == "non_equivalent"
        classes = []
        for flag, yes in (
            ("negative_exact_one", negative and primary == 1.0),
            ("false_match_at_frozen_threshold", negative and primary is not None and primary >= 0.3),
            ("negative_high_ge_0.9", negative and primary is not None and primary >= 0.9),
            ("positive_low_lt_0.5", not negative and primary is not None and primary < 0.5),
            ("false_negative_at_frozen_threshold", not negative and (primary is None or primary < 0.3)),
        ):
            if yes:
                classes.append(flag)
        if negative and all(views[v]["equal_multisets"] for v in VIEWS):
            classes.append("REPRESENTATION_INDISTINGUISHABLE")
        witness = pair["ground_truth"]
        if witness["label"] != pair["equivalence_label"]:
            raise ValueError("contradictory ground truth")
        if negative and "left_result" in witness and witness["left_result"] == witness["right_result"]:
            raise ValueError("contradictory negative witness")
        records.append(
            dict(
                record_id=row["record_id"],
                condition=condition,
                pair=pair,
                primary=primary,
                secondary=row["aggregate_set_similarity"],
                views=views,
                comparable_views=comparable,
                classes=classes,
                endpoint_routines=[gm[qid]["routine_id"], gm[rid]["routine_id"]],
                source_records=[routines[gm[gid]["routine_id"]] for gid in (qid, rid)],
                build_metadata=[{k: builds[pair[b]].get(k) for k in ("build_id", "compiler", "compiler_version", "optimization", "source_path", "source_hash")} for b in ("left_build_id", "right_build_id")],
                source_bearing_artifact=row["artifact"],
                endpoint_provenance=[origins[condition, gid] for gid in (qid, rid)],
                observability_warnings=row["observability_warnings"],
                motif_truncation=row["input_motif_truncation"],
                comparison_complete={v: row["views"][v]["comparison_complete"] for v in VIEWS},
            )
        )
    for gid in sorted(gm):
        ga, gb = graphs["A", gid], graphs["B", gid]

        def source_facts(graph, collection):
            return {source["id"]: (node["kind"], node["facts"]) for node in graph[collection] for source in graph["node_sources" if collection == "nodes" else "edge_sources"].get(node["id"], [])}

        a, b = source_facts(ga, "nodes"), source_facts(gb, "nodes")
        operations = {}
        for operation, kind in (("api_spelling_module_import", "API"), ("constant_supported_semantics", "CONSTANT"), ("section_role", "SECTION")):
            ids = [key for key in a if a[key][0] == kind]
            operations[operation] = dict(applicable_source_ids=ids, changed_source_ids=[key for key in ids if a[key] != b.get(key)], absence="no_applicable_evidence" if not ids else None)
        operations["value_merging"] = dict(merged_source_groups=[sources for nid, sources in gb["node_sources"].items() if len(sources) > 1])
        operations["edge_context_api"] = dict(source_edges=[e for e in gb["source_document"]["edges"] if e.get("context_apis")], changed_canonical_edge_facts=ga["edges"] != gb["edges"])
        normalization.append(dict(graph_id=gid, operations=operations, descriptor_changes={v: jaccard(fps["A", gid][v + "_view"], fps["B", gid][v + "_view"]) for v in VIEWS}, mapping="Source ID within the same embedded local document; no version-dependent feature-ID alignment", provenance=origins["B", gid]))
    features = dict(
        graphs=graph_rows,
        frequencies=[dict(condition=c, view=v, descriptors=[dict(descriptor=json.loads(key), graph_ids=ids, graph_frequency=len(ids), routine_ids=sorted({gm[i]["routine_id"] for i in ids})) for key, ids in sorted(values.items(), key=lambda item: (-len(item[1]), item[0]))]) for (c, v), values in sorted(freq.items())],
        per_view=[],
    )
    for condition in ("A", "B"):
        for split in protocol["design"]["cohort"]["splits"]:
            rows = [r for r in records if r["condition"] == condition and r["pair"]["split"] == split]
            for view in (*VIEWS, "aggregate", "EXPLORATORY_min_comparable_view"):
                scores = [
                    (r["pair"]["equivalence_label"], r["primary"] if view == "aggregate" else min(r["views"][v]["multiset_similarity"] for v in r["comparable_views"]) if view.startswith("EXPLORATORY") and r["comparable_views"] else r["views"][view]["multiset_similarity"] if view in VIEWS else None) for r in rows
                ]
                features["per_view"].append(dict(condition=condition, split=split, view=view, **auc(scores), frozen_threshold_diagnostic=confusion(scores, 0.3), exact_one_negatives=sum(label == "non_equivalent" and score == 1.0 for label, score in scores), null_n=sum(score is None for _, score in scores)))
    classification = []
    for condition in ("A", "B"):
        discovery = [r for r in records if r["condition"] == condition and r["pair"]["split"] == "discovery_train"]
        candidates = sorted({r["primary"] for r in discovery if r["primary"] is not None}) + [None]
        curve = []
        for cutoff in candidates:
            result = confusion([(r["pair"]["equivalence_label"], r["primary"]) for r in discovery], cutoff)
            score = (Fraction(result["TP"], result["positive_n"]) + Fraction(result["TN"], result["negative_n"])) / 2
            curve.append((score, cutoff is None, cutoff, result))
        chosen = max(curve, key=lambda r: r[:3])
        if chosen[2] != 0.3:
            raise ValueError("frozen threshold not independently reproduced")
        classification.append(
            dict(
                condition=condition,
                independent_selected_threshold=chosen[2],
                discovery_candidates=[dict(threshold=r[2], reject_all=r[1], **r[3]) for r in curve],
                splits=[
                    dict(split=split, pair_ids=[r["pair"]["pair_id"] for r in records if r["condition"] == condition and r["pair"]["split"] == split], **confusion([(r["pair"]["equivalence_label"], r["primary"]) for r in records if r["condition"] == condition and r["pair"]["split"] == split], 0.3))
                    for split in protocol["design"]["cohort"]["splits"]
                ],
            )
        )
    pair_index = {(r["condition"], r["pair"]["pair_id"]): r for r in records}
    normalization_pairs = []
    for p in manifest["pairs"]:
        a, b = pair_index["A", p["pair_id"]], pair_index["B", p["pair_id"]]
        normalization_pairs.append(dict(pair_id=p["pair_id"], score_delta=b["primary"] - a["primary"], views={v: dict(intersection_delta=b["views"][v]["multiset_intersection"] - a["views"][v]["multiset_intersection"], union_delta=b["views"][v]["multiset_union"] - a["views"][v]["multiset_union"]) for v in VIEWS}))
    dump("FAILURE_CATALOG.json", dict(equality="Exact parsed numeric == 1.0, no rounding; high>=0.9 and low<0.5 are descriptive tags only", records=sorted(records, key=lambda r: (not bool(r["classes"]), -r["primary"] if r["primary"] is not None else 1, r["pair"]["pair_id"], r["condition"]))))
    dump("FEATURE_DIAGNOSTICS.json", features)
    dump("NORMALIZATION_OPPORTUNITIES.json", dict(graphs=normalization, pairs=normalization_pairs, limitation="Node operations traced by source identity; bundled intervention is not per-operation causal isolation."))
    dump("CLASSIFICATION_FAILURES.json", classification)
    return records


def retrieval(data, records):
    protocol, matrix, _, manifest, *_ = data
    index = {(r["condition"], r["pair"]["pair_id"]): r for r in records}
    pairs = {r["pair_id"]: r for r in manifest["pairs"]}
    queries = []
    for q in protocol["eligibility"]["queries"]:
        ids = [c["reference_graph_id"] for c in q["candidates"]]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate candidate")
        for c in q["candidates"]:
            p = pairs[c["pair_id"]]
            if {q["query_graph_id"], c["reference_graph_id"]} != {p["left_graph_id"], p["right_graph_id"]} or c["label"] != p["equivalence_label"] or q["split"] != p["split"]:
                raise ValueError("invalid relevance/provenance")
        for condition in ("A", "B"):
            candidates = [dict(c, score=index[condition, c["pair_id"]]["primary"]) for c in q["candidates"]]
            mixed = 0 < q["positive_count"] < len(candidates)
            rankings = {}
            methods = ["OSGF", "constant", "perfect_upper_bound", *VIEWS] + [f"random_seed_{seed}" for seed in range(101, 121)]
            for method in methods:
                work = sorted(candidates, key=lambda c: c["reference_graph_id"])
                if method in VIEWS:
                    work = [dict(c, score=index[condition, c["pair_id"]]["views"][method]["multiset_similarity"]) for c in work]
                if method in VIEWS or method == "OSGF":
                    if any(c["score"] is None for c in work):
                        rankings[method] = dict(status="unsupported_null_candidate", metrics=None)
                        continue
                    work.sort(key=lambda c: (-c["score"], c["reference_graph_id"]))
                elif method == "perfect_upper_bound":
                    work.sort(key=lambda c: (c["label"] != "equivalent", c["reference_graph_id"]))
                elif method.startswith("random"):
                    random.Random(method + ":" + q["query_graph_id"]).shuffle(work)
                rankings[method] = dict(status="eligible" if q["eligible"] else "no_positive", order=[c["reference_graph_id"] for c in work], metrics=rank_metrics(work))
            score_counts = Counter(c["score"] for c in candidates)
            queries.append(
                dict(
                    condition=condition,
                    query_graph_id=q["query_graph_id"],
                    split=q["split"],
                    candidates=candidates,
                    positive_n=q["positive_count"],
                    negative_n=len(candidates) - q["positive_count"],
                    eligible=q["eligible"],
                    mixed=mixed,
                    mixed_with_hard_negative=mixed and any(pairs[c["pair_id"]].get("difficulty") == "hard" for c in candidates if c["label"] == "non_equivalent"),
                    single=len(candidates) == 1,
                    tied_candidates=sum(n for n in score_counts.values() if n > 1),
                    rankings=rankings,
                )
            )
    summaries = []
    for condition in ("A", "B"):
        for split in protocol["design"]["cohort"]["splits"]:
            for cohort in ("all_eligible", "mixed", "mixed_with_hard_negative", "positive_only"):
                selected = [
                    q for q in queries if q["condition"] == condition and q["split"] == split and q["eligible"] and (cohort == "all_eligible" or q["mixed"] if cohort == "mixed" else q["mixed_with_hard_negative"] if cohort == "mixed_with_hard_negative" else q["negative_n"] == 0 if cohort == "positive_only" else True)
                ]
                for method in methods:
                    supported = [q for q in selected if q["rankings"][method]["status"] == "eligible"]
                    summaries.append(
                        dict(
                            condition=condition,
                            split=split,
                            cohort=cohort,
                            method=method,
                            query_ids=[q["query_graph_id"] for q in supported],
                            n=len(supported),
                            mrr=distribution(q["rankings"][method]["metrics"]["mrr"] for q in supported),
                            recall={str(k): distribution(q["rankings"][method]["metrics"]["recall"][str(k)] for q in supported) for k in (1, 3, 5)},
                            hit={str(k): distribution(q["rankings"][method]["metrics"]["hit"][str(k)] for q in supported) for k in (1, 3, 5)},
                        )
                    )
    dump(
        "RETRIEVAL_BIAS.json",
        dict(queries=queries, summaries=summaries, random_policy="20 reproducible permutations, seeds 101..120 salted by query ID; whole-cohort ranges describe sampling variability, not query-independent confidence intervals", labels="Only frozen judged relations; all galleries unchanged; subsets diagnostic only"),
    )


if __name__ == "__main__":
    data = load()
    records = analyze(data)
    retrieval(data, records)
    print("436 pair-condition records validated independently; diagnostics written outside frozen baseline", flush=True)
