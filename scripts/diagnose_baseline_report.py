"""Deterministic descriptive tables and source-linked cases for the Step 10A audit."""

from collections import Counter, defaultdict
import json

try:
    from . import diagnose_baseline_core as d
except ImportError:
    import diagnose_baseline_core as d


def read(name):
    return json.loads((d.OUT / name).read_bytes())


def summarize():
    data = d.load()  # Strict source/provenance admission, not trust in saved reports.
    protocol, matrix, catalog, manifest, fps, graphs, origins = data
    records = d.analyze(data)
    d.retrieval(data, records)
    rows = [r for r in records if r["condition"] == "B"]
    oracles = {
        "sum_array": sum,
        "find_max": lambda values: max(values, default=0),
        "count_matches": lambda values: values.count(32),
        "count_digits": lambda values: sum(48 <= v <= 57 for v in values),
        "count_letters": lambda values: sum(65 <= v <= 90 for v in values),
        "search_string": lambda values: next((i + 1 for i in range(len(values) - 1) if values[i : i + 2] == [65, 66]), 0),
    }
    witnesses = []
    for row in rows:
        if row["pair"]["equivalence_label"] != "non_equivalent" or not all(name in oracles for name in row["endpoint_routines"]):
            continue
        truth = row["pair"]["ground_truth"]
        actual = [oracles[name](truth["input_bytes"]) for name in row["endpoint_routines"]]
        assert actual == [truth["left_result"], truth["right_result"]] and actual[0] != actual[1]
        witnesses.append(
            dict(
                pair_id=row["pair"]["pair_id"], routines=row["endpoint_routines"], input_bytes=truth["input_bytes"], independently_recomputed_outputs=actual, score=row["primary"], sources=[dict(path=s["source_path"], sha256=d.admitted.pairs.sha((d.ROOT / s["source_path"]).read_bytes())) for s in row["source_records"]]
            )
        )
    d.dump("SOURCE_WITNESSES.json", dict(scope="Independent Python mathematical witnesses checked against authored C and stored real Ghidra graphs; no new binary execution", witnesses=witnesses))
    attribution = []
    for kind in ("API", "CONSTANT", "SECTION"):

        def subset(condition, gid, view):
            return [f for f in fps[condition, gid][view + "_view"] if f["descriptor"].get("evidence_type") == kind]

        changed = {v: [g["graph_id"] for g in manifest["graphs"] if d.counts(subset("A", g["graph_id"], v)) != d.counts(subset("B", g["graph_id"], v))] for v in d.VIEWS}
        pair_changes = []
        for pair in manifest["pairs"]:
            for view in d.VIEWS:
                a = d.jaccard(subset("A", pair["left_graph_id"], view), subset("A", pair["right_graph_id"], view))
                b = d.jaccard(subset("B", pair["left_graph_id"], view), subset("B", pair["right_graph_id"], view))
                if any(a[k] != b[k] for k in ("set_intersection", "set_union", "multiset_intersection", "multiset_union")):
                    pair_changes.append(dict(pair_id=pair["pair_id"], view=view))
        attribution.append(dict(evidence_type=kind, changed_graph_ids_by_view=changed, overlap_changed_pairs=pair_changes, interpretation="Direct evidence-type descriptor accounting, not an isolated causal ablation of individual normalization subrules"))
    d.dump("NORMALIZATION_ATTRIBUTION.json", attribution)
    features = read("FEATURE_DIAGNOSTICS.json")
    queries = [q for q in read("RETRIEVAL_BIAS.json")["queries"] if q["condition"] == "B"]
    gm = {g["graph_id"]: g for g in features["graphs"] if g["condition"] == "B"}
    evidence = {}
    for v in d.VIEWS:
        comparable_neg = [r for r in rows if r["pair"]["equivalence_label"] == "non_equivalent" and r["views"][v]["multiset_similarity"] is not None]
        comparable_pos = [r for r in rows if r["pair"]["equivalence_label"] == "equivalent" and r["views"][v]["multiset_similarity"] is not None]
        evidence[v] = dict(
            empty_graphs=[g for g, r in gm.items() if r["views"][v]["empty"]],
            distinct_counts=d.distribution(r["views"][v]["distinct"] for r in gm.values()),
            multiplicities=d.distribution(r["views"][v]["multiplicity"] for r in gm.values()),
            equal_sets_including_empty=sum(r["views"][v]["equal_sets"] for r in rows),
            equal_nonempty_sets=sum(r["views"][v]["equal_sets"] and r["views"][v]["set_union"] > 0 for r in rows),
            negative_comparable_n=len(comparable_neg),
            negative_exact_one_ids=[r["pair"]["pair_id"] for r in comparable_neg if r["views"][v]["multiset_similarity"] == 1],
            positive_comparable_n=len(comparable_pos),
            positive_weak_lt_half_ids=[r["pair"]["pair_id"] for r in comparable_pos if r["views"][v]["multiset_similarity"] < 0.5],
        )
    digests = defaultdict(set)
    for fp in fps.values():
        for v in d.VIEWS:
            for f in fp[v + "_view"]:
                digests[f["id"]].add(d.encoded(f["descriptor"]))
    assert all(len(values) == 1 for values in digests.values()), "feature digest collision"
    random_ranges = []
    summaries = read("RETRIEVAL_BIAS.json")["summaries"]
    for split in protocol["design"]["cohort"]["splits"]:
        for cohort in ("all_eligible", "mixed", "mixed_with_hard_negative"):
            selected = [r for r in summaries if r["condition"] == "B" and r["split"] == split and r["cohort"] == cohort and r["method"].startswith("random_seed")]
            random_ranges.append(dict(split=split, cohort=cohort, permutation_means=d.distribution(r["mrr"]["mean"] for r in selected), policy="20 fixed-seed permutations; variability, not inferential CI"))
    diagnostics = dict(
        views=evidence,
        cryptographic_descriptor_collisions=0,
        descriptor_identity_count=len(digests),
        pair_classes=dict(Counter(c for r in rows for c in r["classes"])),
        motif_truncated_graph_ids=[g for g, r in gm.items() if any(t["truncated"] for t in r["motif_truncation"].values())],
        local_truncated_graph_ids=[g for g, r in gm.items() if r["local_truncation"]["truncated"]],
        warning_pair_ids=[r["pair"]["pair_id"] for r in rows if r["observability_warnings"]],
        random_ranges=random_ranges,
        false_top1=[dict(query=q["query_graph_id"], split=q["split"], ranking=q["rankings"]["OSGF"], candidates=q["candidates"]) for q in queries if q["eligible"] and q["rankings"]["OSGF"]["metrics"]["mrr"] < 1],
        negative_heldout=[
            dict(pair_id=r["pair"]["pair_id"], score=r["primary"], comparable_views=r["comparable_views"], view_scores={v: r["views"][v]["multiset_similarity"] for v in d.VIEWS}, witness=r["pair"]["ground_truth"], graph_ids=[r["pair"]["left_graph_id"], r["pair"]["right_graph_id"]])
            for r in rows
            if r["pair"]["split"] == "held_out_test" and r["pair"]["equivalence_label"] == "non_equivalent"
        ],
    )
    d.dump("SUPPLEMENTARY_METRICS.json", diagnostics)
    specs = [
        (
            "ROOT-EXTRACTION-01",
            "critical",
            "Extraction / representation",
            "Independently negative routines have exactly identical semantic descriptor multisets",
            [r for r in rows if "REPRESENTATION_INDISTINGUISHABLE" in r["classes"]],
            "Confirmed descriptor equivalence and independent frozen behavioral witnesses; fresh binary probe unavailable",
            "No scalar scoring or LLM normalization over these same descriptors can recover the absent distinguishing operations",
            "Add verifiable intraprocedural semantics and evidence support",
            "rust_engine/src/fingerprint.rs:317; ghidra_scripts/export_report.py:1497",
        ),
        (
            "ROOT-CALIBRATION-01",
            "critical",
            "Classification",
            "All held-out negatives exceed the discovery-selected 0.3 threshold",
            [r for r in rows if r["pair"]["split"] == "held_out_test" and r["pair"]["equivalence_label"] == "non_equivalent"],
            "Confirmed, 16 at 1 and three at 1/3; threshold computation correct",
            "Threshold changes cannot separate score-1 negative collisions from score-1 positives",
            "New independent calibration families after representation changes",
            "CLASSIFICATION_FAILURES.json; SUPPLEMENTARY_METRICS.json",
        ),
        (
            "ROOT-LOCAL-GRAPH-01",
            "high",
            "Local graph / feature construction",
            "Low positive scores coincide with changed positional topology and evidence context",
            [r for r in rows if "positive_low_lt_0.5" in r["classes"]],
            "Observed association; compiler/helper causes require case-specific source interpretation",
            "Exact roles/distances penalize changed helper layouts; expanded context can include compiler runtime behavior",
            "Controlled context and layout robustness experiments",
            "rust_engine/src/fingerprint.rs:341; CASE_STUDIES.md; STEP9_SUPPLEMENT.json",
        ),
        (
            "ROOT-OBSERVABILITY-01",
            "high",
            "Aggregation / interpretation",
            "Warnings are separate and empty-empty views do not contribute; generic topology alone can score one",
            [r for r in rows if "negative_exact_one" in r["classes"] and len(r["comparable_views"]) == 1],
            "Confirmed contract behavior, not a Jaccard arithmetic defect",
            "A high structural match is not proof of behavioral equivalence",
            "Versioned support/abstention policy with coverage reporting",
            "rust_engine/src/similarity.rs:150; FAILURE_CATALOG.json",
        ),
    ]
    causes = []
    for rid, severity, stage, description, affected, status, consequence, remedy, source in specs:
        gids = sorted({r["pair"][k] for r in affected for k in ("left_graph_id", "right_graph_id")})
        ids = sorted(r["pair"]["pair_id"] for r in affected)
        qs = [q["query_graph_id"] for q in queries if any(c["pair_id"] in ids for c in q["candidates"])]
        causes.append(
            dict(
                root_cause_id=rid,
                severity=severity,
                stage=stage,
                description=description,
                status=status,
                affected_pair_count=len(ids),
                affected_pair_ids=ids,
                affected_graph_count=len(gids),
                affected_graph_ids=gids,
                exposed_query_count=len(qs),
                exposed_query_ids=qs,
                query_count_definition="Queries containing an affected judged edge; not a claim that every exposed ranking changes",
                splits=sorted({r["pair"]["split"] for r in affected}),
                source_groups=sorted({r["pair"]["source_group_id"] for r in affected}),
                evidence=source,
                reproduction="python scripts/diagnose_baseline_report.py",
                consequence=consequence,
                remediation=remedy,
                alternative_explanations="Math mismatch excluded by independent oracle; representation vs compiler attribution distinguished per case; external generalization unsupported",
                minimal_example_pair_id=ids[0] if ids else None,
            )
        )
    causes.append(
        dict(
            root_cause_id="ROOT-EVALUATION-01",
            severity="high",
            stage="Judged galleries",
            status="Confirmed",
            affected_query_count=sum(q["eligible"] and q["negative_n"] == 0 for q in queries),
            affected_query_ids=[q["query_graph_id"] for q in queries if q["eligible"] and q["negative_n"] == 0],
            affected_pair_count=None,
            affected_graph_count=None,
            count_limitation="Gallery construction effect, not an attributable pairwise error",
            description="Positive-only eligible galleries guarantee MRR=1 for every ordering; mixed galleries and constant/random controls are essential",
            evidence="RETRIEVAL_BIAS.json",
            remediation="Preregister mixed judged galleries with stable denominators; no invented negatives",
        )
    )
    causes.append(
        dict(
            root_cause_id="ROOT-DATASET-01",
            severity="high",
            stage="Dataset / intervention coverage",
            status="Confirmed coverage limitation",
            affected_pair_count=218,
            affected_graph_count=120,
            description="Six source components; all negative judgments are within-PE; no section or value-merging examples and no pairwise overlap-changing A/B intervention",
            evidence="datasets/osgf_pairs_v0_1/split_config.json; NORMALIZATION_OPPORTUNITIES.json",
            remediation="New independent families and targeted normalization stressors; untouched test cohort",
            causal_limit="Does not explain away identical-descriptor false matches; limits external validity",
        )
    )
    d.dump("ROOT_CAUSE_MATRIX.json", dict(scope="Condition B counts; A duplicates are not independent observations; categories overlap", roots=causes))
    selected = []
    for tag, candidates, descending, limit in [
        ("highest false matches", [r for r in rows if "negative_exact_one" in r["classes"]], True, 5),
        ("lowest equivalent", [r for r in rows if r["pair"]["equivalence_label"] == "equivalent"], False, 5),
        ("strong true positive", [r for r in rows if r["pair"]["equivalence_label"] == "equivalent"], True, 1),
        ("incomplete observability", [r for r in rows if r["observability_warnings"]], True, 1),
        ("cross compiler", [r for r in rows if r["build_metadata"][0]["compiler"] != r["build_metadata"][1]["compiler"]], False, 1),
    ]:
        selected += [(tag, r) for r in sorted(candidates, key=lambda r: ((-1 if descending else 1) * r["primary"], r["pair"]["pair_id"]))[:limit]]
    lines = ["# Deterministic case studies", "", "Condition B; sorted by score then pair ID, no favorable-case selection. All 436 A/B entries remain in FAILURE_CATALOG.json. Stored independent behavioral witnesses are not claimed as freshly executed binary tests.", ""]
    for tag, r in selected:
        p = r["pair"]
        lines += [
            f"## {tag}: {p['pair_id']}",
            "",
            f"Split {p['split']}; label {p['equivalence_label']}; routines {r['endpoint_routines']}; score {r['primary']!r}. Builds: {p['left_build_id']} / {p['right_build_id']}.",
            "",
            f"Independent ground truth: `{json.dumps(p['ground_truth'], sort_keys=True)}`.",
            "",
            "| View | Set | Multiset | Intersection / union multiplicity |",
            "|---|---:|---:|---:|",
        ]
        for v, x in r["views"].items():
            lines.append(f"| {v} | {x['set_similarity']} | {x['multiset_similarity']} | {x['multiset_intersection']} / {x['multiset_union']} |")
        lines += ["", "Source-bearing evidence:"]
        for gid, origin, routine in zip((p["left_graph_id"], p["right_graph_id"]), r["endpoint_provenance"], r["source_records"]):
            lines += [f"- `{gid}`: `{origin['canonical_path']}` SHA-256 `{origin['canonical_sha256']}`; source `{routine['source_path']}`, routine `{routine['routine_id']}`; local node kinds `{gm[gid]['source_node_kinds']}`."]
        if "REPRESENTATION_INDISTINGUISHABLE" in r["classes"]:
            diagnosis = (
                "Confirmed representation-indistinguishable: every view has equal descriptor counts. "
                "Empty views supply no semantic evidence; matching generic roles/distances cannot distinguish the recorded behavior. "
                "Arithmetic failure is excluded by the independent oracle. Exact earliest extraction loss is supported by exporter/schema inspection; fresh binary reconstruction was not completed."
            )
        elif p["equivalence_label"] == "equivalent" and r["primary"] < 0.5:
            diagnosis = (
                "Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. "
                "Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. "
                "Inspect full count_differences in FAILURE_CATALOG.json; no label is changed."
            )
        else:
            diagnosis = "Agreement on the observed descriptors supports this comparison, not exhaustive semantic equivalence. Ground truth remains independent. Missing observability and narrow corpus coverage prevent extrapolation to arbitrary binaries."
        lines += ["", diagnosis, "", f"Warnings: `{json.dumps(r['observability_warnings'])}`.", "", "Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.", ""]
    raw = ("\n".join(lines) + "\n").encode()
    target = d.OUT / "CASE_STUDIES.md"
    if target.exists() and target.read_bytes() != raw:
        raise ValueError("case report replay differs")
    target.write_bytes(raw)
    print("Case studies", len(selected), "roots", len(causes), "no digest collisions", flush=True)


if __name__ == "__main__":
    summarize()
