"""Step 10.1 preregistration: immutable design and source bindings, never scores."""

import argparse
import hashlib
import json
from pathlib import Path

try:
    from .evaluation_preflight import AUDIT_DIR, ROOT, build_audit, judged_galleries, serialize
    from .dataset_manifest import validate, require
    from .transformation_schema import check_schema
except ImportError:
    from evaluation_preflight import AUDIT_DIR, ROOT, build_audit, judged_galleries, serialize
    from dataset_manifest import validate, require
    from transformation_schema import check_schema


def design():
    return dict(
        protocol_version="0.1.0",
        protocol_id="osgf-baseline-evaluation-0.1.0",
        scope="judged-gallery / limited-judgment evaluation of benign function equivalence",
        conditions=dict(
            A=dict(
                name="No semantic canonicalization research control",
                status="requires_step_10_2_parity_gate",
                input="same validated embedded LocalSubgraphDocument as B",
                restriction="Separate source-traceable adapter; no forged canonical documents or bypassed frozen validation; explicitly shared structural role/order preprocessing",
            ),
            B=dict(name="Deterministic Canonicalization v0.1", input="validated frozen CanonicalSubgraph", canonicalization_version="0.1.0", fingerprint_version="0.1.0", similarity_version="0.1.0"),
        ),
        features=dict(
            semantic_views=["rooted_topology", "typed_evidence", "interaction_motif"],
            topology_motif_limit=4096,
            interaction_motif_limit=4096,
            enumeration_checks_per_family=1000000,
            observability="separate diagnostics; never affects semantic scores",
            feature_parity="Same descriptors/families/counting/budgets except explicitly approved normalization values; B must match frozen engine",
        ),
        scoring=dict(
            primary="aggregate_multiset_similarity",
            secondary=["aggregate_set_similarity", "per_view_set_similarity", "per_view_multiset_similarity"],
            aggregate="unweighted arithmetic mean of comparable semantic views",
            both_empty="null_noncomparable",
            one_empty="zero_comparable",
            all_empty="null_exclude_from_scored_denominator_and_report",
            truncated="retain_with_completeness_warning",
            numeric="IEEE754 binary64, exact integer Jaccard sums, no rounding before ranking; report full JSON precision",
            paired_components="require identical comparable-view sets in A/B; otherwise separate condition coverage, not a paired delta",
        ),
        cohort=dict(
            source="all 218 independently frozen labeled pairs; no score-based admission",
            labels=["equivalent", "non_equivalent"],
            accepted_statuses=["automatically_grounded", "manually_verified"],
            unknown_relevance="never a negative; never transitive",
            splits=["discovery_train", "validation", "held_out_test"],
            split_assignment="frozen source/artifact components, no reassignment",
            physical_graph_identity=["sample.sha256", "anchor_function_id"],
            same_graph="exclude",
            same_physical_function="exclude",
            same_binary_different_anchor="retain; disclose dependence",
            same_canonical_digest_distinct_provenance="retain",
            candidate_duplicate_physical_function="retain lexicographically smallest graph_id; conflicting judgments fail",
            same_canonical_file_bytes="deduplicate exact byte copies with identical physical provenance only",
            step9="separate optional discovery-only supplementary cohort; not part of primary Step 8 evaluation",
        ),
        retrieval=dict(
            direction="each endpoint of an admitted undirected judgment is a query",
            gallery="query-specific judged references only, same split",
            minimum_positives=1,
            k=[1, 3, 5],
            k_exceeds_gallery="unsupported_null",
            null_candidate="entire query excluded from scored retrieval; keep original gallery and disclose coverage",
            tie_policy="primary_score_descending_then_reference_graph_id_ascending",
            paired_conditions="identical query/reference sets and judgments; complete common cohort only",
            recall="per query: number of known relevant references in top K / total known relevant references in full judged gallery",
            hit="per query: 1 if any known positive in top K else 0; named Hit@K separately",
            mrr="mean over eligible scored queries of reciprocal rank of first known relevant reference",
            macro="arithmetic mean over eligible queries within split and K; emit query IDs and denominator",
            retrieval_false_top1="non_equivalent top1 / eligible scored queries; unknown relevance unsupported",
        ),
        threshold=dict(
            selection_split="discovery_train",
            algorithm="maximize balanced accuracy on discovery comparable pairs; candidates = distinct discovery scores plus reject_all; score >= threshold is match; ties choose largest threshold (reject_all largest)",
            per_condition=True,
            paired_cohort="same discovery pair IDs and comparable component sets for A/B calibration",
            missing_class="unsupported_null",
            freeze_before_validation=True,
            positive_prediction="score >= finite threshold; reject_all predicts no matches",
            false_match_rate="negative scored pairs predicted match / all eligible scored negative pairs",
            selection_on_validation_or_heldout=False,
        ),
        distributions=dict(
            labels="positive and negative separately", summaries=["n", "mean", "median", "minimum", "maximum", "q05", "q25", "q75", "q95"], quantile="linear interpolation h=(n-1)*p; null for empty cohort", strata=["split", "source_group", "compiler", "optimization", "family", "signal_availability", "observability"]
        ),
        churn=dict(
            alignment="exact scientific descriptors and counts within condition; cross-condition align only approved descriptor mapping, never version-dependent feature IDs",
            presence="symmetric difference size / union size",
            multiplicity="sum(abs(count_left-count_right)) / sum(max(count_left,count_right))",
            empty_union="null with empty_both reason",
            details="inserted/deleted descriptors and instances; shared-descriptor count deltas",
            cohort="independently equivalent pairs only, per view; incomplete/truncated observations remain qualified",
        ),
        rank_stability=dict(
            primary_dimension="A vs B identical judged gallery",
            secondary_dimensions="compiler/optimization or Step9 only where independently justified identical reference IDs exist; otherwise unsupported",
            metrics=["mean_absolute_rank_difference/(N-1)", "topK_intersection/K", "Spearman correlation of average tie ranks"],
            n_one="normalized rank difference zero; correlation undefined/null",
            constant_ranks="correlation null",
            ties="average ranks for correlation; graph-id tiebreak only for deterministic topK",
            k_exceeds_gallery="unsupported_null",
        ),
        uncertainty=dict(
            cluster="connected frozen source/artifact/declared near-duplicate components, not independent pairs",
            minimum_clusters_for_inference=10,
            primary="descriptive cluster-macro summaries; no inferential intervals when <10 independent components",
            if_supported="paired cluster bootstrap 2000 replicates seed 101; percentile interval 2.5/97.5; undefined replicates disclosed",
            significance="no unqualified significance or population inference",
        ),
        runtime=dict(
            clock="monotonic perf_counter_ns",
            warmups=1,
            repetitions=5,
            cohort="all eligible matched A/B graphs and pairs, deterministic IDs",
            order="alternate A/B order across repetitions",
            profile="same locked debug engine and same research adapter runtime; report language/startup overhead as confound",
            stages=["input_validation_loading", "canonicalization_or_adapter", "feature_extraction", "pair_comparison", "ranking"],
            cache="outputs not reused as zero-cost execution; shared Ghidra upstream cost excluded and disclosed",
            timeout_seconds=120,
            summary="raw repetitions, median and linear-interpolated quantiles, failure counts",
            memory="optional; unsupported unless common verified peak RSS method",
            replay="scientific outputs byte-identical; timings excluded from scientific digests",
        ),
        gates=dict(step10_2="No empirical A/B scores until tested comparability is admitted; unsupported A blocks full acceptance", no_test_selection=True, no_similarity_labels=True, no_malware_claim=True, revision="new immutable protocol version and explicit rationale/authorization; never overwrite"),
    )


def locked_schema(value):
    if isinstance(value, dict):
        return dict(type="object", properties={k: locked_schema(v) for k, v in value.items()}, required=sorted(value), additionalProperties=False)
    return {"const": value}


def eligibility(manifest):
    validate(manifest)
    graphs = {g["graph_id"]: g for g in manifest["graphs"]}
    samples = {s["sample_id"]: s for s in manifest["samples"]}

    def physical(gid):
        graph = graphs[gid]
        return samples[graph["sample_id"]]["sha256"], graph["anchor_function_id"]

    raw = judged_galleries(manifest)
    exclusions = []
    queries = []
    for q in raw["queries"]:
        chosen = {}
        for candidate in q["candidates"]:
            key = physical(candidate["reference_graph_id"])
            if key == physical(q["query_graph_id"]):
                exclusions.append(dict(query=q["query_graph_id"], reference=candidate["reference_graph_id"], reason="same_physical_function"))
                continue
            if key in chosen:
                require(chosen[key]["label"] == candidate["label"], "contradictory duplicate-physical relevance")
                exclusions.append(dict(query=q["query_graph_id"], reference=candidate["reference_graph_id"], reason="duplicate_physical_reference"))
                continue
            chosen[key] = candidate
        candidates = sorted(chosen.values(), key=lambda c: c["reference_graph_id"])
        positives = sum(c["label"] == "equivalent" for c in candidates)
        queries.append(dict(query_graph_id=q["query_graph_id"], split=q["split"], candidates=candidates, positive_count=positives, eligible=positives > 0, gallery_size=len(candidates)))
    return dict(queries=queries, exclusions=exclusions)


def proposed(root=ROOT):
    root = Path(root)
    audit = build_audit(root)
    manifest = json.loads((root / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    return dict(design=design(), inputs=audit["frozen_input_inventory"], eligibility=eligibility(manifest))


def validate_protocol(protocol, root=ROOT):
    require(set(protocol) == {"design", "inputs", "eligibility"}, "unexpected protocol fields")
    check_schema(protocol["design"], locked_schema(design()), "protocol.design")
    require(serialize(protocol["design"]) == serialize(design()), "protocol policy types/values mismatch")
    actual = proposed(root)
    require(serialize(protocol["inputs"]) == serialize(actual["inputs"]), "frozen inputs mismatch")
    require(serialize(protocol["eligibility"]) == serialize(actual["eligibility"]), "judged eligibility/group/positive mismatch")
    return protocol


def load_protocol(root=ROOT):
    folder = Path(root) / AUDIT_DIR
    raw = (folder / "protocol.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == (folder / "protocol.sha256").read_text().strip(), "protocol bytes changed; explicit revision required")
    protocol = json.loads(raw)
    schema = json.loads((folder / "protocol.schema.json").read_bytes())
    require(schema == locked_schema(protocol), "registered schema mismatch")
    check_schema(protocol, schema, "protocol")
    return validate_protocol(protocol, root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", action="store_true")
    args = parser.parse_args()
    if args.register:
        raw = serialize(proposed())
        folder = ROOT / AUDIT_DIR
        require(not any((folder / name).exists() for name in ("protocol.json", "protocol.sha256", "protocol.schema.json")), "protocol already registered")
        for name, value in (("protocol.json", raw), ("protocol.sha256", (hashlib.sha256(raw).hexdigest() + "\n").encode()), ("protocol.schema.json", serialize(locked_schema(json.loads(raw))))):
            with (folder / name).open("xb") as stream:
                stream.write(value)
    protocol = load_protocol()
    print("PROTOCOL 10.1 VERIFIED", hashlib.sha256(serialize(protocol)).hexdigest())
    for split in protocol["design"]["cohort"]["splits"]:
        q = [q for q in protocol["eligibility"]["queries"] if q["split"] == split and q["eligible"]]
        print(split, "queries", len(q), "K coverage", {k: sum(row["gallery_size"] >= k for row in q) for k in (1, 3, 5)})
    print("No scores read/computed. A/B admission still requires Step 10.2.")
