"""Directional reference coverage; additive projection over validated OSGF evidence."""

import argparse
from fractions import Fraction
from pathlib import Path

try:
    from . import graph_first as graph
except ImportError:
    import graph_first as graph

SCHEMA = "osgf.reference-coverage/0.1.0"
FAMILIES = ("apis", "strings", "contextual_constants", "sections", "string_categories")
BASE_FAMILIES = FAMILIES[:-1]
TYPES = dict(API="apis", STRING="strings", CONSTANT="contextual_constants", SECTION="sections")


def feature_map(features):
    result = {}
    for feature in features:
        count = feature["count"]
        graph.require(type(count) is int and count > 0, "feature count must be a positive integer")
        key = graph.encoded(feature["descriptor"])
        graph.require(key not in result, "duplicate descriptor")
        result[key] = feature
    return result


def ratio(numerator, denominator):
    return float(Fraction(numerator, denominator)) if denominator else None


def coverage(query, reference):
    """Exact integer accounting; floats are produced only at the JSON boundary."""
    q, r = feature_map(query), feature_map(reference)
    common = q.keys() & r.keys()
    distinct = len(common)
    matched = sum(min(q[k]["count"], r[k]["count"]) for k in common)
    total = sum(f["count"] for f in r.values())
    return dict(
        set=ratio(distinct, len(r)),
        multiset=ratio(matched, total),
        comparable=bool(r),
        exact=dict(set=dict(numerator=distinct, denominator=len(r)), multiset=dict(numerator=matched, denominator=total)),
        query_distinct=len(q),
        reference_distinct=len(r),
        query_occurrences=sum(f["count"] for f in q.values()),
        reference_occurrences=total,
    )


def origins(document, occurrences):
    canonical = document["canonical"]
    return [dict(multiplicity=o["multiplicity"], canonical_elements=o["canonical_elements"], origins=[dict(canonical_element=e, source_references=canonical["provenance_map"][e]) for e in o["canonical_elements"]]) for o in occurrences]


def projections(document):
    """Read-only projection; caller must first validate the complete source envelope.

    Only attached typed evidence is admitted. Categories remain a derived family,
    never another vote in the disjoint base-value collection.
    """
    fp = document["baseline"]
    values = {family: {} for family in FAMILIES}
    for feature in fp["typed_evidence_view"]:
        descriptor = feature["descriptor"]
        if descriptor["kind"] == "typed_evidence":
            family = TYPES.get(descriptor["evidence_type"])
            if family is None:
                continue
            value = descriptor["evidence"]
        elif descriptor["kind"] == "category_chain":
            family, value = "string_categories", descriptor["category"]
        else:
            raise ValueError("unsupported typed descriptor kind")
        projected = dict(family=family, value=value)
        key = graph.encoded(projected)
        entry = values[family].setdefault(key, dict(descriptor=projected, count=0, support={}))
        for occurrence in origins(document, fp["provenance_index"][feature["id"]]):
            identity = graph.encoded(occurrence["canonical_elements"])
            if identity in entry["support"]:
                graph.require(entry["support"][identity] == occurrence, "conflicting observation support")
            else:
                entry["support"][identity] = occurrence
                entry["count"] += occurrence["multiplicity"]
    evidence = {}
    for family in FAMILIES:
        evidence[family] = [dict(descriptor=e["descriptor"], count=e["count"], provenance=[e["support"][k] for k in sorted(e["support"])]) for _, e in sorted(values[family].items())]
    relations = {}
    for view in graph.VIEWS:
        relations[view] = [dict(descriptor=f["descriptor"], count=f["count"], provenance=origins(document, fp["provenance_index"][f["id"]])) for f in fp[view + "_view"]]
    relations["co_observations"] = [dict(descriptor=f["descriptor"], count=f["count"], provenance=origins(document, [dict(canonical_elements=elements, multiplicity=1) for elements in document["co_observations"]["support"][f["id"]]])) for f in document["co_observations"]["features"]]
    return dict(evidence=evidence, relations=relations)


def qualification(incomplete, deficit=False):
    base = "observed_count_deficit" if deficit else "observed_absent"
    return base + ("_with_incomplete_observability" if incomplete else "")


def partition(query, reference, query_incomplete, reference_incomplete):
    q, r = feature_map(query), feature_map(reference)
    matched, missing, extra = [], [], []
    for key in sorted(q.keys() | r.keys()):
        a, b = q.get(key), r.get(key)
        qc, rc = (a["count"] if a else 0), (b["count"] if b else 0)
        if a and b:
            matched.append(dict(descriptor=a["descriptor"], query_count=qc, reference_count=rc, matched_count=min(qc, rc), query_provenance=a["provenance"], reference_provenance=b["provenance"]))
        if rc > qc:
            missing.append(dict(descriptor=b["descriptor"], count=rc - qc, descriptor_absent=a is None, qualification=qualification(query_incomplete, a is not None), provenance=b["provenance"]))
        if qc > rc:
            extra.append(dict(descriptor=a["descriptor"], count=qc - rc, descriptor_absent=b is None, qualification=qualification(reference_incomplete, b is not None), provenance=a["provenance"]))
    return dict(coverage=coverage(query, reference), matched=matched, missing_reference=missing, additional_query=extra)


def compare(query, reference, engine):
    # Reuse the authoritative validators and the unchanged symmetric comparator.
    previous = graph.compare(query, reference, engine)
    q, r = projections(query), projections(reference)
    observation = previous["baseline_comparison"]["observability"]
    qi, ri = observation["query_possibly_incomplete"], observation["reference_possibly_incomplete"]
    values = {family: partition(q["evidence"][family], r["evidence"][family], qi, ri) for family in FAMILIES}
    base_q = [f for family in BASE_FAMILIES for f in q["evidence"][family]]
    base_r = [f for family in BASE_FAMILIES for f in r["evidence"][family]]
    overall = partition(base_q, base_r, qi, ri)
    related = {}
    for view in q["relations"]:
        q_incomplete = qi or (view == "co_observations" and query["co_observations"]["omitted"] > 0)
        r_incomplete = ri or (view == "co_observations" and reference["co_observations"]["omitted"] > 0)
        related[view] = partition(q["relations"][view], r["relations"][view], q_incomplete, r_incomplete)
    accounting = {}
    for side, projection in (("query", q), ("reference", r)):
        base = [f for family in BASE_FAMILIES for f in projection["evidence"][family]]
        accounting[side] = dict(
            unique_normalized_base_values=len(base),
            base_observation_occurrences=sum(f["count"] for f in base),
            derived_category_values=len(projection["evidence"]["string_categories"]),
            distinct_relation_descriptors={view: len(features) for view, features in projection["relations"].items()},
            policy="Only disjoint base-value families enter overall value coverage. Categories, seed triggers and relation/motif descriptors are not additional independent votes. Multiset counts describe observed attachments/occurrences, not confidence.",
        )
    return dict(
        schema_version=SCHEMA,
        identities=previous["identities"],
        reference_coverage=dict(basis="normalized_base_evidence_values", unit_weights=True, **overall["coverage"]),
        evidence_value_coverage=dict(per_family={k: v["coverage"] for k, v in values.items()}, overall_if_defined=overall["coverage"], overall_families=list(BASE_FAMILIES), excluded_from_overall=["string_categories", "seed_triggers", "all_relation_descriptors", "all_derived_motifs"]),
        relation_aware_coverage=dict(per_view={k: v["coverage"] for k, v in related.items()}, overall_if_defined=None, reason="No aggregate across correlated descriptor views is defined by this protocol"),
        symmetric_similarity=dict(original_baseline=previous["baseline_comparison"], existing_graph_first=previous["graph_similarity"]),
        matched_evidence=dict(evidence_values={k: v["matched"] for k, v in values.items()}, relation_descriptors={k: v["matched"] for k, v in related.items()}),
        missing_reference_evidence=dict(evidence_values={k: v["missing_reference"] for k, v in values.items()}, relation_descriptors={k: v["missing_reference"] for k, v in related.items()}),
        additional_query_evidence=dict(evidence_values={k: v["additional_query"] for k, v in values.items()}, relation_descriptors={k: v["additional_query"] for k, v in related.items()}),
        evidence_support=dict(legacy=previous["evidence_support"], accounting=accounting, observability=observation, warnings=previous["baseline_comparison"]["observability_warnings"]),
        interpretation=dict(
            reference_feature_coverage=True,
            malware_probability=False,
            behavioral_equivalence=False,
            calibrated_confidence=False,
            missing_evidence="Not statically observed; no hidden API, string or matching feature is inferred",
            generic_evidence="Unit weights do not imply equal discriminative strength; support is not confidence",
        ),
        sources=previous["provenance"],
    )


def validate_result(result, engine):
    graph.require(result.get("schema_version") == SCHEMA, "unsupported reference-coverage schema")
    expected = compare(result["sources"]["query"], result["sources"]["reference"], engine)
    graph.require(graph.encoded(result) == graph.encoded(expected), "reference-coverage reconstruction mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("compare", "validate"))
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    documents = [graph.load(p) for p in args.inputs]
    if args.action == "validate":
        graph.require(len(documents) == 1 and args.output is None, "validate takes one result and no output")
        validate_result(documents[0], args.engine)
        print("REFERENCE COVERAGE VALIDATED")
    else:
        graph.require(len(documents) == 2 and args.output is not None, "compare takes query/reference fingerprints and a new output")
        graph.require(not args.output.exists(), "refusing existing output")
        graph.write(args.output, compare(*documents, args.engine))
        print("REFERENCE COVERAGE WRITTEN", args.output)


if __name__ == "__main__":
    main()
