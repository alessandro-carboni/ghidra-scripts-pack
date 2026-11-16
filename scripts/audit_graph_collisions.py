"""Revisit every historical indistinguishable negative without changing labels or bytes."""

import argparse
from collections import Counter
from pathlib import Path

try:
    from . import graph_first as g
    from .evaluate_operational_baseline import ROOT, sha
except ImportError:
    import graph_first as g
    from evaluate_operational_baseline import ROOT, sha


def audit(engine):
    path = ROOT / "datasets/osgf_baseline_diagnostics_v0_1/FAILURE_CATALOG.json"
    records = [r for r in g.load(path)["records"] if r["condition"] == "A" and r["pair"]["equivalence_label"] == "non_equivalent" and "REPRESENTATION_INDISTINGUISHABLE" in r["classes"]]
    cache, output = {}, []
    for record in records:
        endpoints = []
        for endpoint in record["endpoint_provenance"]:
            source_path = endpoint["canonical_path"]
            g.require(sha(ROOT / source_path) == endpoint["canonical_sha256"], "historical canonical bytes changed")
            if source_path not in cache:
                canonical = g.load(ROOT / source_path)
                cache[source_path] = g.fingerprint(canonical["source_document"], engine)
            doc = cache[source_path]
            c, f = doc["canonical"], doc["baseline"]
            excluded = [dict(canonical_element=k, disposition=v) for k, v in f["canonical_coverage"].items() if v["status"] == "excluded"]
            endpoints.append(
                dict(
                    path=source_path,
                    seed=c["seed_id"],
                    anchor=c["anchor_function_id"],
                    context=c["source_document"]["extraction_config"],
                    features={v: len(f[v + "_view"]) for v in g.VIEWS},
                    descriptor_families={v: dict(Counter(x["descriptor"]["kind"] for x in f[v + "_view"])) for v in g.VIEWS},
                    typed_observations=f["typed_evidence_view"],
                    missing_evidence=dict(unresolved=len(c["unresolved_calls"]), local_truncation=c["local_graph_truncation"]),
                    excluded_canonical_observations=excluded,
                    new_co_observations=doc["co_observations"]["features"],
                )
            )
        added = g.jaccard(endpoints[0]["new_co_observations"], endpoints[1]["new_co_observations"])
        distinguishable = added["set_similarity"] is not None and added["set_similarity"] < 1
        output.append(
            dict(
                pair_id=record["pair"]["pair_id"],
                endpoints=endpoints,
                new_view=added,
                resolved_by_added_relation=distinguishable,
                abstraction_collision=True,
                operational_need="Graph cannot establish the source behavior difference; auxiliary analysis or independent verification needed" if not distinguishable else "Already observed relation distinguishes descriptors; not an equivalence proof",
                basis="Historical labels/behavior counterexample preserved; canonical exclusions listed, not guessed",
                historical_views=record["views"],
            )
        )
    return dict(
        schema_version="osgf.graph-collision-audit/0.1.0",
        source_sha256=sha(path),
        negatives=67,
        exact_multiset_collisions=len(output),
        topology_only=sum(not r["endpoints"][0]["typed_observations"] and r["historical_views"]["interaction_motif"]["set_union"] == 0 for r in output),
        resolved=sum(r["resolved_by_added_relation"] for r in output),
        records=output,
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--engine", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = audit(args.engine)
    g.write(args.output, result)
    print({k: v for k, v in result.items() if k != "records"})
