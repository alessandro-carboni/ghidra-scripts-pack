"""Opt-in observable-seeded graph comparison. Frozen Rust stages remain authoritative."""

import argparse
from collections import defaultdict
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

try:
    from .diagnose_baseline_core import jaccard
    from .recovered_evidence import encoded, digest
except ImportError:
    from diagnose_baseline_core import jaccard
    from recovered_evidence import encoded, digest

SCHEMA = "osgf.graph-first/0.1.0"
VIEWS = ("rooted_topology", "typed_evidence", "interaction_motif")
RELATIONS = {"calls_api", "references_string", "uses_constant"}
MAX_MOTIFS = 4096
MAX_ENUMERATION = 100000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def command(engine, *args):
    result = subprocess.run([str(engine), *map(str, args)], capture_output=True, text=True, timeout=180, check=False)
    require(result.returncode == 0, result.stdout + result.stderr)


def relations(canonical):
    """Two observations on one function, or one on each end of a directed call.

    Counts are motif instances, never products of callsite multiplicities.
    Full canonical IDs remain solely in the support sidecar.
    """
    nodes = {n["id"]: n for n in canonical["nodes"]}
    observed = defaultdict(list)
    for edge in canonical["edges"]:
        if edge["kind"] in RELATIONS:
            observed[edge["source"]].append((dict(relation=edge["kind"], type=nodes[edge["target"]]["kind"], facts=nodes[edge["target"]]["facts"]), [edge["source"], edge["id"], edge["target"]]))
    for edge in canonical["edges"]:
        if edge["kind"] == "references_string":
            for category in canonical["edges"]:
                if category["source"] == edge["target"] and category["kind"] == "has_string_category":
                    observed[edge["source"]].append((dict(relation="string_category_chain", type="STRING_CATEGORY", facts=nodes[category["target"]]["facts"]), [edge["source"], edge["id"], edge["target"], category["id"], category["target"]]))
    candidates = []

    def add(descriptor, support):
        require(len(candidates) < MAX_ENUMERATION, "co-observation enumeration budget exceeded")
        candidates.append((encoded(descriptor), tuple(sorted(set(support)))))

    for function, evidence in sorted(observed.items()):
        for a, b in itertools.combinations(evidence, 2):
            if a[0] != b[0]:
                add(dict(kind="same_function_observations", function=nodes[function]["facts"], evidence=sorted([a[0], b[0]], key=encoded)), a[1] + b[1])
    for edge in canonical["edges"]:
        if edge["kind"] == "calls_function":
            for a, b in itertools.product(observed[edge["source"]], observed[edge["target"]]):
                add(dict(kind="directed_observation_pair", caller=nodes[edge["source"]]["facts"], callee=nodes[edge["target"]]["facts"], source=a[0], target=b[0], recursive=edge["source"] == edge["target"]), a[1] + b[1] + [edge["id"]])
    counts, support = defaultdict(int), defaultdict(list)
    for descriptor, elements in sorted(candidates)[:MAX_MOTIFS]:
        counts[descriptor] += 1
        support[digest(json.loads(descriptor))].append(list(elements))
    return dict(features=[dict(id=digest(json.loads(k)), descriptor=json.loads(k), count=v) for k, v in sorted(counts.items())], support=dict(sorted(support.items())), enumerated=len(candidates), omitted=max(0, len(candidates) - MAX_MOTIFS))


def fingerprint(local, engine, graph=None):
    """Rebuild from source with the frozen validator; never trust supplied digests."""
    with tempfile.TemporaryDirectory(prefix="osgf-graph-first-") as folder:
        folder = Path(folder)
        source, canonical, baseline = [folder / n for n in ("local.json", "canonical.json", "baseline.json")]
        write(source, local)
        command(engine, "canonicalize-local-subgraph", source, canonical)
        command(engine, "fingerprint-canonical", canonical, baseline)
        c, f = load(canonical), load(baseline)
        origin = None
        if graph is not None:
            write(folder / "report.json", dict(typed_graph=graph))
            options = []
            for key, value in local["extraction_config"].items():
                if value is not None:
                    options.extend(["--" + key.replace("_", "-"), value])
            command(engine, "export-local-subgraphs", folder / "report.json", folder / "seeds", *options)
            manifest = load(folder / "seeds/manifest.json")
            selected = [e for e in manifest["subgraphs"] if e["anchor_function_id"] == c["anchor_function_id"]]
            require(len(selected) == 1, "anchor not recovered by automatic detector")
            command(engine, "canonicalize-local-subgraph", folder / "seeds" / selected[0]["file"], folder / "selected.json")
            require(load(folder / "selected.json") == c, "automatic seed context/source differs")
            seed = next(s for s in manifest["seed_detection"]["seeds"] if s["seed_id"] == c["seed_id"])
            origin = dict(mode="automatically_detected", graph=graph, graph_digest=digest(graph), seed=seed)
    extra = relations(c)
    science = dict(schema=SCHEMA, baseline=f["semantic_digest"], co_observations=extra["features"])
    return dict(schema_version=SCHEMA, canonical=c, baseline=f, co_observations=extra, semantic_digest=digest(science), seed_origin=origin)


def validate(document, engine):
    require(document.get("schema_version") == SCHEMA, "unsupported graph-first schema")
    origin = document.get("seed_origin")
    require(document == fingerprint(document["canonical"]["source_document"], engine, origin["graph"] if origin else None), "graph-first source reconstruction mismatch")


def compare(query, reference, engine):
    for doc in (query, reference):
        validate(doc, engine)
    with tempfile.TemporaryDirectory(prefix="osgf-graph-comparison-") as directory:
        directory = Path(directory)
        for prefix, doc in (("q", query), ("r", reference)):
            write(directory / (prefix + "c.json"), doc["canonical"])
            write(directory / (prefix + "f.json"), doc["baseline"])
        out = directory / "result.json"
        command(engine, "compare-fingerprints", "query", directory / "qc.json", directory / "qf.json", "reference", directory / "rc.json", directory / "rf.json", out, "--aggregate")
        baseline = load(out)
    return assemble(query, reference, baseline)


def assemble(query, reference, baseline):
    """Internal assembly after authoritative validation; public CLI always validates."""
    components = {v: jaccard(query["baseline"][v + "_view"], reference["baseline"][v + "_view"]) for v in VIEWS}
    components["co_observations"] = jaccard(query["co_observations"]["features"], reference["co_observations"]["features"])
    scores = [v["set_similarity"] for v in components.values() if v["set_similarity"] is not None]
    multiset = [v["multiset_similarity"] for v in components.values() if v["multiset_similarity"] is not None]
    identities, support = {}, {}
    for name, doc in (("query", query), ("reference", reference)):
        c, f = doc["canonical"], doc["baseline"]
        origin = doc["seed_origin"]
        identities[name] = dict(seed_id=c["seed_id"], anchor=c["anchor_function_id"], canonical_digest=c["canonical_digest"], fingerprint_digest=doc["semantic_digest"], seed_mode="automatic" if origin else "provided_local_context", triggering_observations=origin["seed"] if origin else None)
        support[name] = dict(
            typed_descriptors=len(f["typed_evidence_view"]),
            topology_descriptors=len(f["rooted_topology_view"]),
            interaction_descriptors=len(f["interaction_motif_view"]),
            co_observation_descriptors=len(doc["co_observations"]["features"]),
            topology_only=not f["typed_evidence_view"] and not f["interaction_motif_view"],
            unresolved_records=len(c["unresolved_calls"]),
            local_truncation=c["local_graph_truncation"],
            motif_truncation=f["motif_truncation"],
            co_observations_omitted=doc["co_observations"]["omitted"],
            source_coverage=f["source_coverage_totals"],
        )
    return dict(
        schema_version="osgf.graph-first-result/0.1.0",
        identities=identities,
        graph_similarity=dict(set_similarity=sum(scores) / len(scores) if scores else None, multiset_similarity=sum(multiset) / len(multiset) if multiset else None, aggregation="equal mean of nonempty comparable graph views; no operational weight", components=components),
        baseline_comparison=baseline,
        evidence_support=support,
        operational_evidence=dict(status="not_requested", score=None, contribution_to_graph_score=0),
        verified_contradictions=[],
        interpretation="Descriptor agreement, not malware probability, calibrated confidence or proof of behavioral equivalence",
        provenance=dict(query=query, reference=reference),
    )


def extract(graph, engine, output):
    """No labels or routine identities enter the detector. All returned seeds retained."""
    output = Path(output)
    require(not output.exists(), "fresh output directory required")
    output.mkdir(parents=True)
    write(output / "report.json", dict(typed_graph=graph))
    command(engine, "export-local-subgraphs", output / "report.json", output / "local", "--caller-depth", 1, "--callee-depth", 2, "--max-function-nodes", 64, "--max-evidence-nodes", 512, "--max-total-nodes", 576, "--max-edges", 2048)
    manifest = load(output / "local/manifest.json")
    records = []
    for i, entry in enumerate(manifest["subgraphs"]):
        fp = fingerprint(load(output / "local" / entry["file"]), engine, graph)
        path = f"seed-{i:05}.json"
        write(output / path, fp)
        records.append(dict(seed_id=entry["seed_id"], anchor=entry["anchor_function_id"], fingerprint=path))
    result = dict(schema_version="osgf.seed-search-index/0.1.0", source_graph=graph, seed_manifest=manifest, records=records, eligible=bool(records), missing_seed_reason=None if records else "no eligible observable seed; no research anchor substituted")
    write(output / "index.json", result)
    return result


def search(query, references, engine):
    require(len({name for name, _ in references}) == len(references), "duplicate reference identity")
    rows = [dict(reference_id=name, result=compare(query, doc, engine)) for name, doc in references]
    rows.sort(key=lambda row: (row["result"]["graph_similarity"]["set_similarity"] is None, -(row["result"]["graph_similarity"]["set_similarity"] or 0), row["reference_id"]))
    return dict(schema_version="osgf.graph-first-ranking/0.1.0", candidate_policy="exhaustive; no score cutoff; nulls last; ID ascending for ties", candidates=[dict(rank=i + 1, **row) for i, row in enumerate(rows)])


def operational(result, query_path, reference_path, engine):
    """Existing v0.2 mathematics, independently validated; no score blending."""
    require(engine is not None, "operational engine required")
    for side, path in (("query", query_path), ("reference", reference_path)):
        doc = load(path)
        source = doc["source_canonical"]["source_document"]
        structural = source["structural"]
        require(structural == result["provenance"][side]["canonical"]["source_document"], "operational source/context differs from compared subgraph")
        origin = result["provenance"][side].get("seed_origin")
        if origin:
            binary = origin["graph"].get("metadata", {}).get("research_binary_sha256")
            require(binary is not None and binary == source["binary_sha256"], "operational binary provenance unavailable or mismatched")
    with tempfile.TemporaryDirectory(prefix="osgf-auxiliary-") as folder:
        output = Path(folder) / "comparison.json"
        command(engine, "operational-compare", query_path, reference_path, output)
        evidence = load(output)
    result["operational_evidence"] = dict(status="available", comparison=evidence, contribution_to_graph_score=0, interpretation="Representation agreement/disagreement; not a verified behavioral contradiction")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("extract", "fingerprint", "compare", "search"))
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--query-operational", type=Path)
    parser.add_argument("--reference-operational", type=Path)
    parser.add_argument("--operational-engine", type=Path)
    args = parser.parse_args()
    require(bool(args.query_operational) == bool(args.reference_operational), "both operational inputs required")
    require(not args.query_operational or args.action == "compare", "operational inputs supported on compare only")
    require(not args.output.exists(), "refusing existing output")
    documents = [load(p) for p in args.inputs]
    if args.action == "extract":
        require(len(documents) == 1, "one typed graph required")
        extract(documents[0], args.engine, args.output)
        return
    if args.action == "fingerprint":
        require(len(documents) == 1, "one local source required")
        result = fingerprint(documents[0], args.engine)
    elif args.action == "compare":
        require(len(documents) == 2, "two graph fingerprints required")
        result = compare(*documents, args.engine)
        if args.query_operational:
            result = operational(result, args.query_operational, args.reference_operational, args.operational_engine)
    else:
        require(len(documents) >= 2, "query plus references required")
        result = search(documents[0], [(str(p), d) for p, d in zip(args.inputs[1:], documents[1:])], args.engine)
    write(args.output, result)


if __name__ == "__main__":
    main()
