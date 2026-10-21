"""Deterministic provenance relations, not inferred semantic equivalence or graph similarity."""

import json
from pathlib import Path
import sys

try:
    from .step9_preflight import ROOT, exact_hash, safe_path
    from .transformation_build import persist, verify_builds
    from .transformation_extraction import select_anchor, verify_graphs
    from .transformation_harness import load_run
    from .transformation_schema import VERSION, serialize, stable_id, validate_record
except ImportError:
    from step9_preflight import ROOT, exact_hash, safe_path
    from transformation_build import persist, verify_builds
    from transformation_extraction import select_anchor, verify_graphs
    from transformation_harness import load_run
    from transformation_schema import VERSION, serialize, stable_id, validate_record


def default_engine(root=ROOT):
    return Path(root) / ("rust_engine/target/debug/rust_engine.exe" if sys.platform == "win32" else "rust_engine/target/debug/rust_engine")


def relation(execution, level, left, right, evidence, claim, status="verified", kind=None):
    left, right = sorted(set(left)), sorted(set(right))
    kind = kind or ("one_to_one" if len(left) == len(right) == 1 else "one_to_many" if len(left) == 1 and len(right) > 1 else "many_to_one" if len(left) > 1 and len(right) == 1 else "ambiguous" if left and right else "unknown")
    if kind == "ambiguous":
        status = "ambiguous"
    value = dict(
        record_type="mapping",
        schema_version=VERSION,
        transformation_id=execution["transformation_id"],
        execution_id=execution["execution_id"],
        original_element_references=left,
        transformed_element_references=right,
        mapping_level=level,
        mapping_kind=kind,
        expected_mapping=claim,
        observed_mapping=claim if status == "verified" else None,
        supporting_evidence=sorted(evidence, key=serialize),
        observation_completeness="complete" if status == "verified" else "incomplete",
        validation_status=status,
        limitations=["Provenance relation only; no functional equivalence or similarity score is inferred."] + ([] if status == "verified" else ["No verified counterpart in the admitted observation; elements are retained."]),
    )
    value["mapping_id"] = stable_id("mapping", value)
    return validate_record(value)


def evidence(root, path, identity, reference):
    return dict(artifact_id=identity, artifact_path=path, artifact_sha256=exact_hash(safe_path(root, path)), reference=reference)


def project_elements(canonical, level):
    """Canonical IDs are traced through actual node/edge sources and coverage, never guessed."""
    source = canonical["source_document"]
    if not canonical.get("coverage_ledger") or not canonical.get("provenance_map"):
        raise ValueError("Missing canonical provenance/coverage")
    result = {}
    if level == "typed_graph":
        for node in source["nodes"]:
            result["node:" + node["id"]] = {"nodes:" + node["id"]}
        for edge in source["edges"]:
            result["edge:" + stable_id("edge", edge)] = {"edges:" + serialize(edge).decode()}
        for unresolved in source["unresolved_calls"]:
            result["unresolved:" + stable_id("unresolved", unresolved)] = {"unresolved_calls:" + serialize(unresolved).decode()}
        return result
    for collection, sources_name in (("nodes", "node_sources"), ("edges", "edge_sources"), ("unresolved_calls", "unresolved_sources")):
        for canonical_id, sources in canonical[sources_name].items():
            if canonical_id not in canonical["provenance_map"]:
                raise ValueError("Dangling canonical provenance")
            tokens = {collection + ":" + (item["id"] if collection == "nodes" else serialize(item).decode()) for item in sources}
            if not tokens or any(item not in source[collection] for item in sources):
                raise ValueError("Source not represented by canonical provenance")
            result[canonical_id] = tokens
    # Excluded coverage entries are retained explicitly as source-level unknown elements.
    for entry in canonical["coverage_ledger"]["entries"]:
        if entry["disposition"]["status"] != "represented":
            pointer = entry["source"]
            result["excluded:" + pointer["collection"] + ":" + str(pointer["index"])] = set()
    expected = {item["id"] for collection in ("nodes", "edges") for item in canonical[collection]}
    if not expected <= result.keys():
        raise ValueError("Missing canonical element provenance")
    return result


def match_provenance(left, right):
    """Connected components of intersecting source identities admit all cardinalities."""
    remaining_l, remaining_r = set(left), set(right)
    groups = []
    while remaining_l:
        seed = min(remaining_l)
        group_l, group_r = {seed}, set()
        while True:
            new_r = group_r | {r for r in remaining_r if any(left[item] & right[r] for item in group_l)}
            new_l = group_l | {item for item in remaining_l if any(left[item] & right[r] for r in new_r)}
            if (new_l, new_r) == (group_l, group_r):
                break
            group_l, group_r = new_l, new_r
        remaining_l -= group_l
        remaining_r -= group_r
        groups.append((sorted(group_l), sorted(group_r)))
    groups.extend(([], [r]) for r in sorted(remaining_r))
    return groups


def structural_edge_consistency(left, right, node_map, edge_pairs):
    """Only explicit edge-preservation claims require matching types and mapped endpoints."""
    le, re = {e["id"]: e for e in left}, {e["id"]: e for e in right}
    for a, b in edge_pairs:
        if a not in le or b not in re:
            raise ValueError("Dangling edge correspondence")
        x, y = le[a], re[b]
        if x["type"] != y["type"] or node_map.get(x["source"]) != y["source"] or node_map.get(x["target"]) != y["target"]:
            raise ValueError("Impossible structural edge correspondence")


def derive_mappings(bundle, run_dir, root=ROOT):
    run_dir, root = Path(run_dir).resolve(), Path(root).resolve()
    generated = json.loads((run_dir / "generation.json").read_bytes())
    metadata_ref = (run_dir / "generation.json").relative_to(root).as_posix()
    specs = {s["transformation_id"]: s for s in bundle["specifications"]}
    mappings = []
    for execution in sorted(bundle["executions"], key=lambda x: x["execution_id"]):
        if execution["generation_status"] != "generated":
            continue
        spec, generation = specs[execution["transformation_id"]], generated[execution["execution_id"]]
        source_evidence = [evidence(root, execution["generated_source_path"], execution["execution_id"], "generator declarations and exact compiled-source bytes"), evidence(root, metadata_ref, execution["execution_id"], execution["execution_id"])]
        all_names = [generation["original_function"], *generation["generated_functions"]]
        mappings.append(relation(execution, "source", [spec["source_artifact"] + "#" + spec["source_routine_id"]], [execution["generated_source_path"] + "#" + name for name in all_names], source_evidence, "Deterministic source derivation with recorded transformation parameters"))
        mappings.append(relation(execution, "generated_function", [generation["original_function"]], generation["generated_functions"], source_evidence, "Generator declaration association, without claiming binary survival"))
        for build in sorted((b for b in bundle["builds"] if b["execution_id"] == execution["execution_id"] and b["build_status"] == "success"), key=lambda x: x["build_id"]):
            graphs = [g for g in bundle["graphs"] if g["build_id"] == build["build_id"] and g["extraction_status"] == "success"]
            if len(graphs) != 2:
                raise ValueError("Mapping requires both admitted original/transformed graphs")
            typed_path = graphs[0]["typed_graph_reference"]
            if any(g["typed_graph_reference"] != typed_path or g["binary_sha256"] != build["binary_sha256"] for g in graphs):
                raise ValueError("Incompatible graph/sample identity")
            typed = json.loads(safe_path(root, typed_path).read_bytes())
            symbols_path = str(Path(typed_path).with_name("symbols.json")).replace("\\", "/")
            symbols = json.loads(safe_path(root, symbols_path).read_bytes())
            observed = {}
            for name in all_names:
                candidates = {symbols[k] for k in (name, "_" + name) if k in symbols}
                if len(candidates) == 1:
                    observed[name] = select_anchor(typed, symbols, name)
            ev = source_evidence + [evidence(root, typed_path, build["build_id"], "FUNCTION nodes and calls_function edges"), evidence(root, symbols_path, build["build_id"], "controlled export identities")]
            original = observed.get(generation["original_function"])
            targets = [observed[n] for n in generation["generated_functions"] if n in observed]
            if original and targets:
                mappings.append(relation(execution, "binary_function", [build["build_id"] + "#" + original], [build["build_id"] + "#" + t for t in targets], ev, "Observed controlled function identities associated by source derivation; no structural isomorphism claim"))
            for name in all_names:
                if name not in observed:
                    mappings.append(relation(execution, "binary_function", [execution["execution_id"] + "#expected:" + name], [], ev, "Expected function not uniquely observed; not evidence of optimization", status="unknown", kind="unknown"))
            by_anchor = {g["anchor_identity"]: g for g in graphs}
            original_graph = by_anchor.get(original)
            transformed_graph = by_anchor.get(observed.get(generation["transformed_function"]))
            if original_graph is None or transformed_graph is None or original_graph is transformed_graph:
                raise ValueError("Missing or ambiguous original/transformed anchor provenance")
            left = json.loads(safe_path(root, original_graph["canonical_graph_reference"]).read_bytes())
            right = json.loads(safe_path(root, transformed_graph["canonical_graph_reference"]).read_bytes())
            for graph in (original_graph, transformed_graph):
                ev.append(evidence(root, graph["canonical_graph_reference"], graph["graph_id"], "source_document, provenance_map and coverage_ledger"))
            # Shared raw source edges must preserve endpoint identities; no edge inferred from function names.
            common_edges = [(e, r) for e in left["source_document"]["edges"] for r in right["source_document"]["edges"] if e == r]
            structural_edge_consistency(
                [dict(e, id=str(i)) for i, (e, _) in enumerate(common_edges)],
                [dict(e, id=str(i)) for i, (_, e) in enumerate(common_edges)],
                {n["id"]: n["id"] for n in left["source_document"]["nodes"]},
                [(str(i), str(i)) for i in range(len(common_edges))],
            )
            introduced = {observed[n] for n in generation["generated_functions"] if n in observed}
            for level in ("typed_graph", "canonical_subgraph"):
                le, re = project_elements(left, level), project_elements(right, level)
                for ls, rs in match_provenance(le, re):
                    status, kind = ("verified", None) if ls and rs else ("unknown", "unknown")
                    if not ls and rs and all(re[r] and re[r] <= {"nodes:" + node for node in introduced} for r in rs):
                        status, kind = "unmatched", "unmatched"
                    mappings.append(relation(execution, level, [original_graph["graph_id"] + "#" + n for n in ls], [transformed_graph["graph_id"] + "#" + n for n in rs], ev, "Exact source-identity intersection within the same analyzed PE; additional or unresolved elements retained", status=status, kind=kind))
    return sorted(mappings, key=lambda m: m["mapping_id"])


def validate_mappings(bundle, run_dir, root=ROOT, engine=None):
    verify_builds(bundle, root)
    verify_graphs(bundle, engine or default_engine(root), root)
    expected = derive_mappings(bundle, run_dir, root)
    actual = sorted(bundle["mappings"], key=lambda m: m["mapping_id"])
    if actual != expected:
        raise ValueError("Mapping differs from verified evidence: contradictory, dangling or unsupported correspondence")
    return mapping_statistics(actual)


def mapping_statistics(mappings):
    return dict(
        total_original_elements=len({(m["mapping_level"], r) for m in mappings for r in m["original_element_references"]}),
        total_transformed_elements=len({(m["mapping_level"], r) for m in mappings for r in m["transformed_element_references"]}),
        verified_mappings=sum(m["validation_status"] == "verified" for m in mappings),
        unmatched_elements=sum(len(m["original_element_references"]) + len(m["transformed_element_references"]) for m in mappings if m["mapping_kind"] == "unmatched"),
        unknown_elements=sum(len(m["original_element_references"]) + len(m["transformed_element_references"]) for m in mappings if m["mapping_kind"] == "unknown"),
        ambiguous_mappings=sum(m["mapping_kind"] == "ambiguous" for m in mappings),
        one_to_many_mappings=sum(m["mapping_kind"] == "one_to_many" for m in mappings),
    )


def map_run(run_dir, root=ROOT, engine=None):
    bundle = load_run(run_dir, root)
    if bundle["runs"][0]["statuses"]["extraction"] != "passed":
        raise ValueError("Mapping requires admitted extraction")
    if bundle["mappings"]:
        print("MAPPING EXISTING:", validate_mappings(bundle, run_dir, root, engine), flush=True)
        return bundle
    verify_graphs(bundle, engine or default_engine(root), root)
    bundle["mappings"] = derive_mappings(bundle, run_dir, root)
    stats = validate_mappings(bundle, run_dir, root, engine)
    run = bundle["runs"][0]
    run["mapping_ids"] = [m["mapping_id"] for m in bundle["mappings"]]
    run["statuses"]["mapping"] = "passed"
    result = persist(run_dir, bundle, root)
    print("MAPPING VERIFIED:", stats, flush=True)
    return result
