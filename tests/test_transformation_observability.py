"""Structural counterexamples: identical symbols/reachability do not prove topology."""

import copy

import pytest

from scripts.transformation_extraction import observe
from scripts.transformation_families import default_parameters, generate
from scripts.transformation_schema import serialize


def example(family, count=1, delegation=None):
    parameters = default_parameters(family)
    count_key = {"transparent_wrapper": "wrapper_depth", "thunk": "thunk_depth", "function_splitting": "split_count", "harmless_strand": "number_of_strands"}.get(family)
    if count_key:
        parameters[count_key] = count
    if delegation:
        parameters["delegation"] = delegation
    contract = dict(kind="pure_bytes", min_length=0, max_length=255, trailing_nul=True, result_bits=32, preconditions=[])
    generated = generate(dict(routine_id="sum_array"), family, parameters, 9, contract)
    names = [generated["original_function"], *generated["generated_functions"]]
    symbols = {name: f"fn:{index}" for index, name in enumerate(names)}
    original, target = names[0], generated["transformed_function"]
    if family in ("transparent_wrapper", "thunk"):
        pairs = [(names[i], names[i - 1]) for i in range(1, len(names))]
    elif family == "function_splitting":
        pairs = [(target, helper) for helper in names[1:-1]] + [(helper, original) for helper in names[1:-1]]
    elif family == "harmless_strand":
        pairs = [(target, helper) for helper in names[:-1]]
    else:
        pairs = [(target, original)]
    edges = [dict(type="calls_function", source=symbols[a], target=symbols[b], direct=True, indirect=False, unresolved=False) for a, b in pairs]
    doc = dict(nodes=[dict(id=value, type="FUNCTION") for value in symbols.values()], edges=edges, unresolved_calls=[], metadata=dict(scope="complete_seeded_evidence_graph", truncated=False))
    return doc, symbols, generated, family, [], parameters


@pytest.mark.parametrize("family,count", [(f, n) for f in ("transparent_wrapper", "thunk", "function_splitting", "harmless_strand") for n in (2, 3, 8)])
def test_declared_topologies(family, count):
    args = example(family, count)
    assert observe(*args)["status"] == "observed"
    before = copy.deepcopy(args)
    shuffled = copy.deepcopy(args)
    shuffled[0]["nodes"].reverse()
    shuffled[0]["edges"].reverse()
    assert serialize(observe(*args)) == serialize(observe(*shuffled))
    assert args == before


@pytest.mark.parametrize("family", ["transparent_wrapper", "thunk", "function_splitting", "harmless_strand"])
@pytest.mark.parametrize("attack", ["missing_edge", "wrong_topology", "missing_symbol", "unresolved", "truncated"])
def test_no_false_observation(family, attack):
    args = example(family, 3)
    doc, symbols, generated, *_ = args
    if attack == "missing_edge":
        doc["edges"].pop(1)
    elif attack == "wrong_topology":
        # Every helper remains reachable; the required caller/callee pairs do not.
        target = symbols[generated["transformed_function"]]
        for edge in doc["edges"]:
            edge["source"] = target
    elif attack == "missing_symbol":
        del symbols[generated["generated_functions"][0]]
    elif attack == "unresolved":
        doc["unresolved_calls"] = [dict(caller=symbols[generated["transformed_function"]], callee=None, indirect=True, unresolved=True)]
        doc["edges"].pop()
    else:
        doc["metadata"]["truncated"] = True
    # A star is the expected strand topology: introduce a wrong helper caller instead.
    if family == "harmless_strand" and attack == "wrong_topology":
        doc["edges"][0]["source"] = symbols[generated["generated_functions"][1]]
    assert observe(*args)["status"] == "partially_observed"


def test_extra_unrelated_edges_do_not_hide_or_invalidate_required_topology():
    args = example("transparent_wrapper", 3)
    args[0]["edges"].append(dict(type="calls_function", source="unrelated", target="other", direct=True, indirect=False, unresolved=False))
    assert observe(*args)["status"] == "observed"
    args[0]["edges"].pop(1)
    assert observe(*args)["status"] == "partially_observed"


@pytest.mark.parametrize("delegation", ["direct", "fixed_pointer"])
def test_resolved_indirect_thunk_and_unknown_target(delegation):
    args = example("thunk", 2, delegation)
    for edge in args[0]["edges"]:
        edge.update(direct=False, indirect=True)
    assert observe(*args)["status"] == "observed"
    args[0]["edges"][0].update(target=None, unresolved=True)
    assert observe(*args)["status"] == "partially_observed"
    args[1].clear()
    assert observe(*args)["status"] == "unknown"


@pytest.mark.parametrize("family", ["dead_branch", "instruction_reordering"])
def test_outside_graph_vocabulary(family):
    args = example(family)
    args[0]["edges"].clear()
    args[1].clear()
    assert observe(*args)["status"] == "not_observable"


def test_ambiguous_symbols_and_merged_helpers_do_not_prove_chain():
    args = example("transparent_wrapper", 2)
    target = args[2]["transformed_function"]
    args[1]["_" + target] = "fn:other"
    assert observe(*args)["status"] == "unknown"


@pytest.fixture
def aggregation_bundle(tmp_path):
    from scripts.transformation_extraction import exact_hash

    bundle = dict(
        runs=[dict(run_id="synthetic", artifact_hashes={}, statuses={p: "passed" for p in ("generation", "build", "extraction", "mapping", "validation")}, experiment_configuration={})],
        specifications=[],
        executions=[],
        builds=[],
        graphs=[],
        behaviors=[],
        mappings=[],
        frozen_dataset_reference={"scientific_digest": "synthetic"},
    )

    def add(family, index, execution=None):
        args = example(family, 2)
        doc, symbols, generated, _, _, params = args
        eid, bid = execution or f"e{index}", f"b{index}"
        specid = "s" + eid
        run_dir = tmp_path / f"run-{index}"
        folder = run_dir / "extraction" / bid
        folder.mkdir(parents=True)
        doc.update(model_version="0.12.0")
        doc["metadata"].update(research_binary_sha256="a" * 64, node_count=len(doc["nodes"]), edge_count=len(doc["edges"]))
        for path, value in ((folder / "typed.json", doc), (folder / "symbols.json", symbols), (run_dir / "generation.json", {eid: generated})):
            path.write_bytes(serialize(value))
            bundle["runs"][0]["artifact_hashes"][path.relative_to(tmp_path).as_posix()] = exact_hash(path)
        if not any(e["execution_id"] == eid for e in bundle["executions"]):
            bundle["executions"].append(dict(execution_id=eid, transformation_id=specid, generation_status="generated"))
            bundle["specifications"].append(dict(transformation_id=specid, transformation_family=family, parameters=params))
        bundle["builds"].append(dict(build_id=bid, execution_id=eid, build_status="success", binary_sha256="a" * 64))
        evidence = [
            dict(artifact_id=bid, artifact_path=(folder / "typed.json").relative_to(tmp_path).as_posix(), artifact_sha256=exact_hash(folder / "typed.json"), reference="nodes and calls_function edges"),
            dict(artifact_id=bid, artifact_path=(folder / "symbols.json").relative_to(tmp_path).as_posix(), artifact_sha256=exact_hash(folder / "symbols.json"), reference="controlled PE export identities"),
        ]
        for role in ("original", "transformed"):
            bundle["graphs"].append(
                dict(
                    graph_id=bid + role,
                    execution_id=eid,
                    build_id=bid,
                    binary_sha256="a" * 64,
                    typed_graph_reference=evidence[0]["artifact_path"],
                    typed_graph_sha256=evidence[0]["artifact_sha256"],
                    anchor_identity=symbols[generated[role + "_function"]],
                    extraction_status="success",
                    observability_metadata=observe(doc, symbols, generated, family, evidence, params),
                    truncation_metadata={},
                    diagnostics=[],
                )
            )
        return bundle

    return bundle, add


def test_build_level_counts_and_deterministic_reports(aggregation_bundle, tmp_path):
    from scripts.transformation_extraction import transformation_observations, OBSERVATION_CONTRACT
    from scripts.transformation_report import compose_report, markdown

    bundle, add = aggregation_bundle
    families = ("transparent_wrapper", "thunk", "function_splitting", "harmless_strand", "dead_branch", "instruction_reordering")
    for i, family in enumerate(families):
        add(family, i)
        assert len(transformation_observations(bundle, tmp_path)) == i + 1
    report = compose_report(bundle, root=tmp_path)
    assert len(report["transformation_observations"]) == 6
    assert report["canonical_graph_count"] == 12
    assert sum(sum(row["observed_effects"].values()) for row in report["families"].values()) == 6
    assert report["observation_contract"] == OBSERVATION_CONTRACT
    bundle["graphs"].reverse()
    # Report graph rows also need deterministic order, not just aggregated counts.
    rerun = compose_report(bundle, root=tmp_path)
    assert serialize(report) == serialize(rerun)
    assert markdown(report) == markdown(rerun)
    add("transparent_wrapper", 6, execution="e0")
    observations = transformation_observations(bundle, tmp_path)
    assert len(observations) == 7
    assert len({o["observation_id"] for o in observations}) == 7


@pytest.mark.parametrize("attack", ["duplicate", "role", "contradictory", "missing", "incomplete", "wrong_build", "hash"])
def test_invalid_or_incomplete_graph_pairs(aggregation_bundle, tmp_path, attack):
    from scripts.transformation_extraction import transformation_observations

    bundle, add = aggregation_bundle
    add("transparent_wrapper", 0)
    if attack == "duplicate":
        bundle["graphs"].append(copy.deepcopy(bundle["graphs"][0]))
    elif attack == "role":
        bundle["graphs"][1]["anchor_identity"] = bundle["graphs"][0]["anchor_identity"]
    elif attack == "contradictory":
        bundle["graphs"][1]["observability_metadata"]["status"] = "unknown"
    elif attack == "missing":
        bundle["graphs"].pop()
    elif attack == "incomplete":
        bundle["graphs"][1]["extraction_status"] = "timeout"
    elif attack == "wrong_build":
        bundle["graphs"][1]["execution_id"] = "other"
    else:
        bundle["graphs"][1]["typed_graph_sha256"] = "b" * 64
    if attack in ("missing", "incomplete"):
        observations = transformation_observations(bundle, tmp_path)
        assert len(observations) == 1
        assert observations[0]["observation"]["status"] == "unknown"
        assert not observations[0]["complete_graph_pair"]
    else:
        with pytest.raises(ValueError):
            transformation_observations(bundle, tmp_path)


def test_legacy_reachability_claim_is_revalidated_not_reused(aggregation_bundle, tmp_path):
    import json
    from scripts.transformation_extraction import transformation_observations, legacy_observe, exact_hash

    bundle, add = aggregation_bundle
    add("transparent_wrapper", 0)
    graph = bundle["graphs"][0]
    path = tmp_path / graph["typed_graph_reference"]
    doc = json.loads(path.read_bytes())
    symbols_path = path.with_name("symbols.json")
    symbols = json.loads(symbols_path.read_bytes())
    generated = json.loads((path.parents[2] / "generation.json").read_bytes())["e0"]
    # Star keeps every function reachable, while destroying the intermediate delegation.
    for edge in doc["edges"]:
        edge["source"] = symbols[generated["transformed_function"]]
    path.write_bytes(serialize(doc))
    bundle["runs"][0]["artifact_hashes"][graph["typed_graph_reference"]] = exact_hash(path)
    for record in bundle["graphs"]:
        record["typed_graph_sha256"] = exact_hash(path)
        evidence = copy.deepcopy(record["observability_metadata"]["evidence"])
        evidence[0]["artifact_sha256"] = exact_hash(path)
        record["observability_metadata"] = legacy_observe(doc, symbols, generated, "transparent_wrapper", evidence)
        assert record["observability_metadata"]["status"] == "observed"
    before = copy.deepcopy(bundle)
    assert transformation_observations(bundle, tmp_path)[0]["observation"]["status"] == "partially_observed"
    assert bundle == before
