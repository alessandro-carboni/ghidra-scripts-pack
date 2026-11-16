import hashlib
import json

import pytest

from scripts.audit_dataset_graph_signal import PROPERTIES, serialize
from scripts.generate_evaluation_strata import generate


def test_strata_predicates_determinism_and_no_mutation():
    graphs = [dict(graph_id=name, split="validation", sha256=name) for name in ("sparse", "rich")]
    pairs = [dict(pair_id=name, left_graph_id=left, right_graph_id=right, split="validation", equivalence_label=label) for name, left, right, label in (("a", "sparse", "sparse", "equivalent"), ("b", "sparse", "rich", "non_equivalent"), ("c", "rich", "rich", "equivalent"))]
    manifest = serialize(dict(graphs=graphs, pairs=pairs))
    records = []
    for graph in graphs:
        rich = graph["graph_id"] == "rich"
        record = dict.fromkeys(PROPERTIES, False)
        record.update(graph_id=graph["graph_id"], split="validation", content_sha256=graph["sha256"], anchor_only=not rich, has_topology=rich, typed_evidence_present=rich, interaction_capable=rich, observability_unknown=not rich, observed_incompleteness=rich)
        records.append(record)
    audit = serialize(dict(manifest_sha256=hashlib.sha256(manifest).hexdigest(), graphs=records))
    before = (manifest, audit)
    result = generate(manifest, audit)
    assert serialize(result) == serialize(generate(manifest, audit))
    assert before == (manifest, audit)
    strata = result["strata"]
    assert strata["all_pairs"] == ["a", "b", "c"]
    assert strata["both_anchor_only"] == ["a"]
    assert strata["at_least_one_non_anchor_signal"] == ["b", "c"]
    for key in ("both_typed_evidence", "both_function_call_topology", "both_interaction_capable"):
        assert strata[key] == ["c"]
    assert strata["either_observability_unknown"] == ["a", "b"]
    assert strata["either_observed_incomplete"] == ["b", "c"]
    assert strata["both_observability_complete"] == []
    assert result["by_equivalence_label"]["non_equivalent"]["all_pairs"] == ["b"]
    assert result["by_split"]["validation"] == strata
    assert all(set(ids) <= {p["pair_id"] for p in pairs} for ids in strata.values())
    with pytest.raises(ValueError):
        generate(manifest + b" ", audit)
    stale = json.loads(audit)
    stale["graphs"][0]["content_sha256"] = "wrong"
    with pytest.raises(ValueError):
        generate(manifest, serialize(stale))
