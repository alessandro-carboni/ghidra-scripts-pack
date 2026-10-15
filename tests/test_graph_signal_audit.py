import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.audit_dataset_graph_signal import audit, graph_signal, serialize, write_output


def graph(topology=False, api=False, owner="N0"):
    nodes = [dict(id="N0", kind="FUNCTION", facts={"role": "ANCHOR"})]
    edges = []
    if topology:
        nodes.append(dict(id="N1", kind="FUNCTION", facts={"role": "CALLEE"}))
        edges.append(dict(id="E0", kind="calls_function", source="N0", target="N1"))
    if api:
        nodes.append(dict(id="A", kind="API", facts={}))
        edges.append(dict(id="EA", kind="calls_api", source=owner, target="A"))
    return dict(nodes=nodes, edges=edges, unresolved_calls=[], local_graph_truncation=dict(truncated=False, requested_depth={"callee_depth": 3}, effective_depth={"callee_depth": 0}))


class GraphSignalTests(unittest.TestCase):
    def test_anchor_only_and_unknown_visibility(self):
        result = graph_signal(graph())
        self.assertTrue(result["anchor_only"])
        self.assertTrue(result["degraded_observability"])
        self.assertEqual(len(result["unknown_observation_fields"]), 3)

    def test_topology_only(self):
        result = graph_signal(graph(topology=True))
        self.assertTrue(result["topology_only"])
        self.assertFalse(result["interaction_capable"])
        self.assertEqual(result["non_anchor_function_node_count"], 1)

    def test_api_and_connected_interaction(self):
        result = graph_signal(graph(api=True))
        self.assertEqual(result["evidence_types_present"], ["API"])
        self.assertFalse(result["interaction_capable"])
        self.assertTrue(graph_signal(graph(topology=True, api=True, owner="N1"))["interaction_capable"])
        self.assertFalse(graph_signal(graph(topology=True, api=True))["interaction_capable"])

    def test_unresolved_truncated_and_known_visibility(self):
        document = graph()
        document["nodes"].append(dict(id="V", kind="VISIBILITY_INDICATOR", facts=dict(indirect_calls=2, unresolved_indirect_calls=0, explicit_dynamic_dispatch=1)))
        document["edges"].append(dict(id="EV", kind="contains_indirect_call", source="N0", target="V"))
        self.assertFalse(graph_signal(document)["degraded_observability"])
        document["unresolved_calls"] = [dict(id="U", caller="N0", facts=dict(occurrences=3))]
        document["local_graph_truncation"]["truncated"] = True
        result = graph_signal(document)
        self.assertTrue(result["degraded_observability"])
        self.assertEqual(result["unresolved_call_occurrences"], 3)

    def test_category_chain_requires_explicit_edges(self):
        document = graph(topology=True)
        document["nodes"] += [dict(id="S", kind="STRING", facts={}), dict(id="C", kind="STRING_CATEGORY", facts={})]
        document["edges"] += [dict(id="ES", kind="references_string", source="N1", target="S"), dict(id="EC", kind="has_string_category", source="S", target="C")]
        self.assertEqual(graph_signal(document)["category_chain_count"], 1)
        self.assertEqual(graph_signal(document)["interaction_support_count"], 2)
        document["edges"].pop()
        self.assertEqual(graph_signal(document)["category_chain_count"], 0)

    def test_deterministic_and_no_mutation(self):
        document = graph(topology=True, api=True, owner="N1")
        original = copy.deepcopy(document)
        graph_signal(document)
        self.assertEqual(document, original)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "graph.json"
            path.write_text(json.dumps(document))
            manifest = root / "manifest.json"
            record = dict(graph_id="g", split="validation", path=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            pair = dict(pair_id="p", left_graph_id="g", right_graph_id="g", split="validation", equivalence_label="equivalent", pair_category="test", transformation_family="none")
            manifest.write_text(json.dumps(dict(graphs=[record], pairs=[pair])))
            before = {p: p.read_bytes() for p in root.iterdir()}
            first, protected = audit(manifest, root)
            second, _ = audit(manifest, root)
            self.assertEqual(serialize(first), serialize(second))
            output = root / "audit.json"
            write_output(first, output, protected)
            original_output = output.read_bytes()
            write_output(second, output, protected)
            self.assertEqual(original_output, output.read_bytes())
            self.assertEqual(first["pair_statistics"]["equivalence_label"]["equivalent"]["both_typed_evidence"], 1)
            for source, contents in before.items():
                self.assertEqual(source.read_bytes(), contents)
                with self.assertRaises(ValueError):
                    write_output(first, source, protected)
