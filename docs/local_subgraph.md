# Local seed context through Step 4.9

This stage loads the Typed Evidence Graph, validates seed provenance, selects
nearby functions and attaches their observed evidence. It performs no scoring,
ranking or capability reconstruction.

## Rust entry points

1. `graph::TypedGraph::from_report(&report)` loads `report.typed_graph`.
   `from_value`, `from_json` and `load` support standalone graphs. The file loader
   expects a graph object, not a complete report.
2. `graph_indexes::GraphIndexes::new(&graph)` builds reusable borrowed indexes.
3. `seed_validation::validate_seed_candidate` and `validate_consolidated_seed`
   check a seed against those indexes.
4. `local_subgraph::extract_local_subgraph(&indexes, &seed, &config)` validates
   the consolidated seed, selects functions and returns the local context.

`TypedGraph` requires model version **0.12.0**. Its topology uses the seven node
types and seven edge types emitted by the Python exporter. Metadata and other
attributes are retained in JSON property maps. Loading checks duplicate IDs,
endpoint existence/types, provenance aliases, visibility ownership and unresolved
call records. Deserialization also validates the graph; storage is externally
immutable, so indexes cannot become stale through graph mutation.

The generic `Report` representation, Seed Model **0.4.0** and Seed Rules **0.4.0**
remain unchanged. The loader validates topology and version, rather than replacing
all exporter-specific payload validators. Seed validation verifies the payloads
and relationships needed by its evidence.

## Indexes and provenance

Indexes cover node ID/type, incoming/outgoing edges, function evidence/API targets
and caller/callee neighbors. Neighbors are unique and sorted. Parallel edges keep
their separate attributes. Function evidence includes string categories via actual
`references_string` followed by `has_string_category` relationships.

A seed anchor must be an existing FUNCTION. Evidence must match node type, value,
relationship and callsite for that anchor. Category evidence needs the two-edge
string path. Unresolved evidence must match a real caller/callsite/reason record;
no target is invented. This checks provenance, not a malware verdict or a rerun of
the seed rule classification.

## Caller and callee traversal

Configuration:

```json
{"caller_depth": 1, "callee_depth": 2}
```

Missing fields use these defaults. Zero disables traversal in that direction.
Negative/noninteger depths and unknown config fields are rejected.

Both breadth-first traversals start from the anchor, whose distance is zero.
Only resolved `calls_function` edges are followed. Caller traversal follows
incoming edges; callee traversal follows outgoing edges. Explicitly resolved
indirect targets are ordinary known function edges. Unresolved calls cannot add
a function neighbor.

The two traversals are independent. Caller-to-callee or callee-to-caller direction
changes do not automatically pull in siblings or other callers. Their union is
the selected function set, with separate minimum-distance maps. FIFO traversal,
sorted neighbors and visited sets handle cycles, self-loops and repeated edges
deterministically.

## Evidence inclusion

Every selected function contributes all linked APIs, strings, string categories,
constants, sections and visibility indicators, even when they did not trigger a
seed. Evidence does not consume function-hop depth. Depth zero therefore includes
the anchor and all its own evidence.

The local result retains original node/edge properties and all edges whose
endpoints are included. Nodes sort by ID; edges sort by source, relation, target
and canonical JSON properties. Identical edge records are deduplicated; parallel
records with different callsites or occurrence attributes remain distinct. A
shared evidence node never causes another function to enter the function set.


## Unresolved and indirect evidence

Local subgraphs preserve unresolved-call records whose caller belongs to the
selected function set. These records retain their original callsite, reason and
exporter attributes and never create a synthetic target.

Indirect-call and explicitly recognized dynamic-dispatch information remains in
the original VISIBILITY_INDICATOR nodes. Dynamic-dispatch metadata does not
implicitly add functions or edges to the selected topology.

## Local graph resource limits

`LocalExtractionConfig` supports four optional technical limits:

- `max_function_nodes`;
- `max_evidence_nodes`;
- `max_total_nodes`;
- `max_edges`.

Missing or null limits are unlimited and preserve the previous behavior.

The anchor FUNCTION is always retained. Function selection is deterministic:
minimum BFS distance is used first and node ID resolves equal-distance ties.
Evidence is taken from retained functions in deterministic locality order.

`max_total_nodes` limits FUNCTION plus evidence nodes. `max_edges` is applied
to the canonical deterministic edge order.

The limits are resource controls only. They do not use malware scores, seed
priority, trigger family importance, capability weights or verdicts.

Unresolved-call records remain separate from the four node/edge limits defined
for Step 4.9.


## Current boundary and verification

`FunctionSelection` and `LocalSubgraph` remain internal Rust results, not the
final versioned local-subgraph export contract.

Step 4.9 introduces deterministic technical graph limits. The explicit
truncation contract belongs to Step 4.10 and will record whether a limit was
reached, requested/effective depth, node/edge counts and the truncation reason.

The export schema remains reserved for Step 4.12. Final CLI fingerprinting still
uses its planned placeholder until the later runtime integration step.