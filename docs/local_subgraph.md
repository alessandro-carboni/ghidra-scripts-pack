# Local seed context through Step 4.7

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

## Current boundary and verification

`FunctionSelection` and `LocalSubgraph` are internal Rust results, not the final
versioned export contract. Separate unresolved-call record attachment belongs to
Step 4.8; graph limits/truncation to 4.9–4.10; the export schema to 4.12. Existing
visibility-node properties are already preserved intact. Final CLI fingerprinting
still uses its planned placeholder until the later runtime integration step.

Steps 4.1–4.7 add 36 tests covering malformed/versioned graphs, indexes, provenance,
directional BFS, minimum distances, cycles, depth boundaries, evidence inclusion,
parallel edges and deterministic permutations. Full regression at this milestone:
156 Rust tests and 57 Python tests, plus Clippy, Go test/vet, Ruff and formatting.
