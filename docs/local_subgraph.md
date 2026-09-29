Local seed context through Step 4.13
This stage loads the Typed Evidence Graph, validates seed provenance, selects a
bounded deterministic neighborhood around each seed, preserves its observable
evidence, records truncation explicitly, optionally groups closely related seed
contexts and exposes a versioned JSON contract suitable for later pipeline stages
and the Graph Explorer GUI.
The stage performs no malware scoring, ranking, capability reconstruction or
verdicting.
Rust entry points
1. graph::TypedGraph::from_report(&report) loads report.typed_graph.
2. graph_indexes::GraphIndexes::new(&graph) builds reusable immutable indexes.
3. seed_validation::validate_seed_candidate and validate_consolidated_seed
   verify seed provenance against the graph.
4. local_subgraph::extract_local_subgraph(&indexes, &seed, &config) extracts
   one bounded local context.
5. related_seed_grouping::group_related_seeds(&seeds, &subgraphs) optionally
   groups strongly related contexts without a score.
6. local_subgraph_schema::LocalSubgraphDocument::from_local(&local) converts
   the internal extraction result to the explicit versioned JSON contract.
Versions
- Typed Evidence Graph: 0.12.0.
- Seed Rules: 0.4.0.
- Seed Model: 0.4.0.
- Local Subgraph Schema: 0.1.0.
The legacy CLI fingerprinting field remains on its planned placeholder until the
later runtime-integration step. Step 4.12 makes the local-subgraph data itself
serializable and stable; it does not silently change the existing enrichment
runtime contract.
Typed graph and indexes
The Rust graph loader preserves:
- model version;
- metadata;
- typed nodes;
- typed edges;
- unresolved-call records.
It validates graph version, unique node IDs, endpoint existence/types, provenance
aliases, visibility ownership and unresolved-call invariants.
GraphIndexes provides deterministic access to:
- node ID;
- node type;
- outgoing edges;
- incoming edges;
- FUNCTION -> evidence;
- FUNCTION -> API;
- FUNCTION -> callers;
- FUNCTION -> callees.
String categories are associated with a function only through an actual
FUNCTION -> references_string -> STRING -> has_string_category -> STRING_CATEGORY
path.
Seed provenance validation
Before local extraction, a consolidated seed must point to an existing FUNCTION.
Its evidence must match the observable graph relation, node value and callsite
when those fields apply.
Unresolved-call evidence must match an actual unresolved record. No target node or
edge is fabricated.
Caller and callee traversal
Default configuration:
{
  "caller_depth": 1,
  "callee_depth": 2,
  "max_function_nodes": null,
  "max_evidence_nodes": null,
  "max_total_nodes": null,
  "max_edges": null
}
Caller and callee traversals are independent deterministic BFS traversals starting
at the seed anchor. Only resolved calls_function relations are traversed.
Unresolved calls never become neighbors.
The anchor has distance zero. Sorted neighbors and visited sets make cycles,
self-loops, duplicate call edges and input permutations deterministic.
Evidence inclusion
Every retained function contributes linked evidence nodes:
- API;
- STRING;
- STRING_CATEGORY;
- CONSTANT;
- SECTION;
- VISIBILITY_INDICATOR.
Evidence does not consume caller/callee hop depth. Evidence that did not trigger a
seed is still retained when it belongs to a selected function.
A shared evidence node never pulls an unselected function into the local context.
Unresolved and indirect evidence
Local subgraphs preserve unresolved-call records whose caller belongs to the
selected function set. The original callsite, reason and exporter attributes are
retained.
callee remains absent for unresolved records. No synthetic target is created.
Indirect-call and explicitly recognized dynamic-dispatch information remains in
the original VISIBILITY_INDICATOR node properties. Dynamic-dispatch metadata does
not automatically create functions, APIs, call edges or BFS expansions.
An ordinary indirect call is not promoted to dynamic dispatch unless that signal
was already explicitly recognized upstream.
Local graph resource limits
LocalExtractionConfig supports four optional technical limits:
- max_function_nodes;
- max_evidence_nodes;
- max_total_nodes;
- max_edges.
Missing or null values are unlimited and preserve the behavior from the earlier
steps.
max_function_nodes = 0 and max_total_nodes = 0 are rejected because the anchor
must always remain representable. max_evidence_nodes = 0 and max_edges = 0 are
valid technical configurations.
Function retention uses only:
1. minimum BFS distance from the anchor;
2. function ID as a deterministic tie-break.
Evidence retention uses the deterministic order of retained functions and evidence
IDs. Edge retention uses canonical edge order.
No malware score, seed priority, family weight, confidence, risk or capability
weight participates in retention.
Truncation metadata
Every LocalSubgraph contains LocalTruncationMetadata.
It records:
- truncated;
- limits_reached with the configured limit value;
- requested caller/callee depth;
- effective caller/callee depth represented in the retained context;
- returned function/evidence/total node counts;
- returned edge count;
- unresolved-call count;
- reason = resource_limit when truncation occurred.
A configured limit is reported only when it actually omits otherwise eligible
content. Merely configuring a limit does not mark a complete graph as truncated.
The metadata is internally validated against the extraction configuration and
returned graph counts.
Related-seed grouping
Step 3.6 already consolidates all trigger candidates on the same anchor into one
ConsolidatedSeed. Therefore valid Step 4 input cannot contain two distinct
consolidated seeds with the same anchor; duplicate same-anchor consolidated seeds
are rejected rather than re-grouped.
For different anchors, Step 4.11 uses a deliberately conservative boolean rule:
seeds are grouped only when:
1. one selected FUNCTION context fully contains the other; and
2. the seeds have descriptively correlated evidence.
Evidence correlation can come from a shared descriptive trigger family, shared
trigger ID or shared semantic evidence identity.
Full containment is used instead of a hand-tuned percentage overlap threshold.
There is no similarity score, maliciousness score, priority or weighted grouping
formula.
Grouping is deterministic and permutation-invariant. Only groups containing at
least two seeds are emitted.
Local subgraph JSON schema
LocalSubgraphDocument is the explicit Step 4.12 contract.
Schema version: 0.1.0.
Fields:
schema_version
seed_id
anchor_function_id
graph_version
extraction_config
function_selection
nodes
edges
unresolved_calls
truncation
The contract therefore contains all fields required by the roadmap:
- seed ID;
- anchor;
- source graph version;
- nodes;
- edges;
- unresolved calls;
- truncation metadata;
- extraction configuration.
function_selection is intentionally included as additional GUI/debug provenance
so the frontend can distinguish selected functions and inspect caller/callee
minimum distances without reconstructing analysis logic.
LocalSubgraphDocument::validate() checks:
- schema and graph versions;
- seed/anchor consistency;
- extraction config;
- truncation metadata;
- selected FUNCTION membership;
- caller/callee distance bounds;
- deterministic unique node ordering;
- deterministic unique edge ordering;
- edge endpoints;
- unresolved-call locality and lack of fake targets;
- count consistency.
to_json_pretty() and from_json() provide a stable serialization boundary for
later runtime integration and the Graph Explorer GUI.
Step 4.13 acceptance coverage
The dedicated local_subgraph_tests.rs acceptance suite covers the complete local
subgraph stage, including:
- depth 0;
- caller traversal;
- callee traversal;
- cycles;
- self-loops;
- evidence inclusion;
- unresolved evidence;
- duplicate avoidance;
- deterministic traversal and stable JSON;
- function/evidence/total-node/edge limits;
- truncation metadata;
- invalid seed anchors;
- GUI-consumable schema fields.
Module-level tests additionally cover graph loading, indexes, provenance,
dynamic-dispatch preservation, grouping behavior, schema validation and legacy
regressions.
GUI boundary after Step 4.13
After Step 4.13, the backend local-subgraph representation is ready for GUI
consumption:
ConsolidatedSeed
      |
      v
LocalSubgraph extraction
      |
      +-- selected FUNCTIONs
      +-- evidence nodes
      +-- resolved edges
      +-- unresolved calls
      +-- truncation metadata
      |
      v
LocalSubgraphDocument 0.1.0
      |
      v
Graph Explorer GUI
The GUI should visualize this contract; it must not duplicate BFS, grouping,
truncation or analysis decisions in frontend code.