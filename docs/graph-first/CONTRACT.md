# Opt-in graph-first contracts 0.1.0

The command is `python scripts/graph_first.py`; existing Rust commands and all default CLI behavior are unchanged. No LLM integration is introduced.

## Workflow

```powershell
python scripts/graph_first.py extract path/to/typed-graph.json --engine rust_engine/target/debug/rust_engine.exe --output new-seed-index-directory
python scripts/graph_first.py compare query-seed.json reference-seed.json --engine rust_engine/target/debug/rust_engine.exe --output new-comparison.json
python scripts/graph_first.py search query-seed.json reference-1.json reference-2.json --engine rust_engine/target/debug/rust_engine.exe --output new-ranking.json
```

Input to extract is an existing TypedGraph 0.12.0 from the Ghidra exporter, not a function-name list. All automatically detected seeds are retained. The index preserves the full detector manifest, trigger evidence and original graph. No eligible seed yields an empty, explicitly ineligible index; no research anchor is substituted. Default context is caller depth 1 / callee depth 2; limits are 64 function nodes, 512 evidence nodes, 576 total nodes and 2048 edges. These are technical budgets, not relevance filters. Missing and multiple seeds remain visible.

For isolated contract testing, `fingerprint local.json` accepts an already constructed local context. Such a fingerprint explicitly reports `provided_local_context`, with no manufactured automatic-trigger provenance. It is not evidence of seed recovery.

## Representation and validation

`osgf.graph-first/0.1.0` embeds the frozen canonical document, frozen fingerprint, a co-observation view, semantic digest and optional automatic-seed origin. Input source is reconstructed with the original Rust canonical/fingerprint validators. Automatically detected origins are rerun through the unchanged seed exporter and compared with the exact canonical source. A supplied digest or altered support array is not trusted. Unknown schema or reconstruction differences fail before output writing. Outputs are UTF-8 deterministic JSON, refuse overwriting, and use sorted descriptors/support; paths and source identities are provenance only.

New descriptors address one demonstrated abstraction collision: different evidence co-locations among equal-role functions can preserve all three v0.1 bags. Two observations on the same function and observations on both ends of a directed function call are represented. Evidence types are existing normalized APIs, strings, contextual constants and explicit string-category chains. Descriptors retain anchor-relative roles/distances and direction, never incidental function IDs, addresses, names or register slots. Section/visibility facts remain in the legacy views/support, not new co-observation semantics. Counts are structural motif instances, not products of source occurrence counts. Canonical support IDs resolve through the embedded canonical provenance map and coverage ledger.

Enumeration is limited to 100,000 candidates (overflow fails); at most 4,096 are retained in descriptor/support order. Omissions are explicit. The representation does not collapse wrappers, prove inlining equivalence, infer missing API evidence or reconstruct unobserved computations. It can be sensitive to function boundaries. Generic-topology-only equality remains possible and is identified as weak support.

## Continuous comparison and explanation

`osgf.graph-first-result/0.1.0` contains identities, trigger observations, graph similarities, per-view intersections/unions, matched and one-sided descriptors, count differences, evidence support, legacy comparison with qualified missing evidence, provenance and optional operational evidence. The primary graph scalar is the equal mean of nonempty comparable graph views: the three legacy views and the co-observation ablation. Set and multiset scores are separate. Both-empty view => null; one-sided empty => zero. This experimental aggregation is not a calibrated probability; it has not been promoted as default.

Observability never fabricates a match or changes the represented graph score. Unresolved calls, truncation, coverage and missing observations are disclosed separately. A co-observation missing from one side is an observed descriptor difference, not proof of behavioral absence; consult that side's source coverage and legacy global observability qualifications. Support counts are not confidence. `verified_contradictions` is empty: no independent verifier was implemented. Low operational similarity never sets that field.

`osgf.graph-first-ranking/0.1.0` returns every reference, sorted by graph score descending, nulls last, then explicit reference ID. There is no decision threshold or malware verdict. An ID tie break is deterministic, not semantic evidence; study metrics report tie sensitivity.

## Optional operational analysis

```powershell
python scripts/graph_first.py compare query-seed.json reference-seed.json --engine rust_engine/target/debug/rust_engine.exe --query-operational query-op.json --reference-operational reference-op.json --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --output new-annotated-result.json
```

Both operational inputs must describe the exact structural source/context of the compared regions. Automatic-seed graph metadata must bind the binary SHA to the operational binary SHA. The existing v0.2 Rust comparator validates its source-bearing fingerprints. Its entire result remains separate, with contribution to the graph score zero. Operational-only, fixed combined and top-K refinement are study conditions, not default search behavior. Missing operational evidence is not an incompatibility. The experimental E condition reorders only operationally available slots within graph top5; missing slots keep graph rank. Outside candidates remain inspectable; lost true references are counted. E's numeric ROC/classification score remains B, while its ranking is evaluated separately.

## Historical and security boundaries

No frozen artifact, historical result, schema, label or algorithm is replaced. New code is independently versioned. Any future LLM may propose transformations only; an independent verifier must establish an appropriately bounded guarantee before admission. No LLM scoring, malware verdict or broad equivalence claim is allowed by this contract.

The real study is not yet complete: one newly compiled sample was quarantined before byte hashing. Do not change security settings, silently drop that build, relabel data, or treat technical self-comparisons as a successful independent benchmark. See SCIENTIFIC_COMPARISON.md and IMPLEMENTATION_REPORT.md for actual outcomes.
