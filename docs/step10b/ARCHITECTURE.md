# Step 10B.0 — architecture and source audit

Date: 2026-11-03. Branch codex, HEAD 66bcc9dda267aac29f7ea79a60ff6727a7340ada. Existing uncommitted Step 10A diagnostics are user work and are preserved. No production changes are required by the authorized research-only chapters 1–4.

## Current contracts and integration map

| Component | Responsibility and input → output | Proposed additive integration | Compatibility risk / modification |
|---|---|---|---|
| ghidra_scripts/export_report.py main | Ghidra program → legacy raw report schema 1.2.0; seeded graph builder → model 0.12.0 | Separate opt-in P-code exporter/module using the same program and function mapping | Keep existing entrypoint, serialization and default behavior unchanged; no new fields silently added |
| ghidra_scripts/export_research_graph.py | Program → typed graph plus symbol identity map and binary SHA | Reuse identity conventions in a separate research export command | Existing research exporter unchanged |
| ghidra_scripts/typed_graph_model.py; rust_engine/src/graph.rs | Typed graph validation, node/edge types, unresolved records | Separate operational evidence sidecar with strict admission | Do not overload arbitrary legacy properties as new scientific semantics |
| graph_indexes.rs; seed_detection.rs and seed_* modules | Validated graph → observed seeds with limits/deduplication | Future optional attachment by verified function identity | No new seed selection rule in this phase; selection bias must remain explicit |
| local_subgraph.rs; local_subgraph_schema.rs | Seeds/indexes → LocalSubgraphDocument 0.1.0 with selection and truncation | Attach operational evidence only for selected observed functions in a future version | Preserve caller/callee depth, budgets and old CLI output |
| canonical.rs; canonical_order.rs | Local 0.1.0 → CanonicalSubgraph 0.1.0, coverage and source references | New versioned operational canonicalizer, separate from v0.1 | High risk if editing existing facts/order/digest; leave unchanged |
| fingerprint.rs; fingerprint_motifs.rs; fingerprint_provenance.rs | Verified canonical → fingerprint 0.1.0 and sidecar | Future independently versioned operational view and source supports | No additions to frozen feature sets, counts or digests |
| similarity.rs; similarity_observability.rs | Verified fingerprints and sidecars → SimilarityResult 0.1.0 | Future explicit version dispatch; compatibility rejection rather than mixing views | Preserve Jaccard, comparable views, warning semantics and aggregation |
| main.rs; runtime_* modules | CLI dispatch; scientific commands separate from legacy enrichment | New explicit command once extraction contract is designed | Existing commands/defaults unchanged |
| scripts/evaluation_*.py; dataset validators | Frozen labeled inputs → pinned evaluations and acceptance | Separate v0.2 development dataset/protocol later | No regeneration of frozen labels/splits/results |
| tests; rust_engine/tests/fixtures | Golden digests, provenance, permutation and CLI regression | New research API checks now; operational tests after contract design | Existing golden bytes unchanged |

Function identities originate from observed entry addresses (fn: prefix); callsites retain observed addresses. These are provenance bindings, not portable semantic identifiers. Keep binary SHA, function identity, address space and instruction origin together; never join different binaries merely by an address or canonical digest. Research symbols identify controlled functions but do not establish equivalence. Local source documents, canonical source maps/coverage ledger and fingerprint sidecars already provide the model for traceability.

The exporter reads instructions/references but does not export routine CFG/P-code semantics. Its selected API-context constants do not represent all arithmetic constants. The audit's 39 negative collisions are therefore motivation for new evidence, not justification to change weights. Existing three semantic views and separate observability remain intact. The previous fresh micro.exe experiment remains incomplete; this research step neither executes it nor changes antivirus settings.

## Proposed architecture and boundaries

Use a small extraction module and separate research entrypoint, initially opt-in. First collect and inspect raw operations with explicit instruction provenance; define the operational schema only in Step 10B.2. A later Rust loader validates a distinct versioned input before any new canonical/fingerprint logic is enabled. Do not assign a numeric production schema now: existing graph is 0.12.0 while local/canonical/fingerprint/similarity are 0.1.0, so version fields must remain independent.

No existing component needs editing for 10B.0–10B.1. The future additive path is authorized in principle; any incompatible change to the existing scientific format needs human approval. No LLM, dataset relabeling, evaluation retuning, commit or push.

## Verification

Read repository contracts and Step 10A reports/catalogs, inspected actual exporter/schema/CLI/feature modules and source mapping. Checkpoint SHA-256 verification: 291/291 unchanged. API source verification for 10B.1 is recorded separately. Documentation-only work does not claim a running extractor or improved similarity.
