# Graph-first realignment implementation log — 2026-11-10

## MICROSTEP: A / Phase 1
STATUS: Implemented; scientific validation pending

OBJECTIVE: Read-only architecture audit

CURRENT IMPLEMENTATION: Existing observable-seed detector, context export, canonicalization and baseline fingerprint/similarity can be reused unchanged. Specific lost co-location relationships identified; topology-only collisions cannot be repaired by inventing evidence.

ARCHITECTURAL DECISION: Additive opt-in only; no default promotion. LLM remains future independently verified research.

SOURCE FILES INSPECTED: See ARCHITECTURE_AUDIT.md.

FILES CREATED: docs/graph-first/ARCHITECTURE_AUDIT.md

FILES MODIFIED: scripts/.gitattributes (new script LF rules only).

CONTRACT CHANGES: New osgf.graph-first/0.1.0 family; no old schema changes.

LEGACY COMPATIBILITY: No historical algorithm, label, fixture or protocol changed.

TESTS EXECUTED: Inspected graph, seed, canonical, fingerprint, similarity and operational modules, historical audit and latest semantic report. HEAD matched reviewed revision; clean checkout.

SCIENTIFIC RESULTS: No new heldout result yet.

KNOWN LIMITATIONS: Co-observations can be function-boundary sensitive; low or high descriptor agreement is not a behavior proof.

NEXT MICROSTEP: B / graph-first core.

## MICROSTEP: B / Phase 2
STATUS: Implemented; scientific validation pending

OBJECTIVE: Add separately versioned graph-first representation

CURRENT IMPLEMENTATION: Added bounded same-function and directed-call co-observations. Three frozen graph views preserved, separately inspectable. Canonical and fingerprint inputs reconstructed through original Rust validators.

ARCHITECTURAL DECISION: Additive opt-in only; no default promotion. LLM remains future independently verified research.

SOURCE FILES INSPECTED: See ARCHITECTURE_AUDIT.md.

FILES CREATED: scripts/graph_first.py; tests/test_graph_first.py

FILES MODIFIED: scripts/.gitattributes (new script LF rules only).

CONTRACT CHANGES: New osgf.graph-first/0.1.0 family; no old schema changes.

LEGACY COMPATIBILITY: No historical algorithm, label, fixture or protocol changed.

TESTS EXECUTED: 9 targeted tests passed (1.43 s): specificity, permutation/relocation, budgets, topology-only emptiness, source tampering, automatic/missing seeds, operational source mismatch, ROC/tie/candidate rules.

SCIENTIFIC RESULTS: No new heldout result yet.

KNOWN LIMITATIONS: Co-observations can be function-boundary sensitive; low or high descriptor agreement is not a behavior proof.

NEXT MICROSTEP: C / seed-to-reference workflow.

## MICROSTEP: C / Phase 3
STATUS: Implemented; scientific validation pending

OBJECTIVE: Restore automatic seed-to-subgraph retrieval

CURRENT IMPLEMENTATION: New extract and search opt-in commands wrap original exporter. All seeds retained; no injected research anchor. Trigger observations and complete graph provenance retained and revalidated. Exhaustive graph ranking, explicit zero-seed result, deterministic tie order.

ARCHITECTURAL DECISION: Additive opt-in only; no default promotion. LLM remains future independently verified research.

SOURCE FILES INSPECTED: See ARCHITECTURE_AUDIT.md.

FILES CREATED: scripts/graph_first.py

FILES MODIFIED: scripts/.gitattributes (new script LF rules only).

CONTRACT CHANGES: New osgf.graph-first/0.1.0 family; no old schema changes.

LEGACY COMPATIBILITY: No historical algorithm, label, fixture or protocol changed.

TESTS EXECUTED: Synthetic real-engine automatic detection returned 2 expected anchors; no-seed probe returned an explicit ineligible index. No real-binary coverage claim yet.

SCIENTIFIC RESULTS: No new heldout result yet.

KNOWN LIMITATIONS: Co-observations can be function-boundary sensitive; low or high descriptor agreement is not a behavior proof.

NEXT MICROSTEP: D / optional operational evidence.

## MICROSTEP: D-F / Phases 4-5
STATUS: Implemented; scientific validation pending

OBJECTIVE: Separate graph score, optional P-code and explanations

CURRENT IMPLEMENTATION: Existing operational-only comparator exposed with exact structural-context binding. Graph score is unchanged by operational evidence. No heuristic contradiction flag. Explainable versioned results include matched/differing descriptors, coverage, truncation, seed observations and source provenance.

ARCHITECTURAL DECISION: Additive opt-in only; no default promotion. LLM remains future independently verified research.

SOURCE FILES INSPECTED: See ARCHITECTURE_AUDIT.md.

FILES CREATED: scripts/graph_first.py; scripts/graph_first_evaluation.py

FILES MODIFIED: scripts/.gitattributes (new script LF rules only).

CONTRACT CHANGES: New osgf.graph-first/0.1.0 family; no old schema changes.

LEGACY COMPATIBILITY: No historical algorithm, label, fixture or protocol changed.

TESTS EXECUTED: Source-mismatch rejection passed. Retrieval tests verify missing operational evidence retains graph slots and a candidate excluded from top5 remains excluded from refinement. Real complementary contribution remains pending.

SCIENTIFIC RESULTS: No new heldout result yet.

KNOWN LIMITATIONS: Co-observations can be function-boundary sensitive; low or high descriptor agreement is not a behavior proof.

NEXT MICROSTEP: H / independent prospective evaluation.

## MICROSTEP: H / Phase 6 registration
STATUS: Implemented; scientific validation pending

OBJECTIVE: Register conditions before fresh evaluation

CURRENT IMPLEMENTATION: A frozen baseline; B graph-first; C unchanged operational; D fixed half-mean with explicit missing fallback; E graph-top5 available-slot reranking. New buffer-family sources authored after registration, separate source-family partitions.

ARCHITECTURAL DECISION: Additive opt-in only; no default promotion. LLM remains future independently verified research.

SOURCE FILES INSPECTED: See ARCHITECTURE_AUDIT.md.

FILES CREATED: scripts/run_graph_first_study.py; scripts/create_graph_first_study.py; datasets/osgf_graph_first_v0_1/*

FILES MODIFIED: scripts/.gitattributes (new script LF rules only).

CONTRACT CHANGES: New osgf.graph-first/0.1.0 family; no old schema changes.

LEGACY COMPATIBILITY: No historical algorithm, label, fixture or protocol changed.

TESTS EXECUTED: Method registered as 6a4fc4b9636f74625e906c1bc48dbfc65ced06a63aa715d376b0f56d2c2daa6d. Nine tests and Ruff passed. Compilation first failed with sandbox WinError 623; authorized retry in progress. Full Python suite in progress.

SCIENTIFIC RESULTS: No new heldout result yet.

KNOWN LIMITATIONS: Co-observations can be function-boundary sensitive; low or high descriptor agreement is not a behavior proof.

NEXT MICROSTEP: Complete builds/extraction/evaluation, regressions, scientific report.
