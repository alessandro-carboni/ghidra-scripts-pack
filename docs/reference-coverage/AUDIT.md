# Final research realignment: microstep 0 audit — 2026-11-11

Fetched origin/codex and inspected current source. Local branch codex, HEAD and origin/codex both ff4e097351d0b64e0f9f03bede98d0d5db7c41fe. Working tree was clean before this task. Starting tracked-byte inventory is starting_inventory.json. Existing portability validator passed: 35 samples, 27 builds, 68 routines, 120 graphs, 218 pairs; exact source/hash and audit/strata determinism intact. Protected checkpoint 291/291 and scientific inventory 161/161 also verified directly.

The user confirmed the supplied attachment's chapters 0–6: microsteps 0 and 1 only. Later library/benchmark microsteps in TODO TESI are outside this increment. The formulas are unambiguous despite broken display delimiters: set intersection divided by reference distinct count; summed minimum counts divided by reference occurrence total. Empty reference => null. No new weights.

## Existing functionality reused

- Rust seed_detection/seed_rules and runtime_subgraph_export: validated automatic observable detection, trigger provenance, local caller/callee extraction and export-local-subgraphs. No new detector.
- canonical.rs and fingerprint.rs/fingerprint_motifs/fingerprint_provenance: frozen normalization, rooted topology, typed evidence, interaction motifs, source coverage and resolved observation support. No new fingerprint definition.
- similarity.rs/similarity_observability/runtime_similarity: source-validated set/multiset Jaccard, mean of comparable views, matched/missing descriptors and observability-qualified absence. No changes to these files.
- scripts/graph_first.py: extract/fingerprint/compare/search; osgf.graph-first/0.1.0, osgf.graph-first-result/0.1.0, osgf.seed-search-index/0.1.0 and osgf.graph-first-ranking/0.1.0. Automatic origins are rebuilt against source; co-observations and operational annotations already exist. Search currently ranks explicit reference files by symmetric graph similarity, without a curated malware-reference library.
- Operational, value-flow, multilevel and semantic-flow research modules remain independently available. No additional operational features are needed.
- Graph-first protocol, amendment chain, six-family source/build manifest and study runner already exist. The quarantined buffer_low_nibble_xor-msvc-O0 executable is still absent, and results.json is absent. This study remains incomplete; do not change its protocol or substitute another sample.

## Missing functionality for chapter 6

Directional coverage and its source-bound value projection do not yet exist. New scripts/reference_coverage.py will wrap the unchanged graph-first validator/comparator, project normalized typed values, and report exact numerator/denominator pairs with per-family and per-view explanations. APIs, strings, constants and locally attached section facts can be read from existing typed descriptors. String-category chains are derived observations and must be separately reported, excluded from the base-observation aggregate. Motifs and seed triggers must not add another vote to value coverage.

The relation-aware view will preserve whole descriptors and counts for each of the existing four graph views. Its overall score remains null: no unjustified sum of correlated views. The primary reference_coverage field will explicitly identify the disjoint base-value collection it measures. This is feature coverage, not a malware verdict or a calibrated behavioral probability.

Expected additive files: scripts/reference_coverage.py, tests/test_reference_coverage.py, docs/reference-coverage/*. Existing graph-first and frozen Rust sources remain unchanged. Only a new script LF attribute and additive CI test invocation may be needed. No malware download, sample execution, antivirus changes, LLM work, commit or push is part of this increment.
