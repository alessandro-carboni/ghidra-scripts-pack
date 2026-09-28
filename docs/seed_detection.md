# Observable seed detection (through Step 3.11)

The Rust seed stage describes observed triggers; it does not produce a score,
priority, maliciousness confidence, capability or verdict.

## Entry points and contracts

- `seed_detection::detect_seed_candidates(graph, rules)` combines all six
  detectors into ordered, deduplicated atomic candidates.
- `seed_detection::detect_seeds(graph, rules, config)` returns a validated
  `SeedDetectionResult`, with one consolidated seed per function anchor.
- `detect_seeds_from_report(report, rules, config)` requires `report.typed_graph`.
- `SeedDetectionConfig` and `SeedDetectionResult` live in `seed_limits.rs`;
  candidate, evidence, family and consolidated seed types live in `schema.rs`.

Versions: Typed Evidence Graph **0.12.0**, Seed Rules **0.4.0**, Seed Model **0.4.0**.
The CLI's final fingerprinting output remains the existing placeholder. Wiring the
complete Seeded runtime is a later roadmap step; no CLI flags are added here.
The typed graph version loader/validator is also reserved for Step 4.1.

## Ordering and identity

Candidates sort lexicographically by anchor ID, trigger ID, then their canonically
sorted evidence. Evidence sort by callsite, node ID, kind, value and edge type.
Missing optional fields sort first. Addresses remain unchanged, not numerically
normalized. Remaining candidate fields break full ties deterministically.
Consolidated seeds sort by anchor, with the same evidence ordering. Family order
follows the declared enum vocabulary, never risk or importance.

Atomic IDs are `seed:<anchor>:<trigger>`; consolidated IDs are `seed:<anchor>`.
Repeated observations do not change these IDs.

Evidence identity uses structured fields, not delimiter-concatenated strings.
Exact duplicate evidence is removed, while different callsites, node IDs, edge
types, kinds or values remain separate. Candidates with the same anchor, trigger
and reason union their evidence. Different explanations remain separate atomic
variants (sharing the trigger-level ID) until consolidation collects their reasons.
Contradictory families for one anchor/trigger identity are rejected. No raw-graph
provenance is invented; deduplication preserves all fields in the seed contract.

## Technical limits

Configuration example: `{"max_seeds": 100}`. Missing/null means unlimited;
zero returns no seeds while still computing the exact total.

Limits apply **after** detection, deduplication, consolidation and ordering. They
bound returned seeds and downstream work, not initial graph scanning or peak
detection memory. No evidence cap is imposed: returned seeds retain all evidence.

The result includes `config`, `model_version`, `seeds`, `total_detected`,
`returned`, `truncated` and `truncation_reason`. Counts refer to unique consolidated
anchors. The reason is `"max_seeds"` only when seeds were omitted, otherwise null.
Reaching the exact limit without omitting a seed is not truncation. Zero matches
with a zero limit is likewise complete. Unknown config fields, including
`minimum_priority`, and negative/noninteger limits are rejected.

Use `SeedDetectionResult::validate()` after deserializing an external result to
check version, metadata consistency, canonical order and unique evidence/anchors.

## Regression coverage

The synthetic mixed graph in `rust_engine/tests/fixtures/seed_detection.json`
exercises all six detector paths against the bundled rules, without malware samples
or Ghidra installation. `seed_detection_tests.rs` covers standalone trigger types,
empty results, mixed anchors, provenance, duplication, graph/rule permutations,
stable IDs, truncation, invalid input and isolation from legacy scores.

Run the full Rust suite with `cargo test --manifest-path rust_engine/Cargo.toml`.
Focused seed-stage integration tests use the filter `seed_detection_tests::`.
