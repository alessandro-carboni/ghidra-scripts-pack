# Multilevel High P-code features — 2026-11-09

Implemented on branch `codex`, starting HEAD `402d08ad022456712be24d4e40bdc31efc4b92af`. Additive, opt-in research functionality. No parameter recovery, memory-alias inference, slicing, algebraic rewriting or LLM integration is part of this change.

## Contract

`osgf.multilevel-flow-fingerprint/0.1.0` embeds the original validated OperationalFingerprint once. Three independent levels carry their producer depth, features with occurrence references, path truncation and semantic digest. The full fingerprint also carries copy contractions, retention barriers and a digest of the level digests. Unknown fields and all reconstruction mismatches are rejected.

- `depth_0`: operand-local descriptions; validated produced temporaries carry width but no producer descriptor.
- `depth_1`: each linked temporary additionally carries its producer's depth-zero descriptor digest.
- `depth_2`: one further producer-refinement step, exactly the previous value-flow feature representation.

Depth means predecessor-description propagation, **not** the structural caller/callee radius or maximum feature-path length. Every level retains the same three feature families (operation, directed dependency, bounded two-edge path), structural context, source evidence, copy contraction policy and path budget. Holding these fixed isolates producer-context depth as the experimental variable. Per-family scores are also exposed: the `operation` family at depth zero is the operand-local view. Levels are kept separately; feature multiplicities are not pooled across depths.

The existing `value_flow` builder now has a crate-internal bounded-depth entry point. The public legacy constructor remains depth two with its original schema/digest domain and output shape. The new schema extracts features from that builder and gives each level a distinct, explicitly depth-qualified digest domain. New fingerprints cannot silently masquerade as old value fingerprints.

Constants and widths remain exact. Signedness and ordered operand roles remain explicit. Same-producer input groups remain distinguishable from distinct producer values. Unknown inputs retain the prior conservative storage identity. Proven equal-width temporary COPY chains retain the existing 64-hop bound, cycle barriers and source ledger. No unknown is silently treated as a parameter or an alias.

## Comparison

`osgf.multilevel-flow-similarity/0.1.0` includes the unchanged baseline comparison, separate set/multiset Jaccard scores for each depth and each family, matching-feature counts, completeness, path truncation and provenance ledgers.

Three fixed aggregates are exposed:

1. `mean_01`: equal mean of depths zero and one.
2. `mean_012`: equal mean of all three depths.
3. `exact_mean_012`: equal mean of the original exact operational score and `mean_012` (weights 1/2 exact, 1/6 per depth).

Every specified score must be comparable. Missing scores propagate null; weights are never silently renormalized. Aggregates are complete only if all contributing comparisons are complete. Empty family scores follow existing Jaccard conventions. Unavailable evidence does not become a successful empty match. Source/configuration incompatibilities are rejected by the original comparison. `decision` remains null. Correlated views, repeated patterns and bounded descriptors are not equivalence proofs.

## CLI

```powershell
cargo build --locked --manifest-path rust_engine/operational/Cargo.toml
& rust_engine/operational/target/debug/osgf_operational.exe multilevel-fingerprint operational-fingerprint.json new-multilevel.json
& rust_engine/operational/target/debug/osgf_operational.exe multilevel-compare query-multilevel.json reference-multilevel.json new-comparison.json
python -m pytest -q tests/test_multilevel_flow.py tests/test_value_flow.py
```

All output paths must be new. Existing operational/value commands and default behavior remain. New commands are listed in CLI usage. Scoped Git attributes preserve the exact LF implementation bytes for the edited additive entrypoint/dispatcher and new modules/scripts; no protected source byte protocol changes.

## Tests and evaluation design

Tests independently calculate Jaccard and aggregate values, exercise bounded propagation of an upstream change, compare depth-two features against the legacy builder, verify occurrences and deterministic reruns, and reject forged depths/counts/ledgers/digests, Raw evidence, incompatible environments, unknown-label values and family/split leakage. Existing value-flow tests continue to cover copy cycles and resource limits. Truncated scores cannot claim complete aggregates.

The scientific runner separately registers seven fixed conditions, current implementation/executable hashes, old fingerprint/comparison hashes and unchanged pair labels before execution. Registration cannot overwrite a previous protocol; evaluation requires fresh outputs and checks hashes before and after execution. Repeated multilevel fingerprints/comparisons must match byte-for-byte. Legacy value fingerprints are regenerated and must match the historical bytes; depth-two scores and original baseline comparison objects must also match.

Two existing real-Ghidra corpora are reused (27 routines / 81 pairs each). Both have already informed development. Their historical split names are retained to avoid changing labels or partitions, but **all reported splits, including the ones named heldout, are exploratory evidence**. Thresholds are calibrated only on historical discovery rows, using the unchanged policy. There is no parameter selection or promotion after scores are observed. This run does not claim a new blind test, fresh binary compilation, new Ghidra extraction, target execution or statistical significance. A future independent multi-family benchmark remains necessary before any default promotion.

See FINAL_REPORT.md for actual results, command receipts, limitations and report synchronization.
