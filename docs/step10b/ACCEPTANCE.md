# Step 10B acceptance — 2026-11-04

Implementation and the requested controlled evaluation are complete. This accepts a deterministic research baseline, not a proven equivalence classifier or a claim of general superiority. Read [VALIDATION.md](VALIDATION.md) and the [scientific report](../../datasets/osgf_baseline_evaluation_v0_2/REPORT.md) together with this checklist.

| Requirement | Status | Evidence and boundary |
|---|---|---|
| 1. Real reproducible extraction | PASS | Real Ghidra Raw/High, independent fresh imports/settings and exact repeated bytes; recorded environment only |
| 2. Versioned validated schema | PASS | Standalone P-code 0.1.0; operational envelopes/canonical/fingerprint/similarity 0.2.0; strict Python/Rust validation |
| 3. Preserved provenance | PASS | Binary hash, function/sequence origin, original operations, occurrence-level feature supports; forged outputs rejected |
| 4. No invented targets/behavior | PASS | Unsupported/unavailable states explicit; no guessed aliases, indirect targets or full ABI/behavior recovery |
| 5. Controlled operational differences | PASS | Real constants 32/33, signed/unsigned predicates and memory/bitwise operations; same-opcode different-dataflow regressions |
| 6. Selected equivalent transformations checked | PASS with limits | Source algebra establishes selected equivalences; real sum-index/pointer and wrapper/thunk/splitting evidence inspected; comparisons quantify substantial sensitivity. Not a guarantee of similarity 1 or executable equivalence proof |
| 7. Complete v0.1 compatibility | PASS | Original entrypoint/manifest/lock and shared semantic sources unchanged, 252 Rust tests and 7/11/20 acceptance tests, exact A/B identity |
| 8. Deterministic new fingerprints | PASS | Collection permutations, repeated 27 real fingerprints and 81 pair comparisons; final engine reproduces all 279 operational stage outputs |
| 9. Similarity mathematics | PASS | Set/multiset Jaccard, count/empty/large-total cases, comparable-view mean; no learned weight or adopted classifier |
| 10. Incomplete evidence handling | PASS | Missing, unavailable, partial, cancelled, timeout, budget exclusion and path truncation qualified; support never treated as probability |
| 11. Existing regressions | PASS after correction | 526 Python + 175 subtests, 252 original Rust, 258 isolated-crate tests, Go, lint/format/Clippy/build, Notepad smoke, review/leakage/preflight; see exact chronology in VALIDATION.md |
| 12. Independent scientific evaluation | PASS for small pilot | New source families created after algorithm lock; split by source family, mixed galleries and discovery-only thresholds; no external blind evaluation or broad superiority established |
| 13. Documentation | PASS | Model, extraction, graph/context, rule/feature tables, CLI, measured scientific report, command/status receipts and cumulative progress |
| 14. Freeze preservation | PASS | 291 checkpoint and 161 scientific inventory exact hashes, Step8 digest and golden files unchanged |

Demonstrated bugs corrected: unsafe erasure of operand storage roles in noncommutative descriptors, changes to protected entrypoint/manifest during early packaging, and inherited resource lookup relative to the nested crate. Original assertions and protected hashes were preserved. Final packaging imports shared modules by path, with a lexical resource-root adapter in the new entrypoint and a dedicated regression.

Architectural limits: compiler/storage sensitivity, bounded local dependency patterns, incomplete alias/control dependence and no cross-architecture normalization. Scientific hypotheses: richer evidence may improve discrimination, but the measured heldout balanced accuracy remains 0.50; the observed MRR improvement is a small-pilot result with pervasive ties. Proposed future work: larger independent evaluation and verified normalization experiments. These are not implemented or declared successful here.

No LLM implementation, human review decision, old freeze, commit or push was introduced. No antivirus setting was modified. Target programs were compiled and statically analyzed, never executed.
