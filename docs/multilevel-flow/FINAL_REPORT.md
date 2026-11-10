# Multilevel P-code implementation and evaluation — 2026-11-09

STATUS: implementation and validation complete; optional research view, no default promotion. Branch codex; starting HEAD 402d08ad022456712be24d4e40bdc31efc4b92af. No commit or push.

## Microstep 1 — implementation

Added versioned multilevel fingerprints and comparisons with independent producer depths 0, 1 and 2. Local operand semantics, operation/dependency/path families, structural context, source provenance and conservative COPY rules are held fixed. Per-family scores and per-level completeness/truncation are exposed. Fixed means 0+1, 0+1+2, and exact+mean012 require every constituent score; missing evidence remains null. The original value view stays at depth two. New commands are explicit opt-ins; no Step 5–7 algorithm, default, label, human review decision or frozen artifact was changed.

Tests cover bounded propagation, independent score mathematics, fixed weights, legacy features, source occurrences, signedness, operand order, constants, unknown inputs, same-producer sharing, source incompatibility, unavailable/Raw evidence, path budgets, tampering and family/split leakage. 21 new tests; 42 targeted multilevel/value tests passed in 14.33 s. Full suite below includes all of them. CI's operational job builds the engine and runs the new tests explicitly.

See IMPLEMENTATION.md for schema, exact meaning of depth, limitations and CLI.

## Microstep 2 — real-evidence ablation

Both corpora consist of real previously extracted Ghidra evidence, 27 routines and 81 cross-build pairs each. Seven fixed conditions were registered with exact code, executable, input-fingerprint and historical-comparison hashes before this run. The registration is local and descriptive: both corpora have been observed before, so their historical heldout splits are now development evidence. There is NO new blind heldout claim. Thresholds use only the existing discovery split, with no score-driven changes to code, weights or split assignments.

All 54 multilevel fingerprints and 162 comparisons were run twice with identical bytes. All 54 legacy value fingerprints were regenerated and match their historical bytes. Depth-two set/multiset scores and all 162 original baseline comparison objects match historical results. No target executable was run. Raw evidence and missing runtime inputs fail explicitly.

### value corpus — historical heldout slice, exploratory

| Condition | BA | ROC-AUC | MRR | TP | FP | TN | FN | Tied queries / 9 | Discovery threshold |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| exact | 0.500000 | 0.594444 | 0.888889 | 15 | 12 | 0 | 0 | 3 | 0.019230769230769232 |
| depth_0 | 0.500000 | 0.655556 | 1.000000 | 5 | 4 | 8 | 10 | 3 | 0.12087912087912088 |
| depth_1 | 0.500000 | 0.655556 | 1.000000 | 5 | 4 | 8 | 10 | 5 | 0.036363636363636362 |
| depth_2 | 0.500000 | 0.566667 | 0.722222 | 5 | 4 | 8 | 10 | 9 | 0.017857142857142856 |
| mean_01 | 0.500000 | 0.666667 | 1.000000 | 0 | 0 | 12 | 15 | 3 | 0.2137272494232248 |
| mean_012 | 0.500000 | 0.655556 | 1.000000 | 0 | 0 | 12 | 15 | 3 | 0.16228681314683632 |
| exact_mean_012 | 0.633333 | 0.638889 | 0.944444 | 9 | 4 | 8 | 6 | 3 | 0.043416821127735719 |

### operational corpus — historical heldout slice, exploratory

| Condition | BA | ROC-AUC | MRR | TP | FP | TN | FN | Tied queries / 9 | Discovery threshold |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| exact | 0.500000 | 0.583333 | 0.777778 | 5 | 4 | 8 | 10 | 9 | 0.040816326530612242 |
| depth_0 | 0.633333 | 0.697222 | 0.925926 | 9 | 4 | 8 | 6 | 3 | 0.088888888888888892 |
| depth_1 | 0.500000 | 0.677778 | 1.000000 | 0 | 0 | 12 | 15 | 7 | 1.0000000000000002 |
| depth_2 | 0.500000 | 0.472222 | 0.833333 | 0 | 0 | 12 | 15 | 9 | 1.0000000000000002 |
| mean_01 | 0.633333 | 0.700000 | 0.925926 | 9 | 4 | 8 | 6 | 3 | 0.049444444444444444 |
| mean_012 | 0.633333 | 0.700000 | 0.925926 | 9 | 4 | 8 | 6 | 3 | 0.032962962962962965 |
| exact_mean_012 | 0.500000 | 0.733333 | 1.000000 | 0 | 0 | 12 | 15 | 3 | 0.11239116990669785 |

### Interpretation and limits

On the more recent value corpus, exact_mean_012 raises historical-heldout BA from 0.500000 to 0.633333, AUC from 0.594444 to 0.638889 and MRR from 0.888889 to 0.944444. It avoids eight false positives (12 to 4) but loses six true positives (15 to 9); TPR falls from 1.0 to 0.6. This is a tradeoff, not uniformly improved detection. Depth zero/one improve ranking relative to depth two on this slice, consistent with the hypothesis that more producer context can lose useful matches.

On the older operational corpus, the same exact_mean_012 has AUC 0.733333 and MRR 1.0, but its discovery threshold rejects all 15 historical-heldout positives. BA remains 0.5. The mean_01/mean_012 conditions instead reach BA 0.633333 there, but reject all positives on the recent value slice. We do not choose a different winner per corpus or retune thresholds after seeing this.

Validation partitions also show mixed effects: exact_mean_012 BA is 0.533333 versus exact 0.450000 on the recent corpus; both are 0.500000 on the older corpus. Older-corpus depth_0/mean_01/mean_012 validation BA decreases to 0.475000 with FPR 0.916667. These degradations remain in the result files.

The historical heldout labels name different source families, one family per split; pair observations are correlated. Nine mixed-gallery queries and deterministic case-ID tie-breaking limit MRR interpretation. MRR=1 is not proof of perfect equivalence detection, absence of ties, or threshold generalization. All conditions/splits, Recall@K, nulls and ties are in the result JSONs. No statistical significance or population-superiority claim is made. These are not fresh binaries or new Ghidra extractions. Seed recall, context expansion, wrappers, cross-architecture behavior and general semantic equivalence were not newly validated.

DECISION: deliver the feature as opt-in. The experiment supports testing shallow context further, but does not justify replacing the default, selecting per-corpus conditions, or claiming general improvement. A separately registered, independent multi-family test remains future work. No further proposed improvement (parameters/slicing/algebra/LLM) was implemented.

## Microstep 3 — regression and integrity

- Full Python: **569 passed, 175 subtests passed**, 239.44 s, exit 0.
- Rust original: **252 passed**; isolated operational crate: **258 passed** (inherited overlap; not 510 independent new tests).
- Both Rust format checks and Clippy runs PASS; isolated operational build PASS.
- Ruff check PASS; 107 files formatted correctly.
- Canonical/fingerprint/similarity acceptance suites PASS.
- Real Notepad: **25/25 graphs**, 75 comparable views, 10 graphs with observability warnings, **25/25 deterministic reruns**. This is a legacy regression, not a multilevel efficacy test.
- Historical operational replay: **279/279 byte-identical outputs** (9 bind, 27 local, 27 canonical, 54 fingerprint, 162 compare). Receipt: legacy_replay.json.
- Exact current checkpoint **291/291 unchanged**; Step 9 scientific inventory **161/161 unchanged**; receipt: integrity.json. This statement is relative to starting HEAD, which already contains the preceding documented CI metadata correction.
- All 15 validation-driver commands exit 0. No test failure suppression. Log: .build-cache/multilevel-validation-20261109.log.

One initial shell helper failed to write the CLI usage text; the patch tool applied it and the executable was rebuilt before registration. Cargo's sandbox incremental-cache hard-link warnings used its copy fallback; builds/checks passed. No security setting was changed. Full regressions were authorized outside the sandbox to support the existing clean-Git-checkout tests.

### Actual PowerShell commands

Run from C:\Users\aless\Desktop\ghidra-scripts-pack:

```powershell
cargo build --locked --manifest-path rust_engine/operational/Cargo.toml
python -m pytest -q tests/test_multilevel_flow.py tests/test_value_flow.py
python scripts/evaluate_multilevel_flow.py register --protocol datasets/osgf_multilevel_flow_v0_1/value_corpus_protocol.json --baseline-results datasets/osgf_value_flow_evaluation_v0_1/results.json --legacy-value-dir datasets/osgf_value_flow_evaluation_v0_1/runtime/value-001 --engine rust_engine/operational/target/debug/osgf_operational.exe
python scripts/evaluate_multilevel_flow.py run --protocol datasets/osgf_multilevel_flow_v0_1/value_corpus_protocol.json --output datasets/osgf_multilevel_flow_v0_1/runtime/value-corpus-001
python scripts/evaluate_multilevel_flow.py register --protocol datasets/osgf_multilevel_flow_v0_1/operational_corpus_protocol.json --baseline-results datasets/osgf_baseline_evaluation_v0_2/results.json --legacy-value-dir datasets/osgf_value_flow_evaluation_v0_1/runtime/development-001 --engine rust_engine/operational/target/debug/osgf_operational.exe
python scripts/evaluate_multilevel_flow.py run --protocol datasets/osgf_multilevel_flow_v0_1/operational_corpus_protocol.json --output datasets/osgf_multilevel_flow_v0_1/runtime/operational-corpus-001
python -m pytest -q tests
python -m ruff check .
python -m ruff format --check .
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path rust_engine/operational/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/operational/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/operational/Cargo.toml --all-targets -- -D warnings
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
python scripts/verify_operational_replay.py --engine rust_engine/operational/target/debug/osgf_operational.exe --results datasets/osgf_baseline_evaluation_v0_2/results.json --output .build-cache/multilevel-legacy-replay-20261109
git diff --check
```

Registration and output paths above already exist and intentionally cannot be overwritten. Use new paths for a new run; keep previous records. Exact executable bytes are pinned; a different rebuild requires its own registration. The dataset README explains replay prerequisites. Remote GitHub Actions was not run (no push). No compiled-target behavioral execution, independent benchmark, new formal equivalence proof or fresh Ghidra study was performed.

Results: datasets/osgf_multilevel_flow_v0_1/value_corpus_results.json and operational_corpus_results.json. Code: rust_engine/src/multilevel_flow.rs; shared bounded builder in value_flow.rs; additive dispatcher/entrypoint; scripts/evaluate_multilevel_flow.py. Tests: tests/test_multilevel_flow.py.

DONE TESI synchronization completed on 2026-11-09: appended 3,717 bytes and verified exact preservation of all 242,797 pre-existing bytes. Backup: .build-cache/DONE-TESI-before-multilevel-20261109.md. The note includes all three microsteps, actual test counts, favorable and unfavorable scientific results, and the decision to keep the new view optional.
