# Value-flow normalization — final implementation and scientific report

Date: 2026-11-06. Branch codex; starting HEAD 4aeeed5264ca3b790feba104dc1c0eb6dbc935c8. STATUS: implementation and technical tests PASS; no broad scientific superiority established. New view remains opt-in.

## Microstep: divergence audit

OBJECTIVE: identify storage sensitivity before normalization. STATUS: PASS, development diagnostic only. On the old 27-case/81-pair corpus, removing storage slots raised positive mean similarity from 0.044028 to 0.168582 and negative mean from 0.043159 to 0.146754. This unsafe ablation was not deployed. Observed 536 linked inputs (291 register inputs), 132 unresolved nonconstant inputs and 79 COPY operations among 516 operations. See development_divergence_audit.json.

## Microstep: optional normalized value view

STATUS: PASS. OBJECTIVE: abstract proven SSA definitions while preserving unresolved boundaries, operand direction and source provenance. SOURCE FILES INSPECTED: operational_schema/features/context/similarity/runtime modules, isolated entrypoint, extraction contract, baseline evaluator, compiler helper and existing CLI tests.

FILES CREATED: tests/test_value_flow.py; scripts/evaluate_value_flow.py, run_value_flow_study.py, build_value_flow_corpus.py; new experiment dataset; scoped Git attributes; documentation. FILES MODIFIED: value_flow.rs finalized with cycle/budget ledger and comparison provenance/completeness; dedicated CI job adds new tests. The preliminary value_flow module and CLI dispatch were already in the user's starting commit. No legacy semantic algorithm was edited.

ARCHITECTURAL DECISIONS: new osgf.value-flow-fingerprint/0.1.0 and osgf.value-flow-similarity/0.1.0 envelopes; validated original operational fingerprint embedded, not replaced. Proven register/unique definitions use fixed two-round producer descriptions. Only same-width COPY with recovered input and observed consumer is contracted; memory/stack, casts, unknown leaves, cycles and over-budget chains remain. Ordered operand slots and same-producer groups are preserved. No guessed parameters, aliases, LLM or cross-architecture equivalence. Rules and provenance are documented in IMPLEMENTATION.md.

TEST RESULTS: 21 targeted tests PASS, including relocation, safe/unsafe copies, noncommutative direction, sharing versus distinct values, cycles, copy/path budgets, real signed/unsigned/constants/STORE evidence, determinism, occurrence references, forged values and unavailable/Raw rejection. Initial test-harness import and Raw configuration mistakes were fixed; no production guard or expected scientific result was weakened.

## Microstep: scientific ablation

STATUS: PASS for execution. Algorithm/executable hashes were locked in method_protocol.json before authoring new source families. New corpus: weighted positional sum (discovery), byte population count (validation), saturating accumulation (heldout); 9 GCC O0/O2 and MSVC O0 binaries, 27 routines, 81 cross-build pairs (15 positives/12 negatives per split), 9 mixed-gallery queries per split. Source algebra and 106 deterministic Python input-array checks per family support labels; compiled programs were not executed. Families never cross splits. The old corpus is development-only.

Compared exact operational view, new normalized view, and their fixed equal-weight mean. Each condition calibrates only on discovery using the existing highest-threshold tie policy; no changes after observing scores. All old operational pair scores remain identical. The base real-Ghidra run also verifies structural A/B equality.

### New families: measured results

| View | Split | Balanced accuracy | ROC-AUC | MRR | TPR | FPR | Recall@1 / @3 / @5 | TP / FP / TN / FN |
|---|---|---|---|---|---|---|---|---|
| exact | discovery | 0.583333 | 0.533333 | 0.814815 | 1.000000 | 0.833333 | 0.166667 / 0.527778 / 0.861111 | 15 / 10 / 2 / 0 |
| exact | validation | 0.450000 | 0.477778 | 0.833333 | 0.733333 | 0.833333 | 0.250000 / 0.583333 / 0.833333 | 11 / 10 / 2 / 4 |
| exact | heldout | 0.500000 | 0.594444 | 0.888889 | 1.000000 | 1.000000 | 0.277778 / 0.527778 / 0.888889 | 15 / 12 / 0 / 0 |
| normalized | discovery | 0.633333 | 0.541667 | 0.762963 | 0.600000 | 0.333333 | 0.166667 / 0.500000 / 0.833333 | 9 / 4 / 8 / 6 |
| normalized | validation | 0.566667 | 0.555556 | 0.833333 | 0.466667 | 0.333333 | 0.222222 / 0.527778 / 0.833333 | 7 / 4 / 8 / 8 |
| normalized | heldout | 0.500000 | 0.566667 | 0.722222 | 0.333333 | 0.333333 | 0.194444 / 0.472222 / 0.861111 | 5 / 4 / 8 / 10 |
| mean | discovery | 0.583333 | 0.538889 | 0.814815 | 1.000000 | 0.833333 | 0.166667 / 0.527778 / 0.833333 | 15 / 10 / 2 / 0 |
| mean | validation | 0.533333 | 0.511111 | 0.833333 | 0.733333 | 0.666667 | 0.250000 / 0.527778 / 0.833333 | 11 / 8 / 4 / 4 |
| mean | heldout | 0.516667 | 0.605556 | 0.888889 | 0.866667 | 0.833333 | 0.277778 / 0.527778 / 0.888889 | 13 / 10 / 2 / 2 |

Discovery thresholds: exact=0.019230769230769232; normalized=0.017857142857142856; mean=0.014517345399698341.

Heldout interpretation: the mean reduces false positives from 12 to 10 but also true positives from 15 to 13. Balanced accuracy rises only 0.016667 and ROC-AUC 0.011111; MRR does not improve. Normalized-only heldout MRR falls from 0.888889 to 0.722222 and ROC-AUC from 0.594444 to 0.566667. The mixed outcome does not justify replacing the exact view or claiming a large improvement. The lower FPR of normalized-only comes with lower TPR, not free discrimination.

Heldout ties: exact 3/9 queries, normalized 9/9, mean 3/9; case-ID ascending tie resolution. These small, correlated samples do not establish statistical significance. Recall is relevant-item recall, not hit rate. The mean combines two operational scores, not a replacement of the original structural three-view aggregation.

### Development-only old corpus

| View | Old heldout balanced accuracy | ROC-AUC | MRR |
|---|---|---|---|
| exact | 0.500000 | 0.583333 | 0.777778 |
| normalized | 0.500000 | 0.472222 | 0.833333 |
| mean | 0.500000 | 0.605556 | 0.944444 |

Old-corpus mean MRR increases to 0.944444, but that does not reproduce as an MRR gain on the newly authored heldout family. The new evaluation prevents treating a favorable development result as established general improvement. No post-hoc parameter search was performed.

### Observability and determinism

New normalized feature cardinality: 49–89. Contracted copies across 27 routines: 7. Copy-cycle/hop barriers on these routines: 0. All new pair scores comparable; no negative pair scored exactly 1 in these three conditions. The absence of exact collisions is not low false-positive rate at the selected thresholds.

Both development and new-family value runs repeat 27 normalized fingerprints and 81 comparisons byte-for-byte. Fresh real Ghidra outputs also feed repeated exact fingerprints/comparisons. All 279 operational stage outputs from the historical Step10B study replay identically with the new executable. Semantic equivalence is not inferred from determinism.

## Regression, compatibility and commands

STATUS: PASS. Full Python run: 545 passed and 175 subtests passed in 258.22s. Two additional resource-bound tests were subsequently added; the complete targeted file then passed 21 tests. Thus the current test inventory includes two more tests than the full-run count; no false claim of a fresh 547-test full run. Rust original 252 passed, isolated crate 258 passed (includes inherited tests, not 258 new tests). Go tests passed, some cached. Ruff check/format, Rust formatting/Clippy, legacy 7/11/20 acceptance suites, 25/25 Notepad graphs with deterministic repeats, review/acceptance/leakage/preflight and git diff --check passed.

Operational build PASS before protocol lock. Compilation initially hit WinError 623 in the restricted environment; authorized execution outside it compiled all nine targets successfully. No security configuration was changed. Cargo incremental hard-link warnings fell back to copying; commands exited successfully.

| Status | Full PowerShell command |
|---|---|
| PASS | `python -m pytest -q tests` |
| PASS | `python -m ruff check .` |
| PASS | `python -m ruff format --check .` |
| PASS | `cargo fmt --manifest-path rust_engine/Cargo.toml -- --check` |
| PASS | `cargo test --locked --manifest-path rust_engine/Cargo.toml` |
| PASS | `cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings` |
| PASS | `cargo fmt --manifest-path rust_engine/operational/Cargo.toml -- --check` |
| PASS | `cargo test --locked --manifest-path rust_engine/operational/Cargo.toml` |
| PASS | `cargo clippy --locked --manifest-path rust_engine/operational/Cargo.toml --all-targets -- -D warnings` |
| PASS | `go test ./...` |
| PASS | `python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe` |
| PASS | `python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe` |
| PASS | `python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe` |
| PASS | `python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5` |
| PASS | `python scripts/dataset_review.py check` |
| PASS | `python scripts/validate_dataset_acceptance.py` |
| PASS | `python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check` |
| PASS | `python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json` |
| PASS | `git diff --check` |
| PASS | `cargo build --locked --manifest-path rust_engine/operational/Cargo.toml` |
| PASS | `python -m pytest -q tests/test_value_flow.py` |
| PASS | `python scripts/build_value_flow_corpus.py --study-dir datasets/osgf_value_flow_evaluation_v0_1` |
| PASS | `python scripts/evaluate_value_flow.py --protocol datasets/osgf_value_flow_evaluation_v0_1/development_protocol.json --baseline-results datasets/osgf_baseline_evaluation_v0_2/results.json --engine rust_engine/operational/target/debug/osgf_operational.exe --output datasets/osgf_value_flow_evaluation_v0_1/runtime/development-001` |
| PASS | `python scripts/verify_operational_replay.py --engine rust_engine/operational/target/debug/osgf_operational.exe --results datasets/osgf_baseline_evaluation_v0_2/results.json --output .build-cache/value-flow-legacy-replay-20261106` |

Full new-family command:

```powershell
python scripts/run_value_flow_study.py --study-dir datasets/osgf_value_flow_evaluation_v0_1 --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot' --work datasets/osgf_value_flow_evaluation_v0_1/runtime/fresh-001
```

Scripts reject overwritten outputs, changed registered code/binary/source hashes and source-family leakage. The new normalization is never substituted silently for a legacy view. Dataset source bytes and additive implementation files have scoped LF checkout rules; original frozen rules remain unchanged.

## Integrity and remaining limits

PASS: 291/291 Step10A checkpoint and 161/161 Step9 scientific file hashes unchanged. Step8 scientific digest remains 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2. Existing golden outputs, labels, splits and review decisions are untouched. No commit, push or LLM implementation.

NOT RUN: remote GitHub Actions (no push), compiled-target behavioral execution, cross-architecture validation, external blinded benchmark, formal whole-function equivalence proof. This is a three-family investigator-authored pilot with one family per split and explicit depth-zero anchors; it does not establish seed-recall or wrapper/splitting invariance. Memory readings from the underlying runner remain direct-child only; performance was not optimized or used to select this method.

Architectural hypothesis: exact bounded producer colors can amplify upstream compiler differences, explaining why invariance on controlled renaming tests does not guarantee improved cross-compiler matching. This is not isolated causal proof. Unknown parameter/register boundaries and memory semantics remain conservative. Further ablations must be separate registered experiments, not retuning this heldout.

NEXT: implementation is delivered as an opt-in research view. Preserve the exact view as default; no promotion based on these mixed results.
