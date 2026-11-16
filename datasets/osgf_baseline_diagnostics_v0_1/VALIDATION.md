# Step 10A validation — post-reboot regression checks passed; fresh micro-extraction incomplete

Current checkpoint: branch codex; HEAD 66bcc9dda267aac29f7ea79a60ff6727a7340ada.

## Historical pre-reboot execution on 2026-10-28

Working directory for all PowerShell commands: C:\Users\aless\Desktop\ghidra-scripts-pack.

| Command | Exit | Result |
|---|---:|---|
| `python -m ruff check .` | 0 | PASS |
| `python -m ruff format --check .` | 0 | PASS |
| `python -m pytest -q tests` | 0 | PASS |
| `cargo fmt --manifest-path rust_engine/Cargo.toml -- --check` | 0 | PASS |
| `cargo test --locked --manifest-path rust_engine/Cargo.toml` | 0 | PASS |
| `cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings` | 0 | PASS |
| `cargo build --locked --manifest-path rust_engine/Cargo.toml` | 0 | PASS |
| `python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | 1 | FAIL — process launch denied (WinError 5); scientific assertion not reached |
| `python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | 1 | FAIL — process launch denied (WinError 5); scientific assertion not reached |
| `python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | 1 | FAIL — process launch denied (WinError 5); scientific assertion not reached |
| `python scripts/dataset_review.py check` | 0 | PASS |
| `python scripts/validate_dataset_acceptance.py` | 0 | PASS |
| `python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check` | 0 | PASS |
| `python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5` | 1 | FAIL — process launch denied (WinError 5); scientific assertion not reached |
| `python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json` | 0 | PASS |
| `git diff --check` | 0 | PASS |

Python: 398 passed, 65 skipped, 175 subtests passed. Missing audit-only test source is not included in this run. Rust: 252 passed. Ruff: 87 files checked. Skipped tests are not passes. Full current-run log: `.build-cache/step10a-regressions.log`; structured exit codes: `.build-cache/step10a-regressions-results.json`.

Protected preservation inventory: all 291 SHA-256 values match CHECKPOINT.json. Step 9 preflight independently reports 161 protected files and the unchanged Step 8 scientific digest 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2. No existing tracked file changed.

## Earlier executions within this audit (2026-10-27), not rerun today

`python scripts/evaluation_acceptance.py`: PASS; complete reconstruction and second fresh replay, no freeze written. Log `.build-cache/step10a-reproduction.log`.

`python scripts/diagnose_baseline_core.py`: 436 pair-condition records checked; five output files replayed byte-identically. `python -m pytest -q tests/test_diagnose_baseline_core.py`: 13 passed. These new source files are currently absent following the antivirus incident and must be restored and revalidated before claiming reproducible audit completion.

Nine graph-level experiments and six Step 9 supplementary comparisons completed. Their JSON files and `.build-cache/step10a-experiments.log` remain available. Fresh real-binary/Ghidra experiment: INCOMPLETE; no MICRO_REAL_EXPERIMENTS.json exists. Do not infer any successful fresh Ghidra result.

## Blocking event

User screenshots identify Bitdefender Advanced Threat Defense, SuspiciousBehavior.5CD2DB91D13F33A, at 2026-10-27 16:52:38, showing python.exe launching micro.exe. Bitdefender reports all involved applications blocked and requires reboot to finish cleanup. Audit source restoration fails with Access denied; production CLI launch from Python also fails. This is an environment blocker, not evidence of a scientific assertion failure. No protection disabled, no exclusion added, no blocked executable renamed or relaunched to evade protection.

After reboot: inspect detection/quarantine and source code, recover the three audit-only source/test files, rerun focused tests and deterministic diagnostic generation, then decide with the user how to handle the controlled real-binary probe. Rerun all denied acceptance commands. Complete case studies, per-operation attribution, information-loss map, root-cause matrix, remediation plan and final report. Audit remains BLOCKED/INCOMPLETE.

## Final post-reboot execution — 2026-10-28

The reboot resolved the execution restriction. The three audit sources/tests were recovered and the missing research adapter rebuilt from pinned approved sources. Strict catalog admission accepted the resulting executable identity. No antivirus exception or security-setting change was made. The earlier failures above are retained as history, not current scientific failures.

PowerShell orchestration: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .build-cache/step10a-post-reboot-regressions.ps1`. Full log and structured results use the same basename with `.log` and `-results.json`.

| Command | Final outcome |
|---|---|
| `python -m ruff check .` | PASS after fixing an unused import and ambiguous test variable names; initial FAIL retained in log, explicit rerun exited 0 |
| `python -m ruff format --check .` | PASS |
| `python -m pytest -q tests` | PASS |
| `cargo fmt --manifest-path rust_engine/Cargo.toml -- --check` | PASS |
| `cargo test --locked --manifest-path rust_engine/Cargo.toml` | PASS |
| `cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings` | PASS |
| `cargo build --locked --manifest-path rust_engine/Cargo.toml` | PASS |
| `python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | PASS |
| `python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | PASS |
| `python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | PASS |
| `python scripts/dataset_review.py check` | PASS |
| `python scripts/validate_dataset_acceptance.py` | PASS |
| `python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check` | PASS |
| `python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5` | PASS |
| `python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json` | PASS |
| `git diff --check` | PASS |

Python full suite: **478 passed, 175 subtests passed**, no skips reported after recovery. Rust: **252 passed**. Canonical acceptance: 7 tests; fingerprint acceptance: 11; similarity acceptance: 20. Notepad smoke: **25/25 passed**, 75 comparable views, 10 graphs with warnings, 25/25 byte-deterministic reruns.

Additional final commands:

- `python scripts/evaluation_adapter.py --build`: PASS, exact source-bound adapter reconstructed.
- `python scripts/diagnose_baseline_core.py`: PASS; 436 records, both aggregates, exact five-file replay.
- `python scripts/diagnose_baseline_experiments.py --graph --step9`: PASS; nine graph probes, six real existing Step 9 comparisons, exact output replay.
- `python scripts/diagnose_baseline_report.py`: PASS; 13 case studies, six root entries, zero descriptor/hash collisions, 27 independently recomputed source witnesses, per-evidence-type normalization attribution. Repeated execution preserves diagnostic JSON and case-study bytes.
- `python -m pytest -q tests/test_diagnose_baseline_core.py`: PASS, 15 tests on final diagnostic contracts.
- `python -m ruff check .`: PASS on corrected sources.
- `python -m ruff format --check .`: PASS, 91 files.
- `git diff --check`: PASS.

All 291 preservation hashes were rechecked after the work with zero mismatches. Existing tracked source, labels, splits, goldens and freezes are unchanged; only new audit files are present. The full suite also exercises existing forged/missing-provenance rejection tests in test_evaluation_adapter.py; these are actual current-run passes, not an assertion that hashes alone prove provenance.

Fresh real-binary/Ghidra micro-extraction: **NOT COMPLETED / NOT RERUN**, because micro.exe triggered the recorded antivirus event. The diagnostic CLI explicitly refuses that branch pending human review. The original source and command design remain inspectable; no fresh output is fabricated or admitted. Existing real graph cases and source-level witnesses are substitutes only for the stated diagnostic questions, not evidence of a completed fresh binary experiment.

The corpus-level audit and roadmap are delivered for human review. Any requirement for a fresh micro-extraction remains blocked pending an approved execution environment or resolution of the detection. Do not mark that experiment PASS or claim unconditional 100% completion. No v0.2/Step11, commit, push or freeze was performed.
