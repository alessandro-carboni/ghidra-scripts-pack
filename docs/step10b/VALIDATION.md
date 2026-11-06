# Step 10B final validation — 2026-11-04

Branch codex, HEAD 66bcc9dda267aac29f7ea79a60ff6727a7340ada. No commit, push, LLM work or freeze modification. Commands below ran from C:\Users\aless\Desktop\ghidra-scripts-pack in PowerShell.

The full regression driver completed all checks. Its one failing check (104 inherited tests in the isolated crate) exposed resource-path resolution, and was corrected without changing historical tests. The final full new-crate run passed 258 tests. Earlier failures are retained in evidence/final-validation-r3.json; actual corrective outcomes are in evidence/final-validation-correction.json.

## Executed commands and outcomes

| Status | PowerShell command | Evidence |
|---|---|---|
| PASS | `python -m pytest -q tests` | 526 passed, 175 subtests passed in 339.10s; before resource-only correction; 48 affected tests rerun afterward |
| PASS | `python -m ruff check .` | Exit 0 |
| PASS | `python -m ruff format --check .` | 100 files already formatted |
| PASS | `cargo fmt --manifest-path rust_engine/Cargo.toml -- --check` | Exit 0 |
| PASS | `cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings` | Exit 0 |
| PASS | `cargo test --locked --manifest-path rust_engine/Cargo.toml` | 252 passed |
| PASS | `cargo fmt --manifest-path rust_engine/operational/Cargo.toml -- --check` | Exit 0 |
| PASS | `cargo test --locked --manifest-path rust_engine/operational/Cargo.toml` | 258 passed; supersedes earlier 104 resource-path failures |
| PASS | `cargo clippy --locked --manifest-path rust_engine/operational/Cargo.toml --all-targets -- -D warnings` | Exit 0 |
| PASS | `go test ./...` | PASS; cached test packages; internal/ai has no tests |
| PASS | `python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | 7 passed |
| PASS | `python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | 11 passed |
| PASS | `python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe` | 20 passed |
| PASS | `python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5` | 25/25 graphs; 75 comparable views; 10 with observability warnings; 25/25 byte-deterministic reruns |
| PASS | `python scripts/dataset_review.py check` | Existing packet/decisions consistency PASS; no human decision changed |
| PASS | `python scripts/validate_dataset_acceptance.py` | 35 samples, 27 builds, 68 routines, 120 graphs, 218 pairs; technical/final acceptance PASS |
| PASS | `python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check` | Leakage check PASS |
| PASS | `python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json` | 161-file inventory and frozen scientific digest PASS |
| PASS | `git diff --check` | Exit 0 |
| PASS | `cargo build --locked --manifest-path rust_engine/operational/Cargo.toml` | Exit 0 |
| PASS | `cargo build --locked --manifest-path rust_engine/Cargo.toml` | Exit 0 |
| PASS | `python -m pytest -q tests/test_operational_pipeline.py tests/test_operational_evaluation.py tests/test_pcode_evidence.py` | 48 passed in 3.40s after resource fix |

The isolated crate reuses legacy modules, so its 258 tests include inherited tests; do not add 252+258 and describe that sum as distinct tests. The new portion includes 14 operational tests and one resource-path regression. Python totals likewise include the 48 focused tests. Cargo emitted incremental-cache hard-link warnings and copied files instead; build/test/Clippy completed successfully, with no lint suppressed for this warning.

## Real experiments and reproducibility

PASS: Ghidra 12.0.4 Raw/High repeated extraction, 36 main corpus + 16 micro + 8 variant observations; full records under evidence/. PASS: independent-family study, 9 builds/27 routines/81 cross-build comparisons, exact A/B structural identity, 27 fingerprint and 81 comparison reruns. See ../../datasets/osgf_baseline_evaluation_v0_2/REPORT.md.

PASS: final resource-corrected executable replays 279 operational outputs byte-identically. Executed command:

```powershell
python scripts/verify_operational_replay.py --engine rust_engine/operational/target/debug/osgf_operational.exe --results datasets/osgf_baseline_evaluation_v0_2/results.json --output datasets/osgf_baseline_evaluation_v0_2/runtime/resource-path-replay-001
```

The full scientific command and environment paths are in the dataset README and individual command receipts. The historical protocol deliberately remains unchanged after the resource correction; the separate packaging/replay record links final code to measured results. Full Ghidra import was NOT RUN again after that resource-only correction.

## Preservation and status boundaries

PASS: exact SHA-256 checks of 291 Step10A checkpoint files and 161 Step9 inventory files. Step8 scientific digest remains 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2. Legacy main.rs, Cargo.toml/Cargo.lock, sources, scientific fixtures and golden digests remain unchanged. The only tracked modification is .github/workflows/ci.yml; implementation, documentation and fixtures are new files. Existing untracked Step10A audit files predate this continuation.

PASS is used only for executed checks. NOT RUN: target PE behavior execution (source algebra/counterexamples justify labels), cross-architecture/cross-OS reproduction, external blinded benchmark, total process-tree memory profiling, and remote GitHub Actions on a pushed commit. Go packages with no tests are not behavioral validation. No test in the full Python run was skipped. The earlier interrupted experiments and failed packaging checks are historical, not final PASS claims. No current mandatory technical test remains blocked by antivirus; protections were not changed.
