# Reference-library implementation and validation

Date: 2026-11-12. Starting/rechecked HEAD: `ff4e097351d0b64e0f9f03bede98d0d5db7c41fe`, branch `codex`. No commit or push.

## Implemented integration

The new opt-in library supports registration, validation, listing, inspection, source-bound search and independent all-seed workflows. Every comparison exposes directional coverage and the original symmetric scores separately. Stable content-addressed entries preserve provenance; duplicates, malformed schemas, altered bytes and unsupported representations are explicitly rejected or reported unavailable. Frozen representation adaptation is explicit and transient. No family-derived functional labels, probability claims, new P-code normalization or LLM functionality were introduced.

The versioned benchmark reuses existing metrics, calibration, graph-first search and operational refinement. It pins input/implementation hashes before scoring, rejects declared split leakage and incomplete galleries, retains missingness, reports seed eligibility separately and refuses empty datasets. The benign static-only runner exercises real compiler outputs, Ghidra extraction and the complete library workflow, including same-API hard negatives, GCC optimization, GCC→MSVC, interprocedural relocation and deliberately absent seeds.

Contracts: `osgf.reference-library/0.1.0`, `osgf.reference-entry/0.1.0`, explicit `osgf.frozen-reference/0.1.0` adapter wrapper, `osgf.library-ranking/0.1.0`, `osgf.reference-workflow/0.1.0`, `osgf.reference-benchmark/0.1.0`. Existing graph-first and reference-coverage contracts remain unchanged.

New implementation files: `scripts/reference_library.py`, `scripts/reference_benchmark.py`, `scripts/run_reference_controlled.py`, `tests/test_reference_library.py`, `tests/test_reference_benchmark.py`, and this documentation directory. Prior uncommitted reference-coverage work was preserved. Existing files modified only to add CI execution of the new source-validated tests and LF attributes for new scripts: `.github/workflows/ci.yml`, `scripts/.gitattributes`.

Reused unchanged: original Rust stages, optional operational engine, Ghidra graph and P-code exporters, `graph_first.py`, `graph_first_evaluation.py`, existing classification/calibration helpers and serialization. Original source files, golden fixtures, historical protocols/splits/labels/results, and the antivirus-blocked registered graph-first study were deliberately left untouched. The starting inventory checks 1,242 paths; only CI and script attributes differ, with zero unexpected changes. No files were deleted. Cleanup proposals identify consumers and require separate future authorization.

## Evidence and limitations

Read [SCIENTIFIC_RESULTS.md](SCIENTIFIC_RESULTS.md) and `PILOT_RESULTS.json` for actual results. The three P-code-enabled pilots contain 27 directed comparisons from one correlated benign source lineage. Fixed-input reruns are byte-identical. These experiments provide no general evidence that coverage outperforms the frozen baseline. P-code-only comparison degrades under compiler changes, and all methods degrade when the observed effect moves into a separate function.

There is no independently heldout corpus and no authorized malware evaluation. Broad source families, independently documented malware regions and a larger relationship-ablation experiment remain scientific work. **The full malware scientific acceptance criteria are not complete.** The independently testable library, workflow, benchmark and pilot tooling are implemented; passing engineering checks must not be substituted for the missing scientific validation.

Initial pilot metadata used descriptive compiler-target architecture/tool text. Final catalogs were created in **new** `library-verified-metadata` directories, recording PE-header-measured x86 and exact exporter/engine hashes. Original catalogs/registrations were retained. Sample bytes, source provenance, canonical/fingerprint digests and reference IDs did not change; entry/manifest hashes changed because metadata became more precise. New registrations and evaluations explicitly pin those new catalogs. No compiled-byte provenance was normalized or retroactively replaced.

## Reproduction

Run PowerShell from `C:\Users\aless\Desktop\ghidra-scripts-pack`:

```powershell
python -m pytest -q tests
python -m pytest -q tests/test_reference_library.py tests/test_reference_benchmark.py
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
git diff --check
```

The complete runnable static pilot command is in [BENCHMARK_PROTOCOL.md](BENCHMARK_PROTOCOL.md); add `--query-msvc` or `--query-helper` and choose a fresh output directory for each variant. Existing engines were used without modifying Rust source. The initial sandbox GCC WinError 623 was resolved by approved native tool execution, not security changes. The separate DWARF failure remains preserved; no meaningful test command is hidden with `|| true`.

Final command results and evidence hashes are recorded alongside this report. Historical results from the preceding reference-coverage task are not counted as newly executed checks. Full current regressions, targeted checks and pilot outcomes are distinguished in the appended validation record.

## Next research step

Keep this pilot discovery-only. Build an independently annotated multi-lineage corpus with honest heldout separation and hard negatives that share both APIs and literal values while differing in relationships. Use the existing runner without tuning on heldout data. Populate real malware references only after the authorization and isolated-static-analysis protocol in `BENCHMARK_PROTOCOL.md` is satisfied.

## Final validation record — 2026-11-12

Executed in this task:

- Full Python suite: `python -m pytest -q tests` — 647 passed, 175 subtests passed in 279.92s. Log: `.build-cache/reference-library-pytest-final.log`.
- Latest targeted run: `python -m pytest -q tests/test_reference_library.py tests/test_reference_benchmark.py` — 24 passed in 20.07s, including the added two-distinct-samples/same-family regression collected after the full run. Log: `.build-cache/reference-library-targeted-final.log`. This is not reported as a fictional 648-test full run.
- Original Cargo tests: 252 passed; operational Cargo tests: 258 passed. Both fmt checks and Clippy with `--all-targets -- -D warnings` passed.
- Canonical acceptance: 7 passed; fingerprint acceptance: 11 passed; similarity acceptance: 20 passed.
- `python -m ruff check .`: passed. `python -m ruff format --check .`: 128 files already formatted.
- `git diff --check`: passed; Git warns that existing CI/attributes files may use CRLF on future checkout. New hashed script files are explicitly LF.
- Final inventory: 1,242 paths checked, zero unexpected changes. Only CI and script attributes differ from the starting inventory; frozen scientific artifacts/goldens remain byte-identical.
- Three P-code-enabled real-binary pilots: 9 directed pairs each; all final comparison reruns byte-identical. Metadata precision update used new immutable catalogs; IDs and score rows unchanged. See `PILOT_RESULTS.json`.

Not executed/claimed: authorized malware evaluation, independent heldout generalization, broader source-family replication, restart of the quarantined historical graph-first experiment. The prior task's Notepad tests are previous evidence, not newly executed tests in this task. The final scientific caveats are substantive, not technical failures masked by skips.
