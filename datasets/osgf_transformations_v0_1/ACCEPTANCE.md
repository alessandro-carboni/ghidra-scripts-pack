# Step 9 — final acceptance and delivery

Status: **COMPLETED — microsteps 9.0 through 9.9 PASS**. Audited 2026-10-21.

Branch `codex`; unchanged HEAD `47810b07328652c54538a88cb530802f768f9bc3`. No commit or push. No Step 10 implementation.

## Implemented components

Strict versioned contracts; bounded deterministic source generators for all six families; isolated compiler/PE admission; independent finite behavioral oracles; real Ghidra extraction and existing Rust canonicalization; evidence-based mappings at five levels; inherited split and leakage guards; per-run acceptance; fresh end-to-end replay; deterministic JSON/Markdown reports. The unified CLI provides generate, build, extract, map, validate, report and run.

## Microstep acceptance

| Microstep | Status | Evidence |
|---|---|---|
| 9.0 | PASS | Pinned freeze, source and golden inventory; environment and existing review verified |
| 9.1 | PASS | Seven strict record contracts and four versioned schemas |
| 9.2 | PASS | Six safe parameterized families; real C edge tests |
| 9.3 | PASS | Stable run/source IDs, deterministic generation, isolated publication |
| 9.4 | PASS | Six admitted real GCC O0 builds and independent behavior checks |
| 9.5 | PASS | Six real Ghidra analyses; 12 canonical anchor graphs, reconstructed byte-identically |
| 9.6 | PASS | Verified provenance relations; false/corrupt mapping rejection |
| 9.7 | PASS | Frozen source-component inheritance and leakage rejection |
| 9.8 | PASS | Full scientific regressions and fresh compiler/Ghidra replay |
| 9.9 | PASS | Unified CLI exercised; reports byte-deterministic; complete documentation and final integrity check |

## Actual six-family experiment

Run: `run:aba4cd955a9a4166b0e0d6c9`. Source: frozen `sum_array`; seed 9; compiler GCC 6.3.0 O0; Ghidra 12.0.4. Original and transformed entry points coexist in each controlled PE.

| Family | Generated | Builds pass/fail | Oracle inputs | Mismatches | Canonical graphs | Unsupported variants | Observation |
|---|---:|---:|---:|---:|---:|---:|---|
| dead_branch | 1 | 1/0 | 1024 | 0 | 2 | 0 | not_observable: 2 anchor records |
| function_splitting | 1 | 1/0 | 1024 | 0 | 2 | 0 | observed: 2 anchor records |
| harmless_strand | 1 | 1/0 | 1024 | 0 | 2 | 0 | observed: 2 anchor records |
| instruction_reordering | 1 | 1/0 | 1024 | 0 | 2 | 0 | not_observable: 2 anchor records |
| thunk | 1 | 1/0 | 1024 | 0 | 2 | 0 | observed: 2 anchor records |
| transparent_wrapper | 1 | 1/0 | 1024 | 0 | 2 | 0 | observed: 2 anchor records |

Totals: six PE builds; 6,144 distinct deterministic input cases across builds, with 12,288 original/transformed outputs checked against independent oracles. Six full Typed Evidence Graphs and 12 CanonicalSubgraphs. A fresh workspace regenerated, rebuilt, executed and reanalyzed all six binaries: source bytes, PE hashes, toolchain/artifact hash inventories, records, canonical digests, mappings, split and validation report bytes match. This is a same-environment result, not a cross-compiler identity claim.

## Mapping and leakage results

- ambiguous_mappings: 0
- one_to_many_mappings: 10
- total_original_elements: 25
- total_transformed_elements: 87
- unknown_elements: 24
- unmatched_elements: 18
- verified_mappings: 30

These are provenance association counts across distinct mapping levels, not functional-equivalence scores. Source derivation does not imply binary survival or graph isomorphism. Extra introduced elements remain unmatched; insufficient evidence remains unknown. Structural edge claims validate endpoint correspondence and type. Symbols are identity provenance only.

All six default executions and six graph pairs inherit discovery_train. No split changes. Complete family-holdout views are UNSUPPORTED because validation/held-out partitions are missing in this example. Inheritance from an actual frozen held-out source (count_digits) is tested; holdout filtering and cross-split attacks are tested. The current pure-template subset excludes OS/API routines in the frozen validation partition, so a complete real holdout experiment requires separately justified support, never split reassignment.

## Tests actually executed

- 2026-10-21 final full Python suite: **273 passed, 175 subtests passed**, 143.13 seconds.
- After the final observability/truncation/toolchain validation strengthening: **57 targeted tests passed**, 12.12 seconds (includes three new tamper cases). These counts overlap the full suite; they are not additive.
- Reporter/CLI tests: 8 passed; actual unified run completed. Repeated report command left report.json, report.md, validation.json and manifest.json byte-identical.
- Completed 2026-10-20 Rust suite: **252 passed**, zero failures; cargo fmt, clippy with -D warnings, and locked build PASS. Rust source and fixtures remain unchanged.
- Scientific acceptance: canonical **7**, fingerprint **11**, similarity **20** tests PASS.
- Real Notepad canonical self-comparison: **25/25** graphs PASS, 75 comparable views; 10 graphs with observability warnings; all reruns byte-deterministic.
- Step 8 review: **14** decisions verified; final dataset acceptance and leakage checks PASS; existing structural oracle suite **36,864** checks PASS. This count belongs to Step 8, not to the Step 9 experiment.
- Ruff check/format PASS, including explicit checks of all new Python files; git diff --check PASS.

The 2026-10-20 repository-wide Python run (261 tests / 175 subtests) and the subsequent 62-test admission run are historical evidence, superseded for current Python coverage by the runs above. Local detailed logs are in ignored .build-cache/step9-regressions.log, step9-final-tests.log, step9-final-evidence-tests.log and step9-live.log.

## Commands (PowerShell, repository root)

Configurable tool path placeholder: set GHIDRA_HOME to the actual installation.

```powershell
$env:GHIDRA_HOME = '<GHIDRA_INSTALLATION>'
python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json --ghidra-dir "$env:GHIDRA_HOME"
python -m pytest -q tests/test_transformation_schema.py
python scripts/transformation_harness.py run --config datasets/osgf_transformations_v0_1/config/default.json --ghidra-dir "$env:GHIDRA_HOME" --engine rust_engine/target/debug/rust_engine.exe --fresh-replay
python scripts/transformation_harness.py report --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9 --engine rust_engine/target/debug/rust_engine.exe
python -m ruff check .
python -m ruff format --check .
python -m pytest -q tests
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/dataset_review.py check
python scripts/validate_dataset_acceptance.py
python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
git diff --check
python -m pytest -q tests/test_transformation_extraction.py tests/test_transformation_mapping.py tests/test_validate_transformation_harness.py tests/test_transformation_report.py
```

All listed regression commands were actually executed with exit code 0. Unified run and fresh replay were also exercised separately; individual phase commands and their ordering are documented in docs/transformation_harness_v0_1.md.

## Frozen boundary and artifact protocol

All **161** baseline-protected files (entire Step 8 dataset, controlled sources, scientific golden fixtures) are byte-unchanged. No ground-truth label, split, frozen graph, human decision or freeze metadata changed. Freeze scientific digest: `095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2`; manifest file SHA-256: `0758de28ff2b49473b66de1dc90ab7561495eb1f84618114796f81a3be815c42`.

Step 9 JSON is UTF-8/LF, generated C compilation bytes explicitly CRLF. Physical hashes and scientific digests are distinct. The initial replay evidence kept a temporary relative workspace pointer; that diagnostic was moved to the local archive and the full artifact-hash comparison was added before final reporting. No scientific IDs, compiled bytes or frozen provenance changed.

Complete local run bundles include their PE files and are ignored by Git. Configuration, schemas, baseline inventory, code and this acceptance record are versioned candidates. Fresh checkouts regenerate complete bundles; no tracked manifest is shipped without its required binary evidence. Failed staging and Ghidra projects remain local. No tracked Python caches or unexpected working-tree changes were found.

## Files created (repository-relative)

- `datasets/osgf_transformations_v0_1/ACCEPTANCE.md`
- `datasets/osgf_transformations_v0_1/baseline.json`
- `datasets/osgf_transformations_v0_1/config/default.json`
- `datasets/osgf_transformations_v0_1/config/split_policy.json`
- `datasets/osgf_transformations_v0_1/schema/experiment.schema.json`
- `datasets/osgf_transformations_v0_1/schema/manifest.schema.json`
- `datasets/osgf_transformations_v0_1/schema/mapping.schema.json`
- `datasets/osgf_transformations_v0_1/schema/transformation.schema.json`
- `docs/transformation_harness_v0_1.md`
- `scripts/replay_transformation_harness.py`
- `scripts/step9_preflight.py`
- `scripts/transformation_build.py`
- `scripts/transformation_extraction.py`
- `scripts/transformation_families.py`
- `scripts/transformation_harness.py`
- `scripts/transformation_mapping.py`
- `scripts/transformation_report.py`
- `scripts/transformation_schema.py`
- `scripts/transformation_splits.py`
- `scripts/validate_transformation_harness.py`
- `tests/test_step9_preflight.py`
- `tests/test_transformation_build.py`
- `tests/test_transformation_extraction.py`
- `tests/test_transformation_families.py`
- `tests/test_transformation_harness.py`
- `tests/test_transformation_mapping.py`
- `tests/test_transformation_report.py`
- `tests/test_transformation_schema.py`
- `tests/test_transformation_splits.py`
- `tests/test_validate_transformation_harness.py`

## Existing files modified

- `.gitattributes`: Step 9 LF metadata / CRLF generated C policy only.
- `.gitignore`: exclude complete local Step 9 run bundles; preserve all previous rules.

Obsidian DONE TESI was appended after each completed microstep; it is outside the repository. Generated run artifacts and local logs are not counted as versioned source changes.

## Limitations, unavailable checks and Step 10 readiness

Step 9 MSVC/O2/O3 end-to-end matrices were NOT RUN; Clang was unavailable. Hosted CI and non-Windows end-to-end execution were NOT RUN. These are not reported as passing. The actual requested example matrix is GCC O0 and passed completely.

The real default run has no full family-holdout coverage; unsupported views are explicit. Dead branches and instruction order are not_observable with the frozen graph vocabulary. No optimized_away result was asserted merely from absence. Pure source transformations, finite input-domain coverage, compiler dependence, imperfect Ghidra observability, unresolved mappings and small-corpus limitations remain. No malware, similarity-derived label or LLM is used.

Step 9 infrastructure is ready for review and future Step 10 experiments. No fingerprint robustness evaluation, learned rewrite, training or Step 10 experiment has been implemented. No commit or push performed.
