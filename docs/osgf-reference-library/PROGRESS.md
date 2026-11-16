# Incremental implementation record — 2026-11-11

## MICROSTEP 2 — Versioned reference library
STATUS: implemented; initial targeted validation passed, final regression pending.
OBJECTIVE: curated source-bound JSON library without inferred malware labels.
EXISTING CODE REUSED: graph_first fingerprint/validate/operational; deterministic serialization.
NEW CODE: scripts/reference_library.py; tests/test_reference_library.py.
FILES MODIFIED: additive files only in this microstep.
TESTS RUN: `python -m pytest -q tests/test_reference_library.py` — 14 passed in 15.67s (includes microstep 3 tests).
REGRESSION STATUS: full historical regression not yet rerun for this task.
SCIENTIFIC RESULTS: none; explicitly synthetic non-executable format fixtures.
LIMITATIONS: no authorized malware references populated. Source SHA verification binds supplied extraction metadata; it is not independent attestation of Ghidra execution.
NEXT STEP: complete search validation and benchmark integration.

## MICROSTEP 3 — Independent seed search
STATUS: implemented; initial targeted validation passed, final regression pending.
OBJECTIVE: TypedGraph automatic seeds to separately explained library rankings.
EXISTING CODE REUSED: graph_first.extract/search; reference_coverage.compare; graph_first_evaluation.rank.
NEW CODE: reference_library workflow/search and five explicit ranking policies.
FILES MODIFIED: same additive module and tests.
TESTS RUN: same 14-test run above, including two independent seeds, no-seed ineligibility, five self-score policies, deterministic tied references and unavailable artifacts.
REGRESSION STATUS: final full run pending.
SCIENTIFIC RESULTS: correctness checks only, not evidence of improved retrieval.
LIMITATIONS: optional P-code requires matching source/context; no executable-level verdict or score.
NEXT STEP: microstep 4 cross-version benchmark, then controlled scientific validation.

## MICROSTEP 4 — Cross-version benchmark — 2026-11-12
STATUS: implemented and tested; real pilot evaluation in progress.
OBJECTIVE: compare A frozen, B graph-first, C operational, D coverage, E existing optional refinement.
EXISTING CODE REUSED: graph_first_evaluation retrieval/ROC/ranking; existing classification and discovery calibration.
NEW CODE: scripts/reference_benchmark.py, tests/test_reference_benchmark.py; end-to-end and no-seed tests in test_reference_library.py.
FILES MODIFIED: CI includes new source-validated tests; scripts/.gitattributes pins LF for new modules.
TESTS RUN: `python -m pytest -q tests/test_reference_library.py tests/test_reference_benchmark.py` — 22 passed in 25.11s. `python -m ruff check .` passed; `python -m ruff format --check .` — 128 files formatted.
REGRESSION STATUS: full Python suite running, not yet reported as passed.
SCIENTIFIC RESULTS: synthetic exact rerun bytes confirmed; no scientific performance claim from these tests.
LIMITATIONS: thresholds unavailable without both discovery classes; operational missingness retained. Absent-seed queries remain in denominators. Real pilot first attempt stopped on Ghidra DWARF import errors at O2; retry uses no DWARF, preserves failed logs.
NEXT STEP: complete real benign pilot and document independent malware protocol.

## MICROSTEP 5 — Controlled validation and malware admission — 2026-11-12
STATUS: benign pilot and admission infrastructure implemented; broader independent corpus and authorized malware remain outstanding.
OBJECTIVE: exercise actual observable-seeded binaries without executing them or fabricating malware provenance.
EXISTING CODE REUSED: existing Ghidra graph/P-code exporters, Rust automatic detector and optional operational binding; controlled_corpus compiler inventory.
NEW CODE: scripts/run_reference_controlled.py; BENCHMARK_PROTOCOL.md.
FILES MODIFIED: additive runner/documentation only; no historical dataset changes.
TESTS RUN: GCC O0/O2 compilation and Ghidra static extraction completed; 9 source-labeled comparisons, exact deterministic reruns, 3/3 annotated regions recovered per build and 5 automatic seeds searched per query binary. P-code counterpart also completed. Full Python regression: 646 passed, 175 subtests passed in 308.43s; subsequent narrow validation additions are tested separately.
REGRESSION STATUS: original Rust 252 passed, operational Rust 258 passed, both fmt/Clippy passed; canonical 7, fingerprint 11, similarity 20 acceptance tests passed.
SCIENTIFIC RESULTS: this is a small discovery-only benign pilot, not malware validation; comparisons and detailed limitations are in the scientific report.
LIMITATIONS: one authored source lineage; no independently held-out lineage. A first run failed with GCC sandbox WinError 623; approved native execution succeeded. A DWARF O2 import failure was preserved and a fresh no-DWARF run completed. Existing quarantined graph-first study remains untouched.
NEXT STEP: finish cross-compiler pilot, final reporting and cleanup inventory. No malware download/execution or security changes.

## MICROSTEP 6 - Scientific reporting and actual experiments - 2026-11-12
STATUS: available experiments and scientific report completed; broader scientific acceptance remains incomplete.
OBJECTIVE: compare existing representations and coverage without a predetermined winner.
EXISTING CODE REUSED: original A/B/C scores, E refinement, existing metrics and Ghidra exporters.
NEW CODE: controlled static runner with --query-msvc and --query-helper; source-bound benchmark.
FILES MODIFIED: docs/osgf-reference-library/SCIENTIFIC_RESULTS.md, PILOT_RESULTS.json, FINAL_REPORT.md; additive runner.
TESTS RUN: three P-code-enabled real-binary pilots, 9 pairs each, deterministic byte reruns. GCC O0 to O2: A/B/D/E AUC 1, C 0.70. GCC to MSVC: A/B/D/E AUC 1, C 0.425 (MRR 2/3). Helper layout: all AUC 0.70, MRR 1. Annotated regions recovered 3/3 per build; every query seed searched (5/11/5 respectively). No-seed arithmetic probes unselected.
REGRESSION STATUS: full Python 647 passed plus 175 subtests (279.92s); latest targeted 24 passed (20.07s), including one test added after full-run collection. Rust original 252, operational 258; acceptance 7/11/20. Ruff, fmt, Clippy and git diff check passed. Inventory 1242 paths, zero unexpected changes.
SCIENTIFIC RESULTS: no observed coverage improvement over A/B. P-code-only loses true matches across compilers; all methods are sensitive to interprocedural context. Discovery thresholds do not establish heldout FPR. Recall@1=2/3 can coexist with MRR=1 when queries have two true gallery references.
LIMITATIONS: one correlated benign lineage, no authorized malware or independent heldout corpus. More precise x86 and tool-hash metadata was registered in NEW catalogs: original catalogs, binary bytes, fingerprint bytes and reference IDs preserved; manifests re-registered, scores unchanged. No compiled-byte provenance was normalized.
NEXT STEP: independent multi-lineage corpus and relationship-specific ablation; malware only under the authorized static protocol.

## MICROSTEP 7 - Future cleanup inventory - 2026-11-12
STATUS: completed; zero deletions.
OBJECTIVE: identify essential core, optional research, historical assets and future cleanup candidates.
EXISTING CODE REUSED: inspected actual imports, tests and CI consumers.
NEW CODE: none; documentation only.
FILES MODIFIED: docs/osgf-reference-library/FUTURE_CLEANUP_CANDIDATES.md.
TESTS RUN: 1242-path inventory and final git status/diff check; only authorized CI/LF edits among preexisting files.
REGRESSION STATUS: as microstep 6. HEAD remains ff4e097351d0b64e0f9f03bede98d0d5db7c41fe on codex. No commit/push.
SCIENTIFIC RESULTS: no cleanup-based scientific claim.
LIMITATIONS: absence of imports does not prove absence of reproduction consumers.
NEXT STEP: cleanup requires separate explicit authorization; do not delete frozen evidence or shared helpers.

### Resume point / outstanding scientific work
The library, all-seed workflow, versioned benchmark, benign pilots, scientific report and cleanup inventory are implemented. Malware scientific acceptance is NOT 100% complete: independent source lineages with genuine discovery/validation/heldout splits, broader hard negatives and authorized independently annotated malware samples remain necessary. Do not repeat completed engineering, alter the quarantined historical study or infer labels from scores. Main report: docs/osgf-reference-library/FINAL_REPORT.md. Exact evidence: PILOT_RESULTS.json. No commit or push performed.
