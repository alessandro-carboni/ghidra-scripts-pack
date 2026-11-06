# Step 10B.10 and final validation — 2026-11-04

MICROSTEP: 10B.10 — Scientific comparison and final acceptance.

STATUS: PASS for implementation and requested controlled evaluation. General superiority is not demonstrated.

OBJECTIVE: Compare unchanged v0.1 (A), v0.2 structural (B), operational (C) and combined (D) on new source families without retuning on observed scores.

SOURCE FILES INSPECTED: Existing frozen evaluation/manifest/split contracts, new operational modules and CLI, original seed_rules.rs resource resolution, protected Step10A checkpoint, preregistered protocol and all command/result receipts.

FILES CREATED: scripts/evaluate_operational_baseline.py, scripts/verify_operational_replay.py, tests/test_operational_evaluation.py, datasets/osgf_baseline_evaluation_v0_2 source/protocol/manifest/results/README/REPORT, docs/step10b/VALIDATION.md, ACCEPTANCE.md and evidence receipts. The isolated rust_engine/operational crate and preceding operational modules complete the implementation described in earlier microstep reports.

FILES MODIFIED: New isolated entrypoint corrected for legacy resource-root resolution and given one packaging regression; .github/workflows/ci.yml adds an operational-baseline job. Original production code, entrypoint, Cargo manifest/lock and golden files remain unchanged.

ARCHITECTURAL DECISIONS: Separate internal crate shares legacy modules by path, with locked existing third-party dependencies. Operational view remains opt-in and separate. Scientific splits follow source families; thresholds are discovery-only and never become library decision rules. No target program execution.

IMPLEMENTATION DETAILS: Nine real builds, 27 routines, 81 cross-build pairs. All A/B fingerprints and both similarity aggregates agree; 27 fingerprint reruns and 81 comparison reruns are byte-identical. Full new-crate testing exposed 104 inherited resource-path failures, now corrected by an explicit resource-root compatibility macro without changing protected sources. All 279 operational stage outputs were replayed against the final executable and are byte-identical to the original study. Historical protocol revision 3 and results are retained unchanged; final-packaging-verification.json records the changed entrypoint/executable hashes and output-equivalence evidence. Full Ghidra extraction was not repeated after this resource-only change.

SCHEMA CHANGES: Evaluation protocol/result records 0.1.0 for this new study; no changes to the preceding operational contracts or frozen v0.1 formats.

BACKWARD COMPATIBILITY: PASS — 291/291 Step10A checkpoint hashes and 161/161 protected scientific hashes unchanged. Step8 digest remains 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2. No label, split, golden or human decision changed.

TEST RESULTS: Full Python 526 passed plus 175 subtests (before resource-only correction); affected targeted suite after correction 48 passed. Original Rust 252 passed; isolated crate 258 passed after correction (contains inherited tests, not 258 new tests). Go PASS, with cached packages identified. Ruff check/format, both Rust format/Clippy/build checks PASS. Legacy acceptance 7 canonical + 11 fingerprint + 20 similarity tests PASS. Real Notepad 25/25 graphs PASS, 75 comparable views, 10 graphs with observability warnings, all reruns byte-identical. Dataset review/acceptance, leakage, Step9 preflight and git diff --check PASS. Complete PowerShell commands and actual status chronology are in docs/step10b/VALIDATION.md; earlier failing receipts are retained, not relabeled PASS.

SCIENTIFIC EVIDENCE: Heldout MRR A/B=0.666667 versus C/D=0.777778; heldout balanced accuracy is 0.50 for all conditions. C/D heldout TPR=0.333333 and FPR=0.333333. A/B all scores tie at 1; the registered threshold tie policy predicts no positives, so TPR=FPR=0 is not useful discrimination. Every condition has 9/9 tied heldout queries. Complete extraction and 48–80 operational descriptors per routine do not imply complete behavioral evidence. Cross-compiler and optimization positive scores remain low. Full measured tables, timing/memory scope and raw data are in datasets/osgf_baseline_evaluation_v0_2/REPORT.md and results.json.

KNOWN LIMITATIONS: Small investigator-authored pilot with one source family per split, no external blinded benchmark, no cross-OS/architecture validation or executed-PE behavioral proof. Explicit depth-zero research anchors do not establish seed recall or wrapper invariance. Peak working set measures direct child only, not process tree/JVM totals. The strict full evaluation runner rejects final packaging against the historical protocol; use the documented replay utility or a separately registered full reproduction. Remote GitHub CI was NOT RUN because no push was performed. No general improvement claim is justified.

NEXT MICROSTEP: Requested Step10B.2–10B.10 implementation and technical acceptance are finished. Stop here; no LLM implementation. Future scientific strengthening remains a separate decision, not an unreported completed task.
