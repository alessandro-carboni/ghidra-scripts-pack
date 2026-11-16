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
