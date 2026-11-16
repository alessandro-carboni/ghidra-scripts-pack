# Semantic extensions progress — 2026-11-09

Branch codex, starting HEAD 402d08ad022456712be24d4e40bdc31efc4b92af. Existing multilevel work is preserved.

- Step 2: implemented recovered HighParam/CFG sidecar, strict whole-width/no-definition/input checks, ambiguity fallback. PASS: synthetic guards and real Ghidra preflight (3 functions, 2 parameter occurrences each, complete CFG).
- Steps 3 + 7 (deduplicated): implemented backward data/control slice rooted at RETURN, STORE, CALL/indirect/unknown effects, LOAD and explicit memory destinations. Postdominance on recovered CFG; conservative all-condition fallback for incomplete/non-exiting CFG. Alias/volatility uncertainty retained.
- Step 4: implemented only equal-width modular constant folds and neutral integer identities; no casts, floating-point, memory or loop rewrites. Provenance ledger and bounded-expression barriers remain.
- Step 5: implemented layer Pearson/Spearman (average ranks for ties), equal-score counts, class-specific complementary errors and fixed leave-one-out means. Both existing corpora audited.
- Step 6: implemented discovery-only threshold transfer audit with class quantiles, fixed-threshold confusion and reject-all detection; no heldout optimization.
- Step 8: implemented role/family/opcode/signedness/width/constant feature view separate from expression/dependency views.
- Validation so far: 21 new tests PASS, Ruff check PASS; real JSON roundtrip/self-comparison PASS for three Ghidra functions. Tests caught a tuple/list roundtrip issue, corrected before method lock and any new benchmark scores.
- Step 9: COMPLETE. All 18 builds / 54 routines / 405 repeated comparisons passed execution and determinism. Primary heldout 6 TP, 24 FN, 0 FP, 105 TN: no classification improvement over multilevel. See FINAL_REPORT.md and benchmark_diagnostics.json. Method and labels were not retuned.

The first real preflight was not executed because automatic approval review hit its usage limit. After the user resumed, authorized retry completed. No security protections were changed and no analyzed target executable was run.

Full Python regression completed: 590 passed, 175 subtests passed in 1010.91 s. All eight additional regression/lint commands passed, including deterministic legacy Notepad 25/25. Checkpoint 291/291 and scientific inventory 161/161 unchanged. DONE TESI already contains the microstep reports for 2, 3/7, 4, 5, 6, 8; final benchmark report is available in FINAL_REPORT.md; DONE TESI synchronized and verified on 2026-11-10: previous 248,650 bytes preserved; appended 3,130 bytes; final size 251,780 bytes. Backup: .build-cache/DONE-before-semantic-final-20261110.md.
