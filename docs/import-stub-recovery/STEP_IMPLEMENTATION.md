## Import-stub recovery - implementation and source-proof validation - 2026-11-13
STATUS: opt-in experimental recovery implemented and tested; default extraction unchanged.
OBJECTIVE: recover missing socket API observations using binary import/call/jump evidence, never function-name guesses.
EXISTING CODE REUSED: API normalization and typed graph builders; unchanged detector, canonicalization, fingerprints, library and A-E scoring.
NEW CODE: scripts/import_stub_recovery.py; tests/test_import_stub_recovery.py; explicit osgf.pe32-import-stub-view/0.1.0 graph/proof artifacts.
FILES MODIFIED: new module/tests/docs, LF attribute and canonical CI test inclusion. No frozen implementation, original graph or protocol modified.
TESTS RUN: 68 targeted tests passed (22.89s); acceptance suites 7/11/20 passed; Ruff, 135-file format check and git diff check passed. Exact reconstruction of both real derived graphs/proofs. Full Python suite still running at this report.
REGRESSION STATUS: original graph/Rust/P-code implementations untouched. Wrong instruction targets, IAT mismatches, ordinals, ambiguous/indirect calls and truncated files are rejected or left unresolved; no fabricated API name.
SCIENTIFIC RESULTS: named PE imports and exact FF25/E8 bytes support 33 recovered caller edges per build. Original detector recovers subject/equivalent/foil: 0/3 to 3/3 in both O0 and O2, with six total seeds per build.
LIMITATIONS: unbound i386 PE32 named imports and six-byte stubs only. Not a general thunk resolver; no default behavior change. Existing antivirus-blocked fixture untouched.
NEXT STEP: record the separate recovered-region comparison experiment and final full-suite outcome.
