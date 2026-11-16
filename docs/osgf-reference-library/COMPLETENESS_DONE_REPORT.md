## Completeness audit - microsteps 4 and 6 reporting supplement - 2026-11-12
STATUS: missing secondary reporting implemented and tested; full scientific acceptance remains incomplete.
OBJECTIVE: check the user instructions requirement by requirement and close independently implementable reporting gaps.
EXISTING CODE REUSED: registered benchmark results, existing metrics, reference-library validation and source-bound coverage reconstruction.
NEW CODE: scripts/reference_diagnostics.py (osgf.reference-diagnostics/0.1.0); tests/test_reference_diagnostics.py.
FILES MODIFIED: scripts/.gitattributes LF entry; docs/osgf-reference-library/COMPLETENESS_AUDIT.md; four supplementary DIAGNOSTICS JSON reports. Original algorithms/protocols/results unchanged.
TESTS RUN: diagnostic unit tests 7 passed (0.18s); combined coverage/library/benchmark/corpus/diagnostic tests 54 passed (26.08s). Diagnostics executed on all four registered experiments. Separated-experiment diagnostic rerun byte-identical. Ruff passed; 133 files formatted; git diff check passed.
REGRESSION STATUS: 1242-path inventory and prior pilot evidence hashes preserved. The previous full Python 652 + 175 subtests, Rust 252/258 and acceptance 7/11/20 remain previous results, not rerun claims for this supplement.
SCIENTIFIC RESULTS: distributions, positive/negative ties/inversions, compiler/optimization/family strata, feature-family set/multiset coverage, and unique-region truncation/unresolved/warning rates are now explicit. No rescoring, threshold tuning or new improvement claim.
LIMITATIONS: technical implementation is not full scientific acceptance. Discovery remains antivirus-blocked; intended socket heldout regions lack seeds; authorized malware and independent external annotations are unavailable. Missing evidence stays null and warnings stay separate from semantic scores.
NEXT STEP: read the requirement matrix in docs/osgf-reference-library/COMPLETENESS_AUDIT.md. No repeated library/benchmark implementation is needed. Remaining scientific work requires valid observation recovery and suitable independent/authorized data; do not bypass protection or change old splits. No commit/push/deletion.
