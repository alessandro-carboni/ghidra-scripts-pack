
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
