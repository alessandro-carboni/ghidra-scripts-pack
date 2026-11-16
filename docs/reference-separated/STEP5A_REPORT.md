## Continuation 5a - Preregistered benign family separation - 2026-11-12
STATUS: implementation and targeted tests passed; complete experiment blocked by confirmed quarantine of discovery fixture.
OBJECTIVE: expand the single-lineage pilot into distinct discovery/validation/heldout source families, without changing existing algorithms.
EXISTING CODE REUSED: graph_first extraction, reference library, benchmark, original operational pipeline, existing compiler/Ghidra launcher.
NEW CODE: scripts/reference_corpus_sources.py, scripts/run_reference_corpus.py, tests/test_reference_corpus.py.
FILES MODIFIED: scripts/.gitattributes adds LF rules for the two new modules. Prior methods/protocols untouched.
TESTS RUN: python -m pytest -q tests/test_reference_corpus.py -- 4 passed in 0.51s. Ruff on new files passed. Original 1242-path inventory has zero unexpected changes.
REGRESSION STATUS: full Python suite started, not yet reported as passed.
SCIENTIFIC RESULTS: none yet for the new corpus. Sources/contracts/splits were registered before extraction/scoring. A/B/C/D/E unchanged; no score-driven labels.
LIMITATIONS: Bitdefender quarantined the first debugger_status-O0 executable immediately after successful compilation, before it could be hashed/read; user confirmed the event. No hash invented, no restore/rebuild/bypass. Original protocol and partial output preserved.
NEXT STEP: separate explicitly partial protocol retains identical sources/splits and omits ONLY the unavailable discovery family; resource_module (validation) and socket_lifecycle (heldout) are being statically extracted. No discovery means no fitted thresholds or classification claims. User confirmed no authorized malware corpus; benign validation only.
