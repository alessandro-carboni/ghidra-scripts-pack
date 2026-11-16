# Prospective benign family separation — continuation of microsteps 5–6

Date: 2026-11-12. Branch `codex`, HEAD `ff4e097351d0b64e0f9f03bede98d0d5db7c41fe`.

The user confirmed that no authorized malware corpus is available and requested benign validation. No malware was obtained or executed, and no endpoint protection was modified.

## Registered design

Three distinct authored functional source lineages were assigned before extraction or scoring:

| Partition | Family | Positive contract | Hard negative |
|---|---|---|---|
| Discovery | debugger_status | Equivalent boolean observation of debugger presence | Same API, complemented result; deliberately tests observational indistinguishability |
| Validation | resource_module | Load version.dll as data and inspect version resource 1 | Same resource-access API sequence applied to kernel32.dll |
| Heldout | socket_lifecycle | Create/close IPv4 TCP socket, no communication | Same API sequence requesting UDP instead |

Each family has GCC O0 references and GCC O2 queries, three annotated routines per build, and nine within-family directed planned pairs. Source labels specify requested effects and resource identity, not accidental equality of success booleans. Stable OS state/resource availability is an explicit assumption. All targets are static-analysis artifacts and are never run. The socket harness initializes Winsock; it never connects, sends or receives.

Sources and implementation/tool hashes are registered by `prepare` before extraction. Existing A/B/C/D/E definitions, default algorithms and discovery-only threshold calibration are reused unchanged. The families share includes, a small harness and compiler runtime, which are disclosed rather than treated as proof of independent ancestry. This is prospective **internally authored** family transfer, not blind external validation or representative malware evaluation. No original graph-first study or frozen protocol is modified.

## Two distinct limitations observed

1. The first debugger-status binary compiled successfully, but Windows denied the immediate byte read. The user confirmed Bitdefender blocked this path. No binary hash was acquired or invented. It was not restored, renamed, recompiled elsewhere or used. The original study directory and protocol are preserved. The partial protocol retains all original source bytes and split assignments and records discovery as unavailable. Its recorded reason uses the word “quarantine”; the event independently established here is an antivirus **block**, not a separately inspected quarantine status.
2. Socket O0 and O2 static extraction succeeded, but all three annotated regions in each build lacked automatic seeds. Both graphs represent `socket` and `closesocket` as internal FUNCTION nodes of size 6 with `thunk=false`, not as API nodes. The exporter at `ghidra_scripts/export_report.py` resolves external functions or recursively resolved external thunk destinations as APIs. These observed attributes explain why API seed rules did not trigger on the regions. Whether and how the import stubs should be recovered requires separate raw-import/flow validation; function names alone are insufficient evidence for promoting them to API observations.

Discovery is not reassigned to another family. Socket regions do not receive fabricated anchors, false zero similarities or positive labels based on method output. Runtime seeds are still searched and remain distinct from annotated-region recovery.

## Explicit continuation amendment

The initial runner conservatively stopped when an expected region had no seed. After that failure, `resume-available` was added to retain missingness and finish independently valid comparisons. This is a disclosed **post-observation availability-accounting amendment**, not a preregistered success. `continuation.json` pins the original protocol hash, new orchestration implementation and reason. It permits change only to this new runner, rejecting changes to source generation, scientific methods or tools. Existing binary hashes, source hashes, seed indexes and operational contexts are validated before reuse. The original protocol and completed artifacts are not overwritten.

The final record retains all 27 planned pairs and their independent source labels. Missing comparisons have `null` scores and explicit `unavailable_family` or `missing_automatic_seed` statuses. The benchmark evaluates only compatible artifacts and reports the available denominator separately. Without comparable discovery positives and negatives, every calibrated threshold and classification result must remain unavailable. Do not describe an absent heldout ROC result as a low AUC, or a missing observation as evidence of dissimilarity.

## Runnable PowerShell commands

From `C:\Users\aless\Desktop\ghidra-scripts-pack`, these are the actual commands for the partial run (existing directories refuse overwrites):

```powershell
$common = @('--engine','rust_engine/target/debug/rust_engine.exe', '--operational-engine','rust_engine/operational/target/debug/osgf_operational.exe', '--compiler','C:/MinGW/bin/gcc.exe', '--ghidra','C:/Users/aless/Desktop/_/Projects/ghidra_12.0.4_PUBLIC', '--ghidra-python','C:/Users/aless/AppData/Roaming/ghidra/ghidra_12.0.4_PUBLIC/venv/Scripts/python.exe', '--java-home','C:/Program Files/Eclipse Adoptium/jdk-25.0.2.10-hotspot')
python scripts/run_reference_corpus.py prepare --study .build-cache/reference-separated-available-v0_1 --unavailable-family debugger_status --unavailable-reason 'Bitdefender quarantine confirmed by user; binary not read or executed; discovery unavailable' --parent-protocol .build-cache/reference-separated-v0_1/protocol.json @common
python scripts/run_reference_corpus.py run --study .build-cache/reference-separated-available-v0_1 @common
# The original run stopped on the missing socket seed; the explicit amendment resumed it:
python scripts/run_reference_corpus.py resume-available --study .build-cache/reference-separated-available-v0_1 @common
python -m pytest -q tests/test_reference_corpus.py tests/test_reference_benchmark.py tests/test_reference_library.py
python -m pytest -q tests
```

These commands document execution, not instructions to repeat a blocked fixture. The original parent protocol/source record is needed to preserve omission provenance. Fresh partial studies must likewise retain an explicit parent and reason; the omitted family is never compiled. A completed run must not be resumed into its existing output paths.

## Next investigation

Validate the source of the socket import-stub classification from PE imports and Ghidra reference/flow facts. Any corrective extraction experiment must be separately versioned and compared to these preserved raw graphs; do not patch seed rules to match source function names. A complete discovery/heldout experiment also needs an appropriately approved research environment for the blocked fixture or a prospectively designed new study, not retroactive split reassignment. Authorized real malware and independent analyst annotations remain unavailable.
