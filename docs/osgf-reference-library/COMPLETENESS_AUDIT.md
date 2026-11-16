# Requirement completeness audit and reporting supplement

2026-11-12. Reviewed against the user attachment `a274c308-01f5-4116-aef3-d63222a87a45/Testo incollato.txt`. HEAD `ff4e097351d0b64e0f9f03bede98d0d5db7c41fe`, branch `codex`.

## Answer to the completeness question

It was not accurate to describe everything as complete except for one error. The engineering workflow was implemented, but the benchmark's requested secondary diagnostics were partly present only as raw records. This continuation adds a tested, versioned reporting module. The independently testable engineering work is now present; complete scientific acceptance remains unavailable for the explicit reasons below.

| Requested microstep | Engineering status and evidence | Remaining limitation |
|---|---|---|
| 2: versioned curated reference library | Implemented: source/byte/semantic binding, annotations, content-addressed catalog, duplicate rejection, validate/register/list/inspect/search; `reference_library.py` | No authorized real-malware catalog populated; annotations are not independently certified by software |
| 3: end-to-end reference matching | Implemented: authoritative automatic extraction, separate ranking per seed, no-seed state, five named policies, provenance and matched/missing/extra explanations | Socket regions demonstrate an actual upstream observation/seed-recovery limitation; no fabricated anchors |
| 4: cross-version benchmark | Implemented: A–E reuse, shared explicit pairs/gallery, leakage checks, preregistration, availability, retrieval/ROC/pAUC, discovery-only calibration, ties and groups; secondary diagnostics completed here | Missing discovery prevents threshold calibration; no replacement by validation-fitted thresholds |
| 5: controlled and malware-oriented validation | Implemented tooling and executed benign GCC/MSVC, optimization, helper-layout, resource and socket experiments; source-defined qualified labels and safety/admission protocol | Full independent three-partition evaluation incomplete: discovery blocked by antivirus, intended heldout regions unseeded, no authorized malware or external annotations |
| 6: scientific reporting | English reports, actual metrics, uncertainty, negative findings, provenance examples and exact commands; supplementary machine-readable diagnostics | No claim of malware generalization or overall improvement; incomplete experiments remain incomplete |
| 7: future cleanup | A/B/C/D categories with consumers, CI/reproduction use, risk and proposed actions | Zero deletions; future cleanup requires separate authorization |

Examples of benign functionality in the prompt are examples, not a requirement to implement every possible file/network/crypto/process application. The required variation axes have actual benign observations: source equivalents, two compilers, optimization changes, helper organization, hard negatives and absent/unresolved evidence. Their scientific coverage is still small and internally authored, explicitly not a broad independent malware benchmark.

## Added diagnostics

New files: `scripts/reference_diagnostics.py`, `tests/test_reference_diagnostics.py`. `scripts/.gitattributes` adds LF for the new script. No existing scoring, extraction, P-code, benchmark implementation or registered experiment was rewritten.

Contract: `osgf.reference-diagnostics/0.1.0`. This is an additive read-only analysis of registered results, not a new comparison condition. It verifies the registered inventory and result/registration digests, checks query/reference bindings and reconstructs source-bound coverage before deriving:

- Exact empirical positive, negative and hard-negative score distributions, including null counts.
- Positive/negative ordering overlap: ties and inversions with explicit denominators, without choosing a threshold.
- Pooled, per-split and per-functional-family retrieval and continuous diagnostics.
- Compiler-pair and optimization-pair strata, preserving missingness.
- Per-evidence-family set/multiset coverage distributions, separated by truth label.
- Unique-region truncation, observed-unresolved-record and warning rates, separated by query/reference side and split.

Observability denominators include only regions in comparable coverage pairs. Zero observed unresolved records is not proof of complete resolution: warnings remain explicit, and absent strata have null rates. Correlated pairs are not independent subjects. No weights, thresholds, labels, seeds or original scores are tuned or changed.

Executed outputs:

- `docs/reference-separated/DIAGNOSTICS.json`: available resource-module experiment.
- `docs/osgf-reference-library/DIAGNOSTICS-pcode.json`: GCC optimization pilot.
- `docs/osgf-reference-library/DIAGNOSTICS-msvc.json`: compiler-transfer pilot.
- `docs/osgf-reference-library/DIAGNOSTICS-helper.json`: helper-layout pilot.

These are new diagnostic analyses of existing experiments, not additional independently collected datasets. They do not change the previous scientific findings.

## Actual checks in this continuation

- `python -m pytest -q tests/test_reference_diagnostics.py`: **7 passed**, 0.18 s.
- `python -m pytest -q tests/test_reference_diagnostics.py tests/test_reference_corpus.py tests/test_reference_library.py tests/test_reference_benchmark.py tests/test_reference_coverage.py`: **54 passed**, 26.08 s.
- Diagnostics successfully executed on all four registered experiments with source-bound coverage reconstruction.
- The separated-experiment diagnostics were run twice and compared as raw bytes: identical.
- Ruff passed; format check: **133 files already formatted**; `git diff --check` passed.
- The original **1,242-path** inventory has zero unexpected changes. The known CI/LF edits remain the only modified preexisting paths. Prior pilot evidence hashes remain unchanged.

The previous full Python run (652 tests and 175 subtests), Rust tests (252/258), and acceptance suites (7/11/20) are prior validation, not falsely reported as rerun here. This continuation adds only the reporting module, its tests, LF attribute and supplementary documents/artifacts.

## Reproduction

Run from the repository root in PowerShell, choosing a fresh output filename:

```powershell
$study = '.build-cache/reference-separated-available-v0_1'
$digest = (Get-FileHash "$study/evaluation/results.json" -Algorithm SHA256).Hash.ToLowerInvariant()
python scripts/reference_diagnostics.py --evaluation "$study/evaluation" --dataset "$study/dataset.json" --library "$study/library" --registration "$study/registration.json" --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --result-sha256 $digest --output .build-cache/new-reference-diagnostics.json
```

The original registered inputs must remain available and byte-identical. Existing output files are rejected. The supplied digest binds the intended result file; the caller must use the preserved trusted experiment, not invent a result hash as proof of provenance.

## Exact remaining work

There is no outstanding rewrite of the library, ranking or comparison algorithms required by this prompt. Scientific completion still needs evidence-backed recovery of the socket import observations, an appropriately approved environment or a prospectively registered new discovery study, genuinely independent lineages/annotations, and authorized malware samples. None is manufactured by this reporting supplement. The existing blocked fixture is not restored or rebuilt elsewhere, and partitions are not reassigned after observing results. No commit, push or deletion was performed.

## Status update — 2026-11-13

The socket recovery limitation described above has now been addressed in a separate opt-in PE32 import-stub source view. See `../import-stub-recovery/REPORT.md` and `DIAGNOSTICS.json`. Both builds recover 3/3 annotated regions; all nine new pairs are comparable. The original incomplete study remains unchanged. This does not resolve discovery calibration, independent lineages/annotations or authorized malware availability. Detailed diagnostics confirm all graph-score positive/negative comparisons tie; existing P-code separates them in this small post-observation experiment. No new scoring rule or production-default change.
