
## Microstep 6 supplement - recovered socket diagnostics - 2026-11-13
STATUS: completed reporting supplement; no new scoring or default extraction changes.
IMPLEMENTATION: applied the existing versioned diagnostic runner to the registered recovered-socket experiment, validating registered inputs and source-bound coverage. Added docs/import-stub-recovery/DIAGNOSTICS.json and aligned the completeness audit with the completed recovery.
RESULTS: 9 labeled pairs (5 positive, 4 negative), yielding 20 positive/negative score comparisons. A/B/D and the unchanged E graph scores tie in all 20; C operational scores order all 20 correctly. These are correlated comparisons, not 20 independent samples. E ranking improvement remains distinct from its unchanged continuous score.
OBSERVABILITY: 3 query and 3 reference regions; no observed local/motif truncation. All regions retain warnings for unavailable indirect-call/dynamic-dispatch observation. Zero recorded unresolved entries does not establish absence of unresolved behavior. Missing discovery/validation strata remain null.
TESTS EXECUTED: diagnostic generation twice, both source-validation checks passed; complete JSON byte-identical. python -m pytest -q tests/test_reference_diagnostics.py: 7 passed in 0.10s. No source changes, so the previous full 670 tests + 175 subtests and acceptance 7/11/20 are prior results, not new runs.
REPRODUCTION (PowerShell from repository root; output must not exist):
```powershell
$study = '.build-cache/socket-import-experiment-20261113'
$digest = (Get-FileHash "$study/evaluation/results.json" -Algorithm SHA256).Hash.ToLowerInvariant()
python scripts/reference_diagnostics.py --evaluation "$study/evaluation" --dataset "$study/dataset.json" --library "$study/library" --registration "$study/registration.json" --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --result-sha256 $digest --output .build-cache/socket-diagnostics-new.json
python -m pytest -q tests/test_reference_diagnostics.py
```
LIMITATIONS / RESUME: post-observation benign experiment only. Socket recovery completed as opt-in; old incomplete study unchanged. No discovery calibration, independent replication or authorized malware evidence. Next scope must distinguish a new preregistered benign study from STEP 11; neither has been silently started. No commit/push or security exclusions.
