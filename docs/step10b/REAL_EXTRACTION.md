# Step 10B.4 — real extraction gate, 2026-11-04

Technical prototype gate PASS. Ghidra 12.0.4 extracted Raw and High from registered GCC O0/O2 and MSVC O0 numeric/memory binaries, two fresh imports/settings per build: 36 observations, 72 documents, identical repeat bytes. The final run pinned the four extraction/harness source hashes throughout execution. The earlier unpinned pilot remains historical evidence only. The later addition of optional manifest/build-root arguments changes the runner hash, not the extracted evidence or extractor; each saved run records the implementation actually used.

Eight independently authored static micro routines add 16 Raw/High observations, repeated with fresh projects. Actual High output distinguishes signed INT_SLESS from unsigned INT_LESS; count-32 from count-33 by preserved exact constants; XOR from arithmetic; memory copy by LOAD/STORE. Sum-by-index and sum-by-pointer share LOAD, INT_ADD, MULTIEQUAL and RETURN. Their equivalence follows from their source loop invariants under valid input/memory and unsigned modulo arithmetic, not from similarity. Numeric variant export separately observed original/wrapper/thunk/splitting on a registered build (8 observations, two runs); wrappers retain calls rather than becoming invented inlined bodies.

Machine-readable reports, commands, timings, build hashes and opcode/dependency profiles are in evidence/. The new micro source is tests/fixtures/pcode_evidence_v0_1/micro_operations.c. Its binary was compiled but never executed. Compilation command in PowerShell:

```powershell
& 'C:\MinGW\bin\gcc.exe' -O0 -fno-inline '-Wl,--no-insert-timestamp' tests/fixtures/pcode_evidence_v0_1/micro_operations.c -o .build-cache/step10b/micro-builds/micro-O0/micro-O0.exe
```

The standalone extraction commands are scripts/test_pcode_real.py with --ghidra, --python, --java-home, --work and repeated --build; use --manifest, --build-root and repeated --function for the micro case. Exact child commands are retained in each evidence JSON. The launcher uses the supported application.settingsdir property for isolated writable settings and JAVA_HOME_OVERRIDE for the installed JDK; neither security policy nor antivirus configuration changed. Ghidra's exit code alone is insufficient: output admission and logged errors are checked.

## Interpretation and limits

Raw includes instruction/flag/register bookkeeping and only local unique dependencies. High is much smaller and recovers loop SSA, but remains dependent on Ghidra analysis, ABI, data type archives and imported OS-library exports. Compiler/optimization variation is directly visible in the per-build opcode/count profiles; no cross-compiler invariance or superiority is claimed. The contract records language/compiler spec/version/revision and declared analysis policy; reports retain full logs/commands locally. Cross-OS or arbitrary preconfigured-project reproducibility is not established: admission into future evaluation must pin the environment and reject an unrecorded policy. The entrypoint is intended for this fresh-default research protocol, not an assertion that any existing Ghidra project has identical settings.

No invented function input/output roles, alias classes, indirect targets or exact source-language types are introduced. Unsupported semantics and unresolved inputs remain observable. Runtime includes startup/import/analysis; peak memory is not measured here. These measurements are developmental extraction checks, not the independent scientific evaluation required in 10B.10.

Full Python regression rerun outside the restricted subprocess environment: 518 passed and 175 subtests passed, no skips/failures. The previous seven failures were environment-specific GCC/MSYS startup failures; their history remains in REPORT_SYNC_2026-11-04.md.
