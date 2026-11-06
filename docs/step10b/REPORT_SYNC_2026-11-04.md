<!-- osgf-step10b-report-sync-2026-11-04 -->

## Step 10B.2 — Operational evidence model (report synchronized 2026-11-04)

STATUS: Implemented and tested prototype; not acceptance of the full v0.2 baseline.
OBJECTIVE: Preserve operational distinctions and justified operand relationships beyond opcode counts.
SOURCE FILES INSPECTED: Existing exporter and scientific contract map; Step 10A checkpoint; Step 10B architecture/API research; controlled numeric and memory sources.
FILES CREATED: scripts/pcode_evidence.py, ghidra_scripts/pcode_extraction.py, ghidra_scripts/export_pcode_evidence.py, tests/test_pcode_evidence.py, docs/step10b/OPERATIONAL_MODEL.md and PROGRESS.md.
FILES MODIFIED: No existing production component.
ARCHITECTURAL DECISIONS: Separate requested Raw and High layers. Raw links only conservative instruction-local unique definitions; High links recovered SSA. No invented memory aliases, source types, ABI arguments or full control dependencies.
IMPLEMENTATION DETAILS: Ordered operands, widths, constant bits, distinct signed/unsigned predicates, optional outputs and original sequence provenance; unsupported operations remain explicit. Overlapping writes and control barriers invalidate Raw links.
SCHEMA CHANGES: Independent osgf.pcode-evidence/0.1.0; legacy contracts unchanged.
BACKWARD COMPATIBILITY: All 291 checkpoint SHA-256 values reverified unchanged on 2026-11-04.
TEST RESULTS: PASS — python -m pytest -q tests/test_pcode_evidence.py, 40 passed on 2026-11-04 (the earlier 34-test result was an intermediate checkpoint).
SCIENTIFIC EVIDENCE: Unit adapters are synthetic; real fixtures and real experiments are identified separately below.
KNOWN LIMITATIONS: No full Raw dataflow or proof of behavioral equivalence.
NEXT MICROSTEP: Standalone schema validation, then completion of the real-data gate.

## Step 10B.3 — Standalone P-code evidence contract (report synchronized 2026-11-04)

STATUS: Python contract prototype implemented and tested; later Rust integration not implemented.
OBJECTIVE: Strict independently versioned evidence and deterministic serialization.
SOURCE FILES INSPECTED: Legacy schema conventions and operational model.
FILES CREATED: Shared prototype files above; six real numeric Raw/High fixtures plus manifest and local LF attributes in tests/fixtures/pcode_evidence_v0_1/.
FILES MODIFIED: No frozen fixtures or existing scientific contracts.
ARCHITECTURAL DECISIONS: Original addresses/storage IDs are provenance, not portable semantic descriptors.
IMPLEMENTATION DETAILS: Reject invalid versions/IDs, duplicate operations/origins/JSON keys, dangling/conflicting dependencies, stale Raw definitions, invalid widths and inconsistent budgets/completeness. Serialize UTF-8/LF with deterministic ordering. Explicit complete/partial/unavailable/timeout/cancelled/failed states; configurable operation/dependency/time limits.
SCHEMA CHANGES: osgf.pcode-evidence/0.1.0 only.
BACKWARD COMPATIBILITY: Legacy CLI and scientific algorithms untouched.
TEST RESULTS: PASS — current 40-test focused suite includes fixture hashes, round-trip/order, semantic distinctions, invalid JSON, provenance, truncation and decompiler failure/disposal.
SCIENTIFIC EVIDENCE: Real fixture bytes originate from two fresh Ghidra imports of the registered numeric-gcc-O0 binary; the target executable was not run.
KNOWN LIMITATIONS: Extraction policy/environment provenance and cross-environment reproducibility need further review before scientific acceptance.
NEXT MICROSTEP: Finish 10B.4 before graph/fingerprint integration.

## Step 10B.4 — Real P-code extraction gate (checkpoint, 2026-11-04)

STATUS: IN PROGRESS — real extraction/repeatability subchecks PASS; entire microstep not yet accepted.
OBJECTIVE: Validate actual Ghidra data before integration.
SOURCE FILES INSPECTED: Registered build hashes, numeric/memory source and numeric transformation source; installed Ghidra Application API sources.
FILES CREATED: scripts/test_pcode_real.py; local logs/documents/validation.json under .build-cache/step10b/real-gate-1 and real-variants-1.
FILES MODIFIED: Prototype exporter corrected to Application.getApplicationProperty; command-line budgets added. No production code changed.
ARCHITECTURAL DECISIONS: Static analysis of existing registered PE bytes, fresh projects and settings for each repetition, separate Raw/High documents. Check output documents and log errors even if Ghidra exits zero. Later runner records implementation hashes and rejects changes during an experiment.
IMPLEMENTATION DETAILS: Dedicated existing PyGhidra interpreter, installed JDK 25, workspace-local Ghidra settings through application.settingsdir. This avoided denied writes to the user Ghidra profile without changing security protections.
SCHEMA CHANGES: None beyond the experimental contract above.
BACKWARD COMPATIBILITY: Samples were not executed; freeze files and legacy algorithms unchanged.
TEST RESULTS: Saved validation reports both say PASS. On 2026-11-04 the actual output pairs and their registered SHA-256 values were independently reread: 36/36 observations across six builds and 8/8 observations on the variant build are byte-identical between fresh repetitions.
SCIENTIFIC EVIDENCE: Six builds are numeric-gcc-O0, memory-gcc-O0, numeric-gcc-O2, memory-gcc-O2, numeric-msvc-O0 and memory-msvc-O0; three routines per build, two layers, two repetitions (72 documents). Variant build numeric-variants-gcc-O0 covers sum_array, transparent wrapper, thunk and function splitting in both layers and repetitions (16 documents). High numeric O0 distinguishes sum_array (15 operations/15 dependencies), find_max (19/20), count_matches (17/17); count_matches retains INT_EQUAL with constant 0x20. This is operational evidence, not an equivalence proof or a v0.2 accuracy claim.
KNOWN LIMITATIONS: The first six-build pilot did not record implementation hashes and the CLI was refined during that session: do not promote it to a pinned final gate. The variant experiment did record hashes; all still match current source. Full semantic/transformational analysis, final pinned replay, independent micro-experiments, environment provenance review and independent scientific evaluation remain pending. Peak memory not measured. Existing development corpus is not an untouched held-out evaluation.
NEXT MICROSTEP: Close those 10B.4 gaps, then implement 10B.5–10B.10. No new graph integration, operational canonicalizer, fingerprint, similarity or scientific evaluation is yet delivered.

Commands used for the saved experiments (PowerShell, repository root):

```powershell
python scripts/test_pcode_real.py --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot' --work .build-cache/step10b/real-gate-1 --build numeric-gcc-O0 --build memory-gcc-O0 --build numeric-gcc-O2 --build memory-gcc-O2 --build numeric-msvc-O0 --build memory-msvc-O0
python scripts/test_pcode_real.py --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot' --work .build-cache/step10b/real-variants-1 --build numeric-variants-gcc-O0 --function sum_array --function sum_array__transparent_wrapper --function sum_array__thunk --function sum_array__function_splitting
```

Use a new --work directory for future runs; existing evidence must not be overwritten. These commands were executed in the preceding work session, not rerun on 2026-11-04.

### Regression status and resumption boundary

Previous-session results, distinct from today's focused rerun:

- PASS: cargo test --locked --manifest-path rust_engine/Cargo.toml — 252 tests.
- PASS: python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe — 7 tests.
- PASS: python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe — 11 tests.
- PASS: python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe — 20 tests.
- PASS: python -m ruff check .; python -m ruff format --check .; cargo fmt --manifest-path rust_engine/Cargo.toml -- --check; cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings; cargo build --locked --manifest-path rust_engine/Cargo.toml; go test ./...; git diff --check.
- FAIL: python -m pytest -q tests — 504 passed, 7 failed, 1 skipped, 175 subtests passed. Six compiler-start failures report WinError 623; clean-checkout Git/MSYS reports NtCreateDirectoryObject access denied. These failures remain unresolved, not converted into PASS. Later focused additions brought the targeted suite to 40 tests; the full suite has not been rerun since those additions.
- BLOCKED: full python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json fails while probing GCC (WinError 623). Its read-only frozen_baseline verification separately passed for 161 files and scientific digest 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2.
- NOT CONFIRMED: final completion of the last Notepad smoke invocation; individual passing output was seen, but no complete final summary was recovered for this report.

Today, 2026-11-04: focused Python suite 40 PASS; 291/291 protected file hashes PASS; saved real experiment byte/hash reread 44/44 PASS. No fresh full-suite, Rust or Ghidra run is claimed today.

Branch codex, HEAD 66bcc9dda267aac29f7ea79a60ff6727a7340ada. No commit, push, LLM, scientific freeze, label/split modification or claim that Step 10B is complete. Resume at the remaining 10B.4 validation and regression/environment issues.
