# Experimental, byte-backed import-stub recovery

2026-11-13. Branch `codex`, HEAD `ff4e097351d0b64e0f9f03bede98d0d5db7c41fe`.

## Root cause and implementation

The original socket graphs classify `socket` and `closesocket` as internal six-byte functions with `thunk=false`. Static `objdump` inspection of the benign O0 binary shows the named imports `WS2_32.dll!socket` and `closesocket`, and stubs consisting of `FF 25` jumps to IAT slots `0x40822c` and `0x408228`. The original Ghidra exporter accepts external functions or resolved external thunk destinations as APIs; these functions meet neither criterion.

The new **opt-in** `scripts/import_stub_recovery.py` writes an explicitly versioned derived graph and a proof receipt (`osgf.pe32-import-stub-view/0.1.0`). It never executes or edits the target, never changes the raw graph, and does not modify the default exporter or detector. Each recovered edge requires:

1. The actual binary SHA-256 to match raw extraction provenance.
2. A bounded, unambiguous i386 PE32 import lookup/IAT mapping to an observed named import.
3. A six-byte function body in an executable section, exactly `FF 25 <absolute IAT slot>`.
4. Every recorded direct caller site to contain an `E8` call targeting that exact stub, with matching static multiplicity.
5. No ambiguous duplicate API edge requiring unsupported aggregation.

The parser follows Microsoft's [PE import table specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table): lookup entries identify names or ordinals, and the unbound IAT corresponds to the lookup table. This implementation conservatively rejects bound/mismatched tables and unsupported architectures. It does not guess ordinal names. The recovered API identity comes from the import bytes, never the Ghidra function name. Existing API normalization and typed-node/edge builders are reused unchanged.

Both builds recover 33 proven caller edges, including runtime import stubs as well as the socket stubs. This is a generic proof rule over the inspected graph, not a socket-name whitelist. Original stub nodes are retained; metadata counts are updated in the new view, and all original edges replaced in that view remain in the proof receipt. This is not a complete PE loader or general thunk resolver: x64, bound/delay imports, multi-instruction thunks, ordinal resolution and ambiguous call aggregation are outside this version's scope.

## Actual validation and experiment

The unchanged Rust detector now recovers all three annotated socket regions in O0 and O2: **0/3 before, 3/3 after** in both builds. Total automatic seeds change from three to six per build. This establishes recovery of the intended observable regions, not behavioral equivalence or better discrimination.

The existing P-code exports were rebound to the **new exact structural contexts**. Previous operational fingerprints were not reused against a different graph. All six region contexts passed structural/binary binding. A separate source-labeled nine-pair experiment was registered before scoring; the old blocked/partial study, labels and raw outputs remain untouched. Its original heldout label is retained for traceability, but this is a **post-observation extraction experiment**, not a fresh blind heldout test.

| Condition | AUC | MRR | Discovery threshold |
|---|---:|---:|---|
| A: original graph score on new source view | 0.50 | 0.833333 | unavailable |
| B: graph-first on new source view | 0.50 | 0.833333 | unavailable |
| C: existing operational-only | 1.00 | 1.00 | unavailable |
| D: directional evidence coverage | 0.50 | 0.833333 | unavailable |
| E: existing optional refinement | 0.50 (unchanged B score) | 1.00 | unavailable |

Graph observations alone cannot distinguish the requested TCP/UDP contracts here. The graph ranking's MRR is affected by deterministic ties and must not be mistaken for discriminative score separation. P-code provides complementary discrimination in this small case; E improves retrieval without inventing a blended continuous score. No classifier/FPR claim is possible without discovery calibration. Discovery remains antivirus-blocked, and no authorized malware corpus is available.

All four complete result/ranking JSON files match their rerun bytes. Proofs and derived graphs reconstruct exactly. Machine-readable outputs are `RESULTS.json`, `proof-O0.json` and `proof-O2.json`; full local experiment artifacts are `.build-cache/socket-import-experiment-20261113/`.

## Commands and checks

From the repository root in PowerShell:

```powershell
$old = '.build-cache/reference-separated-available-v0_1/runtime/socket_lifecycle-O0'
python scripts/import_stub_recovery.py --binary "$old/socket_lifecycle.exe" --graph "$old/typed/socket_lifecycle.exe.graph.json" --output .build-cache/new-import-view-O0
python -m pytest -q tests/test_import_stub_recovery.py tests/test_reference_coverage.py tests/test_reference_library.py tests/test_reference_benchmark.py tests/test_graph_first.py
$study = '.build-cache/socket-import-experiment-20261113'
python scripts/reference_benchmark.py run --dataset "$study/dataset.json" --library "$study/library" --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --registration "$study/registration.json" --output .build-cache/new-import-view-evaluation
```

Fresh output paths are mandatory. To construct new seed fingerprints, use `graph_first.extract` on the derived graph; optional P-code must be bound again using the same derived graph and the existing raw high-P-code exports. The library registration and benchmark interfaces remain unchanged. The supplied experiment is reproducible from its preserved dataset, library, registration, context configurations, proof receipts and source hashes; no new binary compilation is needed.

Targeted checks: **68 passed in 22.89 s**, including synthetic byte fixtures, bogus instruction/IAT rejection, ordinal non-inference, source-hash mismatch, bound imports, truncated files, indirect calls and integration with the original Rust detector. Canonical/fingerprint/similarity acceptance suites rerun: **7/11/20 passed**. Ruff and format checks passed (**135 files**); `git diff --check` passed. Full Python suite: **670 passed, 175 subtests passed in 229.37 s** (fresh run). Final integrity verification: 1242 inventory paths with only authorized CI/attributes differences; all 30 historical pilot hashes, 10 separated-study hashes and 7 new experiment hashes match. Both real graphs/proofs reconstruct byte-for-byte; four complete comparison outputs match the rerun. Original scientific fixtures and golden files remain unchanged. Rust unit/clippy results from earlier work were not rerun for this Python-only change.

The initial `objdump` launch failed inside the sandbox with a DLL relocation error; approved native static inspection succeeded. This was a tool-launch issue, unrelated to the blocked debugger-status fixture. That fixture was not read, restored, renamed or rebuilt elsewhere. No malware execution, protection changes, commits, pushes or deletions.

## Remaining scientific scope

The socket seed gap has a working, narrowly supported opt-in recovery experiment. It is **not silently enabled in production** and does not make the historical incomplete study complete. Broader import forms require their own evidence and tests. Discovery calibration, genuinely independent replication, and authorized independently annotated malware remain outstanding. Preserve these negative/positive findings together: fixing extraction makes comparison possible, but graph coverage alone still fails to discriminate this controlled hard negative.

Final full-suite command (PowerShell, repository root):

```powershell
python -m pytest -q tests
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
git diff --check
```

Full Python output: `.build-cache/import-stub-full-pytest.log`. Acceptance output: `.build-cache/import-stub-{canonical,fingerprint,similarity}.log`.
