# Step 10B.10 independent-family pilot

This directory contains a new research evaluation, separate from all frozen v0.1 datasets. Read `REPORT.md` for measured outcomes and limitations. `protocol.json` revision 3 locks the implementation and executables used; `manifest.json` records exact source/build bytes, source-based equivalence arguments, negative witnesses and compiler commands. Labels are not inferred from similarity.

The three new source families are discovery (polynomial), validation (rotate) and heldout (modular). Each family remains wholly in one split. Each has subject, source-equivalent subject and foil routines, built with GCC O0/O2 and MSVC O0. Sources were authored after the operational algorithm lock. This is a small investigator-authored pilot, not an external blinded benchmark. Prior corpus observations are development evidence only.

`protocol-initial.json` and `protocol-revision-2.json` preserve interrupted packaging attempts. Neither reached pair scoring or validation/heldout extraction. The amendments restore historical source/manifest compatibility; operational semantic modules were not retuned. The successful run uses `runtime/study-003`.

## Recorded full-study command (historical protocol revision 3)

The following command produced study-003 (the example uses a new work directory). It is a historical receipt, not permission to rewrite a protocol after implementation changes:

```powershell
cargo build --locked --manifest-path rust_engine/Cargo.toml
cargo build --locked --manifest-path rust_engine/operational/Cargo.toml
python scripts/evaluate_operational_baseline.py --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot' --work datasets/osgf_baseline_evaluation_v0_2/runtime/study-004
```

Use a new workspace for each run. The required nine target binaries are intentionally local under `runtime/builds`; full compiler commands, versions, flags and expected SHA-256 values are in `manifest.json`. Rebuild those exact sources using the recorded compiler and its normal environment (MSVC requires its developer environment). Only compilation and Ghidra static analysis are needed; do not execute the targets. A different compiler installation or linked runtime may produce different bytes. Do not silently replace the recorded hashes: register a separate experiment with its own manifest/protocol and retain this result.

The runner rejects changed pinned implementation or executable bytes, wrong target hashes, split leakage, failed extraction, unequal A/B components, and non-deterministic fingerprint/comparison bytes. Rebuilding the Rust tools on a different platform/compiler may also change exact executable hashes. Historical hashes authenticate this experiment, not arbitrary rebuilds or cross-platform equality. New metadata use UTF-8/LF; compiled-source provenance uses the actual bytes, never retroactively normalized hashes.

The final packaging correction changes only entrypoint resource resolution and its executable hash; consequently the full runner correctly rejects final code against the historical protocol. Do not bypass that check. `docs/step10b/evidence/final-packaging-verification.json` records the difference. The source before the correction and original executable are retained in the local study directory. A full new-environment run requires a separate registered protocol/manifest and preservation of this study's metadata.

To verify the final executable against every existing operational output, the following current command replays only operational stages, never target programs. The recorded successful run used `resource-path-replay-001`; use a fresh directory when repeating it:

```powershell
python scripts/verify_operational_replay.py --engine rust_engine/operational/target/debug/osgf_operational.exe --results datasets/osgf_baseline_evaluation_v0_2/results.json --output datasets/osgf_baseline_evaluation_v0_2/runtime/resource-path-replay-002
```

## Outputs and interpretation

`results.json` contains every case, pair label/score, condition summary and successful command receipt. Local `runtime/study-003` additionally contains Ghidra projects, complete operational/source provenance, pair comparison JSON including multiset scores, exact rerun outputs and logs. The runtime directory is ignored by Git. Missing local runtime data must not be described as independently reproduced evidence.

A is the unchanged v0.1 CLI; B is the embedded structural component; C is operational only; D averages comparable views without learned weights. The primary analysis uses set Jaccard. A/B equality is checked for both set and multiset scores. Discovery-only thresholds maximize balanced accuracy, with highest threshold breaking ties; validation/heldout thresholds stay fixed. Library similarity does not adopt these experimental thresholds as a decision policy.

Retrieval uses mixed galleries with same-build candidates excluded. Recall@K is the fraction of all comparable relevant candidates retrieved, averaged across eligible queries; it is not hit-rate@K. Case-ID ordering resolves score ties. All negatives are source-defined hard negatives from the same family. Cross-compiler and optimization stability are positive-pair mean scores, not semantic equivalence proofs. Feature churn is mean `1 - operational set Jaccard` over positives.

Runtime receipts measure wall time of individual commands. Windows peak working set covers only the direct child, not its process tree; a Ghidra launcher measurement is not total JVM memory. Concurrent regression activity and warm caches limit timing comparisons. These measurements are diagnostic, not a controlled throughput benchmark. Explicit anchors and depth zero isolate intraprocedural evidence; they do not measure observable-seed recall or wrapper/context invariance. No cross-architecture or cross-OS reproducibility claim is made.

## Full final-implementation replication (2026-11-05)

The complete Ghidra extraction and A/B/C/D study have now been rerun using final implementation and fresh projects/settings. The original protocol/results remain unchanged. See [replication-2026-11-05/REPORT.md](replication-2026-11-05/REPORT.md) for actual results, commands and the separate registered protocol. This is a replication on previously observed sources, not a new blinded holdout.
