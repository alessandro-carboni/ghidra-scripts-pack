# Semantic extensions: final implementation and scientific report

Completed and verified 2026-11-10; execution started 2026-11-09. Branch codex, HEAD 402d08ad022456712be24d4e40bdc31efc4b92af. No commit or push.

## Conclusion

Implementation and the prospective pilot are complete. The preregistered primary combination does NOT improve heldout classification over multilevel: both have 6 TP, 24 FN, 0 FP and 105 TN. Near-maximal recall with low false positives was not achieved. New views remain opt-in research outputs; no default promotion or heldout-driven retuning. A PASS execution status means integrity and deterministic execution passed, not that the scientific improvement hypothesis passed.

## Implemented scope

- Step 1 multilevel was already implemented and preserved.
- Step 2: strict recovered HighParam slot/width/provenance sidecar, whole-width input checks, no-definition checks, ambiguity fallback to physical storage.
- Steps 3 and 7, implemented once: bounded effect-centered backward data/control dependencies; recovered CFG/postdominance, conservative condition fallback; explicit unknown, alias, volatility, indirect-effect and cycle barriers.
- Step 4: same-width modular integer constant folds and neutral identities, with provenance ledger. No general loop/memory/cast/float rewriting.
- Steps 5 and 6: layer correlations, redundancy/complementary errors, leave-one-out means, discovery-only threshold transfer diagnostics and reject-all detection.
- Step 8: separate role/family/opcode/signedness/width/constant view.
- Step 9: new internally authored six-family prospective benchmark, source contracts/oracles, fixed method registration, real compilation and Ghidra extraction, repeated comparisons.

See IMPLEMENTATION.md and the microstep entries already appended to DONE TESI.

## Benchmark and protocol

Method SHA-256: b17a175d9c289b22a8ac906aeca01c36f46e9af82e0e848a901d2d802587d486. Six new source families were authored after method registration, two per discovery/validation/heldout split; no source family crosses splits. Each has subject, equivalent implementation and bit-flipped foil. 1,051 Python oracle inputs per family (6,306 total), source-level algebraic arguments, and 12 cross-family class counterexamples support labels independently of similarity. Python formula validation is not execution of compiled targets or a formal whole-program proof.

18 GCC O0/O2 and MSVC O0 builds; 54 fresh Ghidra routine extractions; 54 complete CFGs and 242 recovered parameter occurrences. All 405 cross-build pairs were compared twice: 135 per split, each with 30 positives and 105 negatives. Fingerprints and semantic comparisons reproduced deterministically; Rust comparison bytes matched on every rerun. Final resumption rechecked all 405 stored Rust byte pairs. No target PE was executed.

Primary combined = 0.5 multilevel + 0.5 algebra. Discovery threshold maximizes TPR with FPR <= 5%, then lower FPR and higher threshold as tie breaks. Each diagnostic condition uses the same discovery-only rule. Validation/heldout never select thresholds or weights.

## Heldout results

| Condition | TP / 30 | FP / 105 | TPR | FPR | Same-family FPR (24 negatives) | AUC | MRR |
|---|---:|---:|---:|---:|---:|---:|---:|
| exact | 0 | 0 | 0.00% | 0.00% | 0.00% | 0.7838 | 0.8611 |
| multilevel | 6 | 0 | 20.00% | 0.00% | 0.00% | 0.8194 | 0.9167 |
| physical | 7 | 6 | 23.33% | 5.71% | 25.00% | 0.7352 | 0.8889 |
| parameters | 7 | 6 | 23.33% | 5.71% | 25.00% | 0.7352 | 0.8889 |
| effects | 8 | 2 | 26.67% | 1.90% | 8.33% | 0.6257 | 0.6818 |
| algebra | 8 | 2 | 26.67% | 1.90% | 8.33% | 0.6257 | 0.6818 |
| families | 12 | 6 | 40.00% | 5.71% | 25.00% | 0.8637 | 0.9722 |
| combined | 6 | 0 | 20.00% | 0.00% | 0.00% | 0.8200 | 0.9167 |

The family view has higher recall, but 6 false positives: 5.71% overall and 25% on same-family negatives. It cannot be declared the winner or substituted for the primary after inspecting heldout. Effects/algebra recover 8 positives at 2 false positives (1.90% overall; 8.33% same-family).

Primary discovery: 10 TP/20 FN/0 FP/105 TN; validation: 3 TP/27 FN/2 FP/103 TN; heldout: 6 TP/24 FN/0 FP/105 TN. Primary threshold = 0.1701923076923077. Its diagnostic balanced-accuracy discovery threshold produces heldout 20 TP and 14 FP (66.67% TPR, 13.33% FPR): ranking alone does not provide the requested low-FPR classifier.

Heldout primary AUC 0.8200 versus multilevel 0.8194 is negligible descriptive movement, not evidence of a meaningful improvement. Primary MRR is 0.9167, recall@1/3/5 is 0.2917/0.6528/0.8333. All 18 heldout queries contain score ties; case-ID tie breaking is recorded. No null scores occurred.

Post-run descriptive stratification (benchmark_diagnostics.json): every condition recovers 0/12 positive pairs across different equivalent implementations. All recovered positives are among the 18 same-implementation cross-build positives. Effects/algebra recover 8/18; multilevel and primary 6/18; families 12/18. This diagnosis did not change the method. Physical/parameter and effect/algebra have identical heldout metrics; there is no measured heldout gain from parameter normalization or these restricted algebraic rules in this pilot.

15/54 cases have expression barriers in physical/parameter/effect/algebra views. Complete extracted CFG does not imply complete symbolic semantics. Family bags have no expression barrier, but are coarser evidence.

## Existing-corpus audits

Both layer audit outputs reproduced byte-for-byte. On the historical value heldout corpus, depth0/depth1 Pearson = 0.9779859 and Spearman = 0.9673272; all three depths have the same 4 FP and 10 FN at their discovery thresholds. On the historical operational corpus, depth1/depth2 reject all 15 positives; depth0 has 6 FN and 4 FP. These are audits of previously observed data, separate from the new prospective pilot.

## Validation and preservation

- Prior segment of this same implementation run: 21 new tests passed; full suite 590 passed, 175 subtests passed in 1010.91 seconds. Logs: .build-cache/semantic-full-pytest-20261109.log.
- All eight commands in validation_commands.json passed: portability/hash and audit/strata determinism, canonical/fingerprint/similarity acceptance, real Notepad smoke, Ruff lint/format, git diff check. Notepad: 25/25 graphs, 75 comparable views, 10 warning-bearing graphs, 25/25 deterministic. Ruff format checked 115 files.
- Final 2026-11-10 verification: all 10 registered method files, executable SHA, 6 sources, 18 binaries, result/manifest/method bindings unchanged; preserved inventory 291/291 and frozen scientific files 161/161 unchanged. See final_integrity.json.
- Existing multilevel Rust edits predate this extension; no new Rust implementation changes here. Cargo suites were not rerun in this semantic extension run. Earlier Rust results are historical, not a new validation claim.
- No labels inferred from similarity, no old split/anchor-only removal, no golden/frozen metadata migration. The metadata-poison probe preserved semantic digest after renaming binary/function metadata.

## Limits

This is an internally authored prospective scalar uint32 pilot, not an externally blinded independent replication: only two source families per split, correlated compiler pairs, no population/significance claims. The contracts have no OS inputs; they do not validate OS/memory/call behavior. Effect guards are a bag of expressions, not a path-sensitive ordered effect trace or termination-sensitive equivalence proof. Aliasing, loops and missing evidence remain explicit. Recovered parameters are decompiler evidence, not ABI truth; parameter representation may also enable width-guarded COPY forwarding, so changes cannot all be attributed solely to register renaming.

## Commands (PowerShell from repository root)

These are actual commands used during this run; registration/generation/evaluation intentionally reject overwriting existing study outputs. Full compiler and 1,062 execution receipts are recorded in manifest.json/results.json. The final integrity helper is local under .build-cache.

```powershell
python -m pytest -q tests/test_semantic_flow.py
python -m pytest -q tests
python scripts/audit_semantic_layers.py datasets/osgf_multilevel_flow_v0_1/value_corpus_results.json --output docs/semantic-flow/value_layer_transfer_audit.json
python scripts/audit_semantic_layers.py datasets/osgf_multilevel_flow_v0_1/operational_corpus_results.json --output docs/semantic-flow/operational_layer_transfer_audit.json
python scripts/run_semantic_benchmark.py register-method --study datasets/osgf_semantic_benchmark_v0_1 --engine rust_engine/operational/target/debug/osgf_operational.exe
python scripts/create_semantic_benchmark.py --study datasets/osgf_semantic_benchmark_v0_1
python scripts/build_value_flow_corpus.py --study-dir datasets/osgf_semantic_benchmark_v0_1
python scripts/run_semantic_benchmark.py run --study datasets/osgf_semantic_benchmark_v0_1 --engine rust_engine/operational/target/debug/osgf_operational.exe --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot'
python scripts/validate_dataset_portability.py
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
python -m ruff check .
python -m ruff format --check .
git diff --check
python .build-cache/finalize-semantic-integrity.py
```

DONE TESI final report appended and verified on 2026-11-10: 248,650 prior bytes preserved, 3,130 appended, total 251,780. Backup saved locally before append.
