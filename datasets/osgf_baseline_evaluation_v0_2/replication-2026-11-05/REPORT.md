# Real Ghidra scientific replication — 2026-11-05

STATUS: PASS for completion of the experiment. No general classification improvement demonstrated.

## What actually ran

Fresh Ghidra projects and settings for all nine existing controlled PE builds; no reuse of old extraction. The final resource-corrected operational executable was used. Target PE programs were statically analyzed, never executed. The experiment measures binary representation/retrieval, not dynamic behavioral correctness. Source-derived equivalence arguments and negative witnesses remain the ground truth.

27 routines from three source families, GCC O0/O2 and MSVC O0. Each family is entirely in one split. 81 cross-build pairs (27 per split: 15 positive, 12 hard negatives), nine mixed-gallery queries per split. Same-source variants are correlated observations, not 81 independent scientific samples. This is a replication on previously observed families, not a new blinded heldout or population-wide significance test.

A = unchanged v0.1, B = v0.2 structural only, C = P-code operational only, D = combined comparable-view mean. All receive the same selected structural context. Algorithm, ground truth, splits and threshold policy were fixed before the run. Thresholds use discovery only; validation and heldout never tune them. Explicit depth-zero anchors isolate intraprocedural evidence and do not establish full seed-detection or wrapper robustness.

## Actual results

| Condition | Split | TP / FP / TN / FN | TPR | FPR | Balanced accuracy | MRR | Recall@1 / @3 / @5 |
|---|---|---|---|---|---|---|---|
| A | discovery | 0 / 0 / 12 / 15 | 0.000000 | 0.000000 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| A | validation | 0 / 0 / 12 / 15 | 0.000000 | 0.000000 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| A | heldout | 0 / 0 / 12 / 15 | 0.000000 | 0.000000 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| B | discovery | 0 / 0 / 12 / 15 | 0.000000 | 0.000000 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| B | validation | 0 / 0 / 12 / 15 | 0.000000 | 0.000000 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| B | heldout | 0 / 0 / 12 / 15 | 0.000000 | 0.000000 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| C | discovery | 7 / 4 / 8 / 8 | 0.466667 | 0.333333 | 0.566667 | 0.777778 | 0.222222 / 0.500000 / 0.861111 |
| C | validation | 5 / 4 / 8 / 10 | 0.333333 | 0.333333 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| C | heldout | 5 / 4 / 8 / 10 | 0.333333 | 0.333333 | 0.500000 | 0.777778 | 0.222222 / 0.555556 / 0.888889 |
| D | discovery | 7 / 4 / 8 / 8 | 0.466667 | 0.333333 | 0.566667 | 0.777778 | 0.222222 / 0.500000 / 0.861111 |
| D | validation | 5 / 4 / 8 / 10 | 0.333333 | 0.333333 | 0.500000 | 0.666667 | 0.166667 / 0.500000 / 0.833333 |
| D | heldout | 5 / 4 / 8 / 10 | 0.333333 | 0.333333 | 0.500000 | 0.777778 | 0.222222 / 0.555556 / 0.888889 |

## Does P-code improve the baseline?

On this heldout family, MRR changes from 0.666667 to 0.777778 (absolute delta +0.111111); Recall@1 changes from 0.166667 to 0.222222. Balanced accuracy changes from 0.500000 to 0.500000. These are descriptive pilot effects, not proof of generalization or statistical significance.

The structural-only scores are all 1 on this experiment. Under the registered highest-threshold tie policy, discovery selects the sentinel above 1 and A/B reject every pair. FPR=0 therefore coexists with TPR=0 and is not evidence of a useful classifier. C/D distinguish some representations, but their heldout TP=5/15 and FP=4/12 yield TPR=FPR=1/3 and balanced accuracy 0.5. The retrieval gain does not establish a classification gain.

Every split/condition still has 9/9 queries with tied scores, resolved by case ID. Recall@K is relevant-item recall, not hit-rate. C and D have identical rankings here because the only comparable structural contribution is constant, making D=(1+C)/2. Combined scoring supplies no independent gain in this setting.

## Compiler/optimization sensitivity

| Split | Operational positive mean across compilers | Across GCC optimization | Mean positive feature churn |
|---|---|---|---|
| discovery | 0.080473 | 0.022186 | 0.938956 |
| validation | 0.044016 | 0.027027 | 0.961647 |
| heldout | 0.034994 | 0.028073 | 0.967313 |

Compiler/optimization sensitivity remains substantial; the experiment does not meet the broader scientific ambition of robust equivalence recognition across those changes. No representation or threshold was retuned to conceal this result.

## Reproducibility and observability

A/B representations and set/multiset scores are identical. Within this run, 27 fingerprints were regenerated and 81 comparisons repeated with exact byte equality. Across fresh extraction versus the previous study, 27/27 complete fingerprints are byte-identical; all pair records match: True. No additional independent evidence is claimed from repeated identical data.

Extraction states: ['complete']. Operational feature cardinality 48–80. Null scores and descriptive insufficient-evidence rates are zero. Complete extraction does not imply full behavioral observability or proven equivalence.

Executed 423 successful command receipts, total measured child wall time 419.216 seconds. Memory readings cover only direct-child peak working set, excluding descendant/JVM process-tree memory. Logs and original operation/source provenance are under runtime/study-001; full receipts and scores are in results.json.

## Execution and preservation

Two attempts to start outside the sandbox timed out in automatic permission review before execution. The full experiment then ran inside the restricted environment with projects/settings in the repository. No antivirus or operating-system protection was changed. Math-policy regression: python -m pytest -q tests/test_operational_evaluation.py, 2 passed. New driver Ruff check and format check passed.

PowerShell command from the repository root:

```powershell
python scripts/run_operational_replication.py --study-dir datasets/osgf_baseline_evaluation_v0_2/replication-2026-11-05 --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot' --work datasets/osgf_baseline_evaluation_v0_2/replication-2026-11-05/runtime/study-001
```

This work directory and result file now exist: repeating requires a new registered study/output directory. The old protocol, results, scientific golden fixtures and labels are preserved. No LLM changes, commit or push.

Conclusion: real P-code extraction and the final pipeline are reproducible. A limited retrieval improvement is measured on one heldout family; general classification improvement and cross-compiler robustness are not demonstrated. A larger independent benchmark and separately designed normalization studies remain necessary before a broader claim.
