# Multilevel producer-context experiment v0.1

Additive experiment, 2026-11-09. Both corpora were previously observed; every split is exploratory, including historical `heldout`. No old labels, partitions or results were overwritten.

- `value_corpus_protocol.json` / `value_corpus_results.json`: the three source families introduced by the previous value-flow study.
- `operational_corpus_protocol.json` / `operational_corpus_results.json`: the earlier operational study.
- Each corpus: 27 real-Ghidra routine fingerprints, 81 cross-build pairs, seven fixed conditions.
- `runtime/` (ignored): repeated full fingerprints/comparisons, legacy replay outputs and command logs.
- Registration pins exact implementation/executable/input hashes. These are local paths to existing evidence; the real-data study is not a generic CI dependency.

The fingerprint contains separate depths 0, 1 and 2. All levels retain operation/dependency/two-edge-path families; depth changes only predecessor descriptor propagation. All source features remain traceable. The legacy depth-two features and original comparison objects are verified unchanged.

See `../../docs/multilevel-flow/IMPLEMENTATION.md` and `../../docs/multilevel-flow/FINAL_REPORT.md` for contracts, limits and results.

## Historical heldout slices (exploratory, not new blind tests)

### value corpus

| Condition | BA | ROC-AUC | MRR | TP | FP | FN | Ties / queries |
|---|---:|---:|---:|---:|---:|---:|---|
| exact | 0.500000 | 0.594444 | 0.888889 | 15 | 12 | 0 | 3 / 9 |
| depth_0 | 0.500000 | 0.655556 | 1.000000 | 5 | 4 | 10 | 3 / 9 |
| depth_1 | 0.500000 | 0.655556 | 1.000000 | 5 | 4 | 10 | 5 / 9 |
| depth_2 | 0.500000 | 0.566667 | 0.722222 | 5 | 4 | 10 | 9 / 9 |
| mean_01 | 0.500000 | 0.666667 | 1.000000 | 0 | 0 | 15 | 3 / 9 |
| mean_012 | 0.500000 | 0.655556 | 1.000000 | 0 | 0 | 15 | 3 / 9 |
| exact_mean_012 | 0.633333 | 0.638889 | 0.944444 | 9 | 4 | 6 | 3 / 9 |

### operational corpus

| Condition | BA | ROC-AUC | MRR | TP | FP | FN | Ties / queries |
|---|---:|---:|---:|---:|---:|---:|---|
| exact | 0.500000 | 0.583333 | 0.777778 | 5 | 4 | 10 | 9 / 9 |
| depth_0 | 0.633333 | 0.697222 | 0.925926 | 9 | 4 | 6 | 3 / 9 |
| depth_1 | 0.500000 | 0.677778 | 1.000000 | 0 | 0 | 15 | 7 / 9 |
| depth_2 | 0.500000 | 0.472222 | 0.833333 | 0 | 0 | 15 | 9 / 9 |
| mean_01 | 0.633333 | 0.700000 | 0.925926 | 9 | 4 | 6 | 3 / 9 |
| mean_012 | 0.633333 | 0.700000 | 0.925926 | 9 | 4 | 6 | 3 / 9 |
| exact_mean_012 | 0.500000 | 0.733333 | 1.000000 | 0 | 0 | 15 | 3 / 9 |

The multilevel/exact mean improves classification on the recent value corpus, but on the earlier operational corpus its discovery-calibrated threshold rejects every heldout positive. Good ranking is not reliable threshold transfer. No condition is promoted to the default. A new independent multi-family benchmark remains future work.

## Reproduction

With the exact registered input files and executable still present, choose unused output directories:

```powershell
python scripts/evaluate_multilevel_flow.py run --protocol datasets/osgf_multilevel_flow_v0_1/value_corpus_protocol.json --output datasets/osgf_multilevel_flow_v0_1/runtime/value-corpus-replay
python scripts/evaluate_multilevel_flow.py run --protocol datasets/osgf_multilevel_flow_v0_1/operational_corpus_protocol.json --output datasets/osgf_multilevel_flow_v0_1/runtime/operational-corpus-replay
```

A rebuild that changes executable bytes requires a separately documented registration; never replace historical hashes or claim an exact replay of a different executable.
