# Value-flow study: measured result

The new view is implemented and technically validated, but is not promoted to replace the exact operational view. Full implementation, tests, commands, development/new-family separation and scientific discussion: [final report](../../docs/step10c/FINAL_REPORT.md).

New-family heldout (saturating accumulation; 27 pairs, 9 mixed-gallery queries):

| View | Balanced accuracy | ROC-AUC | MRR | TPR | FPR |
|---|---|---|---|---|---|
| exact | 0.500000 | 0.594444 | 0.888889 | 1.000000 | 1.000000 |
| normalized | 0.500000 | 0.566667 | 0.722222 | 0.333333 | 0.333333 |
| mean | 0.516667 | 0.605556 | 0.888889 | 0.866667 | 0.833333 |

The equal-weight mean has only a small classification gain; normalized-only retrieval degrades. No statistically significant or general improvement is claimed. Ground truth is source-defined; algorithm and threshold policy were fixed before new source-family extraction/scoring. See value_results.json for all splits and development_results.json for separately labeled historical-corpus observations.
