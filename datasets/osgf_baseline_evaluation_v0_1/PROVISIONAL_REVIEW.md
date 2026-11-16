# Step 10.8 provisional scientific review

Controlled benign function-equivalence dataset. Not a malware detector.

105 overlapping tables; 6 independent source components, below the preregistered minimum of ten. No inferential confidence interval or significance claim.

Family holdout membership is exactly frozen. Family-excluded threshold selection was not preregistered: holdout-specific FPR is unsupported. Retrieval within a cell preserves whole judged galleries; it never fills unknown relationships.

A/B query ranking is unchanged on the available cohort. This does not establish general method equivalence. The global discovery threshold produces held-out FPR 1.0, a material weakness. Anchor-only graphs and incomplete observations remain included and qualified.

Examples selected in stable matrix order, without changing labels or tuning the method:

| Condition | Pair | Split | Independent label | Score |
|---|---|---|---|---|
| A | pair:1111ce3850555321293ef20a | discovery_train | non_equivalent | 1.0 |
| B | pair:1111ce3850555321293ef20a | discovery_train | non_equivalent | 1.0 |
| A | pair:116f9b94ff3137f41fe0e872 | discovery_train | equivalent | 0.1111111111111111 |
| B | pair:116f9b94ff3137f41fe0e872 | discovery_train | equivalent | 0.1111111111111111 |
| A | pair:11da606b1cea94fb33958b0b | discovery_train | non_equivalent | 1.0 |
| B | pair:11da606b1cea94fb33958b0b | discovery_train | non_equivalent | 1.0 |
| A | pair:140bf804706cbf64f3ec36df | held_out_test | non_equivalent | 0.3333333333333333 |
| B | pair:140bf804706cbf64f3ec36df | held_out_test | non_equivalent | 0.3333333333333333 |
| A | pair:150a989550f7c4251c21e5de | validation | equivalent | 0.19999999999999998 |
| B | pair:150a989550f7c4251c21e5de | validation | equivalent | 0.19999999999999998 |
| A | pair:1510de987f48e7682a0c2e5b | discovery_train | non_equivalent | 1.0 |
| B | pair:1510de987f48e7682a0c2e5b | discovery_train | non_equivalent | 1.0 |

All 142 condition-specific errors and their graph IDs, raw artifact hashes and score record IDs are retained in stratified_results.json. The raw records link to source-bearing provenance. Pair dependence and limited judged galleries prevent open-world performance claims.

Cross-condition feature churn has no approved descriptor mapping and is unsupported. Step9 supplementary data is not mixed into this evaluation. Runtime and final acceptance remain pending.
