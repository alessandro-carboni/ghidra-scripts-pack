# OSGF Baseline Evaluation v0.1 — acceptance

Controlled benign function-equivalence experiment with query-specific judged galleries. No malware labels, no LLM contribution and no open-world retrieval claim.

## Retrieval on the complete common A/B cohort

Recall means retrieved positives / all judged positives in each query. Hit@K is separate in primary_metrics.json. K>N is unsupported. Different K denominators mean these columns are not a monotone curve on one cohort.

| Split | Condition | Recall@1 (N) | Recall@3 (N) | Recall@5 (N) | MRR (N) | Pairwise FPR |
|---|---|---|---|---|---|---|
| discovery_train | A | 0.579326047 (61) | 0.557347670 (31) | 0.905376344 (31) | 0.923497268 (61) | 0.714285714 |
| discovery_train | B | 0.579326047 (61) | 0.557347670 (31) | 0.905376344 (31) | 0.923497268 (61) | 0.714285714 |
| validation | A | 0.318181818 (22) | 0.937500000 (16) | 1.000000000 (4) | 0.840909091 (22) | 0.461538462 |
| validation | B | 0.318181818 (22) | 0.937500000 (16) | 1.000000000 (4) | 0.840909091 (22) | 0.461538462 |
| held_out_test | A | 0.551612903 (31) | 0.463541667 (16) | 0.773333333 (15) | 0.887096774 (31) | 1.000000000 |
| held_out_test | B | 0.551612903 (31) | 0.463541667 (16) | 0.773333333 (15) | 0.887096774 (31) | 1.000000000 |

Thresholds were selected on identical paired discovery IDs, by the preregistered balanced-accuracy rule, and persisted before validation/held-out evaluation. FPR is negative pairs predicted equivalent / scored negatives; it is not retrieval false-top1.

## Pair distributions

| Split | Condition | Label | N | Mean | Median | q05 | q95 |
|---|---|---|---|---|---|---|---|
| discovery_train | A | equivalent | 80 | 0.7067860108301284 | 1.0 | 0.11764705882352942 | 1.0 |
| discovery_train | A | non_equivalent | 35 | 0.665217266393737 | 1.0 | 0.05784313725490196 | 1.0 |
| discovery_train | B | equivalent | 80 | 0.7067860108301284 | 1.0 | 0.11764705882352942 | 1.0 |
| discovery_train | B | non_equivalent | 35 | 0.665217266393737 | 1.0 | 0.05784313725490196 | 1.0 |
| validation | A | equivalent | 26 | 0.6710346811308349 | 0.7777777777777777 | 0.16666666666666666 | 1.0 |
| validation | A | non_equivalent | 13 | 0.4785009861932939 | 0.19999999999999998 | 0.16153846153846155 | 1.0 |
| validation | B | equivalent | 26 | 0.6710346811308349 | 0.7777777777777777 | 0.16666666666666666 | 1.0 |
| validation | B | non_equivalent | 13 | 0.4785009861932939 | 0.19999999999999998 | 0.16153846153846155 | 1.0 |
| held_out_test | A | equivalent | 45 | 0.8012698412698412 | 1.0 | 0.3 | 1.0 |
| held_out_test | A | non_equivalent | 19 | 0.8947368421052632 | 1.0 | 0.3333333333333333 | 1.0 |
| held_out_test | B | equivalent | 45 | 0.8012698412698412 | 1.0 | 0.3 | 1.0 |
| held_out_test | B | non_equivalent | 19 | 0.8947368421052632 | 1.0 | 0.3333333333333333 | 1.0 |

## Churn and rank stability

302 independently equivalent pair-condition records contain exact inserted/deleted/count-changed descriptors for all three views. 114 eligible A/B rankings have zero normalized rank difference. Undefined constant/singleton correlations remain null. Cross-condition descriptor churn is unsupported without an approved mapping; within-condition churn remains fully reported.

| Condition | Split | View | Presence mean (N) | Multiplicity mean (N) |
|---|---|---|---|---|
| A | discovery_train | rooted_topology | 0.2190422077922078 (80) | 0.2501739355415825 (80) |
| A | discovery_train | typed_evidence | 0.8 (15) | 0.8 (15) |
| A | discovery_train | interaction_motif | 0.8 (15) | 0.8 (15) |
| A | held_out_test | rooted_topology | 0.1439153439153439 (45) | 0.1542857142857143 (45) |
| A | held_out_test | typed_evidence | 1.0 (3) | 1.0 (3) |
| A | held_out_test | interaction_motif | 1.0 (3) | 1.0 (3) |
| A | validation | rooted_topology | 0.1585081585081585 (26) | 0.17407544378698223 (26) |
| A | validation | typed_evidence | 0.4094017094017094 (26) | 0.4094017094017094 (26) |
| A | validation | interaction_motif | 0.8787878787878788 (11) | 0.8787878787878788 (11) |
| B | discovery_train | rooted_topology | 0.2190422077922078 (80) | 0.2501739355415825 (80) |
| B | discovery_train | typed_evidence | 0.8 (15) | 0.8 (15) |
| B | discovery_train | interaction_motif | 0.8 (15) | 0.8 (15) |
| B | held_out_test | rooted_topology | 0.1439153439153439 (45) | 0.1542857142857143 (45) |
| B | held_out_test | typed_evidence | 1.0 (3) | 1.0 (3) |
| B | held_out_test | interaction_motif | 1.0 (3) | 1.0 (3) |
| B | validation | rooted_topology | 0.1585081585081585 (26) | 0.17407544378698223 (26) |
| B | validation | typed_evidence | 0.4094017094017094 (26) | 0.4094017094017094 (26) |
| B | validation | interaction_motif | 0.8787878787878788 (11) | 0.8787878787878788 (11) |

## Runtime observations

Warm-up excluded; five measured repetitions on identical cohorts. Wall times include named validation/IO and process startup. Both engines use debug builds. A has one combined extraction invocation; B uses two. B-only substages are diagnostic, not matched A/B comparisons. OS caches were not flushed. Ghidra is a shared upstream cost not measured here. Peak RSS is unsupported.

| Condition | Stage | N | Median ms | q05 ms | q95 ms |
|---|---|---|---|---|---|
| A | combined_canonicalization_feature_extraction | 600 | 32.456 | 23.44926 | 86.66114499999999 |
| A | input_validation_loading | 600 | 2.9715 | 2.40652 | 5.029419999999997 |
| A | pair_comparison_with_validation_and_io | 1090 | 75.3702 | 65.025975 | 161.08445 |
| A | ranking | 5 | 1.6341 | 1.6095 | 1.96176 |
| B | B_only_canonicalization | 600 | 27.000500000000002 | 22.798825 | 40.13589499999997 |
| B | B_only_feature_extraction | 600 | 32.52265 | 25.58887 | 65.05022499999997 |
| B | combined_canonicalization_feature_extraction | 600 | 60.0503 | 48.878775000000005 | 105.85543499999996 |
| B | input_validation_loading | 600 | 2.7978 | 2.43118 | 4.169524999999998 |
| B | pair_comparison_with_validation_and_io | 1090 | 104.69784999999999 | 91.28885000000001 | 145.52215999999999 |
| B | ranking | 5 | 1.7628 | 1.54572 | 2.52322 |

## Limits and failure analysis

105 descriptive tables preserve frozen split, signal/observability strata and family holdouts. Six connected source components are below the preregistered minimum ten: no inferential interval or significance claim. Overlapping strata must not be counted as independent samples. Family-specific holdout FPR is unsupported because a family-excluded threshold protocol was not preregistered. Whole original galleries only are used for cell retrieval; empty cells remain unsupported.

A and B have identical retrieval outcomes here; this is not evidence of general method equivalence. Held-out FPR=1.0 is a major failure of the calibrated classification threshold on this cohort. All 142 condition-specific errors, exact pair labels and source-bearing artifact references appear in stratified_results.json; PROVISIONAL_REVIEW.md lists examples. No label or method was adjusted after seeing these results. Anchor-only graphs and incomplete/truncated observations remain included with warnings. Same-PE anchors remain dependent observations. Optional Step9 variants were not mixed into frozen partitions.

## Replay, checks and exclusions

Fresh-directory replay reconstructs both catalogs, all 436 pair scores and every derived scientific result. Timings are variable experiment observations and are bound separately. validation_commands.json records complete executed commands and exit codes. Python and Rust suites, Step5–7 acceptance, Step8 manual review/acceptance/leakage and Step9 protected inventory must all pass. Frozen source inputs and goldens are hash-bound in the scientific manifest.

NOT RUN: hosted CI/Linux, fresh compiler rebuild in the replay workspace, new Ghidra extraction, new Step9 supplementary experiment, optional peak RSS measurement, malware pilot. No commit or push was performed. The workspace replay uses the same pinned executable bytes in a new local directory; it is not advertised as a clean git checkout.

## Future separate experiment and handoff

The eventual ‘Step 10.5 REAL MALWARE PILOT’ is a separate future study: define authorized sample provenance and containment, independent labels, family/time splits, preregistered thresholds and evaluation before acquisition. Do not insert malware into this frozen controlled corpus. No samples were ingested here.

Ready for user review before Step11 implementation, within the explicit supported scope and limitations above. Step11 has not been started. Any baseline revision needs explicit supersession metadata and authorization; freeze-001 cannot be overwritten.
