# Step 10B.10 scientific comparison report

Status: PASS for executing the preregistered pilot and technical checks. General scientific superiority is NOT DEMONSTRATED. Date: 2026-11-04.

## Design and provenance

Three new source families, nine real compiled builds, 27 routines and 81 cross-build pairs (27 per split: 15 positives, 12 hard negatives). Each split has nine mixed-gallery queries. Source algebra and counterexamples define labels before scoring; no target PE was executed. Discovery selects thresholds; validation and heldout never retune them. All four conditions use identical selected structural contexts. A/B representations and both similarity measures match exactly. See README.md, protocol.json and manifest.json for commands, hash policy and limitations.

The algorithm was locked before the new source families were authored; families do not cross splits. This is investigator-authored, one family per split, and not external blinded validation. The explicit depth-zero anchor protocol is an intraprocedural test, not end-to-end seed discovery. Initial protocols 1/2 were interrupted for packaging compatibility before scoring. Protocol 3 is the measured run.

## Measured discrimination and retrieval

| Condition | Split | TP / FP / TN / FN | TPR | FPR (hard negatives) | Balanced accuracy | MRR | Recall@1 / @3 / @5 |
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

A = frozen v0.1; B = structural v0.2; C = operational only; D = comparable-view mean. Primary metric: set Jaccard. Recall is relevant-item recall, not hit rate. Every split/condition has 9/9 queries with score ties. Tie resolution is case-ID ascending, so MRR alone is fragile.

Discovery thresholds: A=1.0000000000000002; B=1.0000000000000002; C=0.04081632653061224; D=0.5204081632653061. A/B have all scores 1; the declared highest-threshold tie policy selects the sentinel above 1 and predicts no positives. Their FPR=0 is not useful discrimination: TPR=0 as well.

The operational view improves heldout MRR from 0.666667 to 0.777778 in this pilot, but heldout and validation balanced accuracy remain 0.5. It does not establish general classification improvement. C and D rankings are identical here: comparable structural evidence is constant, and D=(1+C)/2. The combined condition provides no independent gain in this setting.

## Stability, churn and observability

| Split | Operational positive mean across compilers (10 pairs) | Across GCC optimization (5 pairs) | Positive feature churn |
|---|---|---|---|
| discovery | 0.080473 | 0.022186 | 0.938956 |
| validation | 0.044016 | 0.027027 | 0.961647 |
| heldout | 0.034994 | 0.028073 | 0.967313 |

All 27 extractions report complete; feature cardinality ranges from 48 to 80. There are no null pair scores and the descriptive INSUFFICIENT_EVIDENCE rate is 0. This is extraction completeness, not complete behavioral knowledge: unresolved inputs, compiler lowering, register/stack roles and unsupported semantics remain qualified in source/support documents. Low positive similarities show substantial compiler/optimization sensitivity. Their precise causal contribution is an architectural hypothesis, not established by this ablation.

Source-equivalent transformations are proved by source algebra and compared empirically; matching score 1 is not asserted. Development sum-index/sum-pointer operational similarity was only 0.240964. Wrapper/thunk/splitting extraction preserves calls; no wrapper-invariant semantic equivalence guarantee is claimed.

## Determinism and cost

27 fingerprints were generated twice, and 81 comparisons twice, with byte-identical results. The later resource-path packaging correction was verified by replaying all 279 operational stage commands: bind 9, local 27, canonical 27, fingerprint 54, compare 162. All outputs match the original study bytes. No scientific descriptors, labels, splits or thresholds were changed.

| Stage | Calls | Mean wall seconds | Maximum direct-child peak bytes |
|---|---|---|---|
| operational-bind | 9 | 0.106555 | 11161600 |
| operational-canonical | 27 | 0.051370 | 8462336 |
| operational-compare | 162 | 0.181282 | 15020032 |
| operational-fingerprint | 54 | 0.095969 | 11583488 |
| operational-local | 27 | 0.088478 | 11350016 |

The 423 command receipts total 453.725 wall seconds, including extraction/legacy verification/repeats, excluding initial target compilation. All receipts obtained a direct-child peak reading. These are process measurements, not process-tree/JVM totals. Concurrent regressions, startup and cache effects prevent interpreting these as a controlled performance benchmark. Target compilation receipts are in manifest.json.

## Final packaging and repeatability boundary

A full new-crate test run initially failed 104 inherited tests because CARGO_MANIFEST_DIR pointed to the nested package. The original 252-test crate passed. The new entrypoint now supplies the original resource root to shared modules through a lexical env! compatibility adapter; the frozen files and bundled rules remain unchanged. A dedicated resource-root test plus all 258 new-crate tests pass. This is a demonstrated packaging bug and correction, not a semantic algorithm change.

The final entrypoint and executable hashes differ from protocol revision 3. The original protocol/results were not silently rewritten. docs/step10b/evidence/final-packaging-verification.json records the precise difference, and resource-path-replay.json binds final executable bytes to all original stage outputs. Full Ghidra extraction was not repeated after this resource-only correction; the extractor and semantic modules are byte-identical. The strict full evaluation runner will correctly reject final packaging against the historical protocol; use the replay command or preregister a separate run with its own retained protocol for a full new-environment reproduction.

## Conclusion and limits

The operational pipeline is implemented and technically validated. It distinguishes controlled minimal semantic differences while preserving v0.1, but is not yet a demonstrated strong classifier across compiler/optimization changes. Small correlated within-family pair samples, pervasive ties, conservative storage roles, bounded dependency paths, absence of full alias/control-dependence recovery, and one-family heldout limit external validity. A larger independent benchmark and verified normalization studies remain future scientific work; this delivery does not start LLM implementation or change old freezes.
