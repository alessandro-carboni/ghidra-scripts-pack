# OSGF Step 10A — deep baseline failure analysis

## 1. Executive finding and scope

The frozen implementation is reproducible and its Jaccard arithmetic agrees with an independent descriptor/count oracle. That does not make the representation a reliable behavioral-equivalence classifier. **39 of 67 independently negative pairs have exactly equal semantic descriptor multisets and score 1.0.** Of these, 32 compare only topology. No threshold or LLM normalization of those unchanged descriptors can recover distinctions absent from their input.

At the frozen threshold 0.3, held-out FPR is 19/19 = 1.0: 16 negatives score 1 and three score 1/3. The held-out negative mean exceeds the positive mean. Aggregate retrieval looks considerably better because 48 of 114 eligible query galleries are positive-only and numerous remaining candidates tie. On mixed held-out galleries, constant graph-ID ordering exceeds the OSGF MRR in this cohort; this is descriptive evidence of a weak ranking signal, not proof that constant ordering generalizes.

All 218 judgments and both conditions have been inspected computationally, without removing anchor-only graphs or relabeling. This report includes an explicit experimental limitation: a new real-binary/Ghidra probe was interrupted by host antivirus and was not completed or relaunched. Existing real graph evidence, graph-level counterexamples, independent source witnesses and Step 9 supplementary comparisons are reported separately. No production change, v0.2 implementation, Step 11, commit, push or freeze is authorized by this report.

## 2. Repository, tools and scientific identities

Branch `codex`; HEAD `66bcc9dda267aac29f7ea79a60ff6727a7340ada`; initial working tree clean. `CHECKPOINT.json` records Python 3.11.2, rustc 1.94.0 (4a4ef493e 2026-03-02), cargo 1.94.0 (85eff7c80 2026-01-15), Windows platform and exact preservation hashes. Ghidra 12.0.4 installation was present; installation presence is not a completed fresh extraction.

Step 8 scientific digest: `095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2`. Manifest exact SHA-256: `0758de28ff2b49473b66de1dc90ab7561495eb1f84618114796f81a3be815c42`. Step 10 protocol SHA-256: `35a4d37ba175e1316e4f2bd179179da5da28e2c534bfb7a1fa1005ddabb040eb`. The protected Step 9 inventory contains 161 files. An additional checkpoint covers 291 existing scientific/code files. These identities and all Step 5–7 goldens remain unchanged.

Contracts inspected: `docs/canonicalization_baseline_v0_1.md`, `fingerprint_baseline_v0_1.md`, `similarity_v0_1.md`, `controlled_dataset_v0_1.md`, `transformation_harness_v0_1.md`, `baseline_evaluation_v0_1.md`, and their production Rust/Python implementations. Frozen Step 10 acceptance is in `datasets/osgf_baseline_evaluation_v0_1/freezes/freeze-001/`.

## 3. Reproduction and evidence status

During this audit on October 27, `python scripts/evaluation_acceptance.py` completed full reconstruction and a second end-to-end fresh-workspace replay without writing a freeze. On October 28, after reboot resolved the process restrictions, the recovered diagnostic scripts reproduced the existing five core diagnostic JSON files byte-for-byte. Both aggregate measures and every view of all 436 records agreed with the independent oracle. Nine synthetic graph probes and six Step 9 comparisons also reproduced their exact output hashes.

`VALIDATION.md` distinguishes the earlier failed process launches, the successful post-reboot runs, skipped checks and the unavailable fresh micro-extraction. It contains full PowerShell commands. Earlier frozen reports are reference material; numerical tables in this report were independently recomputed from admitted inputs during this audit. The original behavioral proof outputs are stored evidence; 27 numeric/text negative witnesses were additionally recomputed with independent mathematical Python expressions against the authored C, in `SOURCE_WITNESSES.json`. This is not a claim of freshly executing those original binaries.

## 4. Complete failure forensics

`FAILURE_CATALOG.json` retains 436 records with unchanged pair judgments, routine/build/compiler metadata, comparable views, exact matched and different descriptors/counts, source-bearing artifact hashes, endpoint canonical paths, observability and truncation. Conditions duplicate judgments and are not independent trials. Exact score-one classification uses numeric equality, not rounded displays.

| Condition B category | Unique pairs |
|---|---:|
| Non-equivalent score exactly 1 / representation-indistinguishable | 39 |
| False match at threshold >=0.3 | 50 |
| Negative score >=0.9 | 39 |
| Equivalent score <0.5 | 41 |
| False negative at threshold 0.3 | 21 |
| Score-one negatives with only topology comparable | 32 |
| Comparisons with observability warnings | 193 |

Categories overlap. `CASE_STUDIES.md` deterministically selects five score-one negatives, five lowest positives, a strong positive, an observability case and a cross-compiler case, sorted by score then pair ID. `SUPPLEMENTARY_METRICS.json` includes every false Top-1 query and each held-out negative, not only representative successes.

Concrete negative: `pair:1111ce3850555321293ef20a`, numeric-gcc-O0, `sum_array` versus `count_matches`. Graphs `graph:6ff68b280145bdaab2fc192b` and `graph:e4935848a6d0deab8dd9c53d`. Input bytes `[13,30,47,64,81,98,115]` yield 448 versus 0, independently recomputed. Both fingerprints contain only three matching descriptors: ANCHOR role, caller distance 0, callee distance 0. Typed evidence and interaction are empty. Source: `samples/controlled/source/numeric.c`; exact canonical and fingerprint sidecar references are in the catalog/case study. This is representational indistinguishability, not a cryptographic collision or incorrect division.

Concrete low positive: `pair:116f9b94ff3137f41fe0e872`, `copy_buffer` versus the same source routine across builds, score 1/9. One endpoint contains additional helper/context descriptors, including runtime APIs such as IsProcessorFeaturePresent and GetCurrentProcess. Evidence and interaction overlap are zero. The measured mechanism is descriptor/context mismatch; its attribution to a particular compiler transformation remains an inference, not a fresh binary disassembly proof.

## 5. Classification and calibration

The independent discovery search reproduces threshold 0.3 under the preregistered balanced-accuracy policy and tie rule. All comparisons are >= threshold decisions; no rounding or null substitution.

| Split | TP | FP | TN | FN | TPR | TNR | FPR | Precision | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Discovery | 68 | 25 | 10 | 12 | .850000 | .285714 | .714286 | .731183 | .567857 |
| Validation | 17 | 6 | 7 | 9 | .653846 | .538462 | .461538 | .739130 | .596154 |
| Held-out | 45 | 19 | 0 | 0 | 1.000000 | .000000 | 1.000000 | .703125 | .500000 |

Held-out topology similarity is 1 for all 19 negatives. Sixteen have aggregate 1; three have topology 1 plus two one-sided empty evidence views scoring zero, giving `(1+0+0)/3`. Both groups exceed 0.3. A threshold above 1/3 removes the latter but retains all score-one collisions; rejecting score-one negatives also rejects score-one positives. This arithmetic explains why recalibration alone cannot solve the observed collision mechanism.

Held-out mean positive score .8012698412698412; mean negative .8947368421052632. Discovery aggregate ROC-AUC .524821, validation .637574, held-out .419298. Source-family composition shifts across splits, and there are only two connected components per split. Correct calibration on a weak discovery distribution does not imply useful transfer. The full discovery candidate curve is in `CLASSIFICATION_FAILURES.json`; it is not a post-hoc replacement threshold.

## 6. Feature quality and mathematical limits

| View | Empty graphs /120 | Mean distinct descriptors | Equal nonempty sets /218 pairs | Negative multiset=1 / comparable negatives | Positive score<.5 / comparable positives |
|---|---:|---:|---:|---:|---:|
| Rooted topology | 0 | 5.525 | 138 | 44/67 | 28/151 |
| Typed evidence | 82 | 1.458333 | 20 | 7/29 | 24/44 |
| Interaction | 97 | .958333 | 8 | 5/25 | 24/29 |

Including empty-empty sets, equality counts become 138, 165 and 172 respectively. Empty-empty equality is not a comparable semantic match. `FEATURE_DIAGNOSTICS.json` supplies every graph's distinct/multiplicity counts, common and rare descriptor frequencies, reuse across routine IDs, coverage and per-split distributions. `SUPPLEMENTARY_METRICS.json` supplies explicit denominators. No local graph or motif truncation flag is set in the 120 frozen graphs; sparsity is not explained by hitting these recorded budgets. Finite depth remains a context boundary even without a truncation flag.

| Held-out view | ROC-AUC | Average precision | Comparable positives / negatives |
|---|---:|---:|---:|
| Topology | .366667 | .647910 | 45 / 19 |
| Typed evidence | .375000 | .428571 | 3 / 4 |
| Interaction | .375000 | .428571 | 3 / 4 |
| Current aggregate | .419298 | .666422 | 45 / 19 |
| EXPLORATORY minimum comparable view | .433333 | .669609 | 45 / 19 |

Average precision uses grouped score thresholds, not trapezoidal PR integration. These dependent small-cohort summaries are not generalization estimates. Validation typed-evidence ROC-AUC is .671598, so it would also be incorrect to claim no signal exists anywhere. The sparse held-out evidence coverage and score-one collisions do establish that this representation does not reliably separate the current corpus. The exploratory control is fixed and untrained; it is not a proposed official score.

No same-feature-ID/different-descriptor collision was found across admitted fingerprints. Equal descriptors, generic topology and absent semantics are distinct from cryptographic collisions. The independent integer oracle checks set/multiset intersections, multiplicities, comparable selection and both unweighted aggregates for all 436 rows. Focused tests cover duplicates, invalid/u64 counts, sums exceeding u64, null/empty behavior, ties and threshold equality. Rust uses u128 sums; descriptor insertion uses checked counts. High scores here are compatible with correct arithmetic on weak features.

## 7. Why A and B are identical

The approved research adapter uses the same structural ordering, feature slots, role derivation, motif budgets, observability and scoring code. A disables selected value normalization/merging; it does not disable all preprocessing. Correspondence was traced through embedded raw source IDs, not version-dependent feature hashes.

| Intervention evidence | Applicable graphs | Graphs with changed node facts | Observed interpretation |
|---|---:|---:|---|
| API spelling/module/import normalization | 38 | 38 | Case normalization activates; graph changes are real |
| Supported constant interpretation | 11 | 11 | Raw annotation versus supported interpretation changes facts |
| Section abstraction | 0 | 0 | No section evidence in this corpus; efficacy unmeasured |
| Equivalent value-node merging | 0 observed merged groups | 0 | No corpus merge stressor |
| Context API names on edges | 11 | See source edges | Canonical edge context is not used by current semantic descriptor slots |

Typed descriptor collections change for 38 graphs and interaction collections for 23; topology changes for zero. Direct evidence-type accounting in NORMALIZATION_ATTRIBUTION.json further resolves API changes to 38 typed / 23 interaction graph collections and constant changes to 11 typed / 7 interaction collections, with zero pairwise intersection/union changes within either evidence type. Nevertheless, every one of the 218 pairs retains the same per-view intersection and union totals, and therefore both scores. All 114 common eligible rankings remain identical: zero beneficial, harmful or score/rank-changing A/B outcomes; all neutral on the frozen metrics.

This is not evidence that normalization never executes. It is evidence that the available changes preserve the measured overlap relations in this corpus. A/B is bundled, so independent corpus causal attribution to each simultaneous operation is not identifiable; the report does not pretend to have per-operation randomized effects. The absence of section/merge stressors and lack of overlap-changing API variants limit the ablation's coverage.

Isolated graph probes demonstrate API decoration normalization, supported-annotation handling and section-name abstraction: A .8214285714, B 1.0. A/W and Nt/Zw remain distinct; a changed constant remains distinct. Context-API aliases change A canonical edge facts but both scores remain 1, because this edge field does not enter semantic descriptors. This is a real downstream information omission, not a broken normalizer.

The value-merging probe is deliberately not forced to 1: B set score 1, multiset .9523809524. Typed counts align, but one merged value reached by two edge records creates two structural call-evidence motif occurrences versus one edge with occurrence count 2; interaction is 6/7. `fingerprint.rs:398` counts structural edge-pair motifs, not call-occurrence products. The graph encodings are not identical structural inputs. This exposes a future counting-contract review question; it does not prove a corpus failure caused by merging (the corpus has no merged groups).

## 8. End-to-end information-loss map

| Information | Typed graph / local graph | Canonical / fingerprint / score | Limitation and consequence |
|---|---|---|---|
| Arithmetic operations, comparison predicates, dataflow | No routine-level CFG/P-code/operation schema in seeded typed export | Absent downstream | Sum, maximum and predicates may become identical anchor observations; cannot be recovered by normalization |
| Functions | Raw identity/name/size in typed source; bounded caller/callee selection | Roles/distances survive; names, addresses and size remain provenance rather than semantic features | Relocation robustness, but no intrinsic computation representation |
| Internal calls | Resolved calls, sites, direct/indirect and counts; local depth boundary | Roles/relations/counts and structural motifs scored | Helper introduction changes layout; direct/indirect and context fields are not all descriptor slots |
| API/import evidence | Observed API names and reference relationships | Surface normalization, literal semantic API values, role-attached typed and interaction descriptors | Same APIs do not imply same ordering, arguments, branch conditions or behavior |
| Strings/categories | Referenced string values and existing categories, then local selection | Exact text/category descriptors and category chains | Preserves available evidence but misses unobserved computed strings; exact text may be compiler/context sensitive |
| Constants | `_record_constants_for_api_call` scans an eight-instruction window and `_classify_constant_for_api` selects supported cases | Literal preserved; only supported symbolic semantics; attached evidence scored | Not a routine-wide constant or argument-dataflow representation; arithmetic/predicate literals often never enter the graph |
| Sections | Supported by schema and canonical roles/flags | Can contribute typed evidence, but no frozen local graph contains one | Corpus cannot establish robustness of section normalization |
| Unresolved/indirect calls | Explicit observations and visibility indicators; no invented targets | Observability tracked separately | Missing evidence is warned about but does not reduce semantic Jaccard; callers must not treat score as confidence |
| Site addresses and raw properties | Source-bearing local documents preserved | Canonical IDs/order and ledger separate provenance from facts; fingerprint references source supports | Provenance retention is not semantic-feature retention |
| Coverage/budgets | Local configuration, counts, selection and truncation records | Coverage ledger and motif truncation explicit | No recorded truncation in this cohort; requested depth still limits context; absent feature does not imply absent binary behavior |
| Retrieval/classification | Judged edges and frozen scores | Mean of comparable views; deterministic ties; threshold .3 | Sparse high structural agreement becomes a positive decision; gallery composition affects ranking metrics |

Code anchors: `ghidra_scripts/export_report.py:944` (functions), `:1198` (constant classification), `:1304` (API-window constants), `:1497` (seeded typed exporter); `rust_engine/src/local_subgraph.rs` (selection/budgets), `canonical.rs:113` (edge facts), `:217` (API surface normalization), `:388` (function canonical facts), `fingerprint.rs:317`, `:341`, `:356`, `:373`, `:398` (feature construction), `similarity.rs:150` (aggregation). Legacy exporter entrypoint instruction analyses elsewhere in the file must not be confused with intraprocedural semantics in the seeded graph consumed here.

The controlled cohort uses explicitly mapped research anchors with caller depth 0 and callee depth 3. This is not a measurement of production observable-seed recall. A seed-selection defect cannot be inferred from these selected anchors; selection coverage requires a separate population-level experiment.

## 9. Gallery bias and ranking controls

| Split | Eligible / all queries | Positive-only eligible | Mixed eligible | OSGF all MRR | OSGF mixed MRR | Constant mixed MRR |
|---|---:|---:|---:|---:|---:|---:|
| Discovery | 61/61 | 24 | 37 | .923497 | .873874 | .825225 |
| Validation | 22/27 | 12 | 10 | .840909 | .650000 | .725000 |
| Held-out | 31/32 | 12 | 19 | .887097 | .815789 | .868421 |

Six zero-positive queries are ineligible, not silently successful. Single-candidate gallery counts (all queries) are 24/2/12; queries containing tied scores are 37/21/20; false Top-1 eligible queries are 9/7/7. Eligible K=3 denominators are 31/16/16 and K=5 denominators 31/4/15. All denominators and hard-negative mixed subsets are retained in RETRIEVAL_BIAS.json. No unjudged pair is treated as a negative.

Positive-only MRR is necessarily 1 for any ranking; Recall@1 is not necessarily 1 when more than one relevant candidate exists. The perfect-label control has MRR 1 but retains this Recall denominator. On held-out mixed galleries, OSGF Recall@1 is .268421 versus constant .291228; perfect-label upper bound .357018. Twenty fixed random permutations give mixed MRR range .692982–.921053, mean .839474. This is permutation variability, not a confidence interval. On validation mixed galleries the random mean is .725250; OSGF is .650000. High all-gallery MRR is therefore insufficient evidence of discrimination.

## 10. Dataset and ground-truth coverage

35 sample records, 27 controlled builds, 68 routine records, 120 canonical graphs, 218 pairs (151 equivalent, 67 negative). There are only 35 unique canonical digests. A canonical duplicate is not necessarily source leakage: distinct behavior can collapse to the same representation. Split validation groups source/artifact dependencies, not similarity scores. Numeric and memory share byte-sum semantics and are joined; explicit near-duplicate groups are documented in `split_config.json`. Six connected source components remain, two per split, so inference treating all pairs as independent is unsupported.

Independent judgment methods: 100 same-controlled-source positives, 51 source-transformation proofs, 67 concrete behavioral counterexamples. All 67 negatives share the same PE between endpoints, although their negative-category tags differ. Thus within-binary hard negatives are present, but cross-binary negative generalization is untested. Builds comprise MSVC O0=8/O2=4 and GCC O0=7/O2=4/O3=4; compiler availability and architecture coverage are narrow. Source-level OS-dependent proofs require their recorded stable-environment assumptions. None of these labels comes from similarity, the observed scores or this audit.

Dataset limitations and algorithm limitations coexist. More independent families are needed for generalization, but more samples with the same missing operation semantics would not by itself resolve the demonstrated indistinguishable pairs. No anchor-only example, hard negative or inconvenient split was removed.

## 11. Step 9 supplementary evidence

Existing six GCC O0 builds and twelve canonical anchors were hash-checked and reconstructed from their registered typed sources. Original and transformed anchors coexist in each PE; these are six dependent supplementary comparisons, not twelve independent binaries or a new held-out cohort.

| Family | Newly recomputed B multiset score |
|---|---:|
| Transparent wrapper | .5 |
| Thunk | .5 |
| Function splitting | .1875 |
| Harmless strand | .3 |
| Instruction reordering | .42857142857142855 |
| Dead branch | .5 |

All comparison reruns were byte-deterministic. Exact graph identities, typed/canonical SHA-256, call-edge observations and original behavior records are in STEP9_SUPPLEMENT.json. Explicit structural relationships support helper/layout sensitivity. Dead-branch predicates and instruction order are not exposed by this typed contract; observed graph differences may still arise from wrapper/layout scaffolding. Their absence is not evidence that the optimizer removed a transformation. A richer CFG/P-code view is a justified research hypothesis, not a demonstrated performance improvement.

## 12. Controlled micro-case coverage and limitation

| Requested case | Evidence used | What is established |
|---|---|---|
| Distinct arithmetic, similar external topology | Frozen real numeric graphs plus SOURCE_WITNESSES.json | Independently different outputs; identical observed descriptors in actual admitted graphs |
| Different predicates, same shape | Frozen real text/numeric graphs and authored predicates | Concrete independent witnesses; current representation cannot encode those guards |
| Equivalent behavior, different call layout | Step 9 wrapper/thunk/splitting, registered behavioral proof | Topology sensitivity with real existing extraction; no independent-binary claim |
| Distinct constants | `distinct_constant` graph probe | Observed literal 64 versus 65 remains distinct; not a claim all binary constants are extracted |
| Allowed/disallowed API aliases | Decoration versus A/W and Nt/Zw graph probes | Surface alias activates; unsupported semantic merging is not invented |
| Controlled missing evidence | Motif budget (0,0) graph probe | Truncation explicit; typed evidence unchanged; aggregate .6; missing support is not inferred equivalence |
| Generic topology collision | Real score-one negative examples and mathematical witness | ANCHOR/distance descriptors cannot identify routine behavior |

Nine synthetic graph probes include supported annotation/section handling, merging and edge-context cases. All validate provenance and B parity with the production CLI. They are diagnostic oracles, not new real-world performance samples.

The separate fresh `micro.c` compilation/execution/Ghidra run did not finish after Bitdefender flagged micro.exe. No MICRO_REAL_EXPERIMENTS.json is admitted. Its source is retained in the diagnostic script for review; the command-line real-execution path fails clearly pending security review. The incomplete run cannot prove fresh extraction behavior, compiler survival or real binary determinism. This limitation remains explicit rather than being replaced with invented Ghidra output.

## 13. Ranked attribution and alternatives

ROOT_CAUSE_MATRIX.json supplies affected pair/graph/query IDs, source groups, splits, evidence and reproduction commands. Counts overlap. Exposed query counts mean a gallery contains an affected edge, not that every such ranking changed.

| Root | Pair / graph exposure | Assessment |
|---|---:|---|
| Extraction/representation indistinguishability | 39 / 51 | Critical; exact equal multisets and independent negatives confirmed |
| Classification transfer failure | 19 / 20 held-out | Critical; calibration arithmetic correct, overlap defeats threshold separation |
| Local context/layout sensitivity | 41 / 51 low positives | High; feature mismatch confirmed; precise compiler causality case-dependent |
| Sparse-support interpretation | 32 / 37 score-one negatives | High; topology-only agreement is not behavioral evidence |
| Positive-only galleries | 48 eligible queries | High; inflated aggregate interpretation, not a ranking-code defect |
| Source/intervention coverage | 218 / 120 cohort scope | High; six components and missing normalization stressors limit conclusions |

Similarity arithmetic defects, digest collisions, recorded motif-budget truncation and normalization being entirely inactive do not explain the measured corpus failures. Unresolved issues include exact compiler instruction transformations, external malware transfer, richer representation efficacy and whether a revised multiplicity/context contract improves unseen families. The audit does not conflate these hypotheses with established causes.

## 14. Strengths retained

Strict provenance validation, independent labels, deterministic output, frozen scientific identities, explicit observability, source-component split checks and exact numeric correctness are valuable foundations. They make the failure interpretable and reproducible. They are not substitutes for discriminative semantic content.

## 15. Remediation and new evaluation

REMEDIATION_PLAN.md evaluates all ten requested design directions and gives phased objectives, components, contracts, independent tests, risks and evidence gates. Priority: verifiable intraprocedural distinctions and support reporting; then controlled context/layout robustness; then scoring/calibration on new independent families. Fingerprint-only improvements may exploit omitted existing facts but cannot distinguish identical input semantics by themselves.

A new versioned dataset/evaluation must reserve unseen source families. The current held-out split has been observed and cannot be reused as an untouched final test for a method designed from these failures. Compare frozen v0.1 against v0.2 on identical new inputs/judgments where valid, with preregistered mixed-gallery metrics, FPR/TPR, hard-negative robustness, compiler diversity, coverage and dependency-aware uncertainty. No numerical improvement is claimed and no new threshold or weight is adopted.

## 16. Completion boundary and human review

The corpus-level numerical audit, graph-level probes, source-linked case studies and roadmap are delivered. Fresh binary/Ghidra micro-extraction remains NOT COMPLETED due to the documented antivirus event; a full fresh micro-experiment acceptance claim is therefore unavailable. Review VALIDATION.md for the actual final regression status, rather than treating this limitation or earlier process-denied runs as passes.

Human review is required before implementing v0.2 or resuming the flagged binary probe in an approved environment. Do not start Step 11. Do not interpret this report as a freeze or production acceptance of the current classifier.
