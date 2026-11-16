# Observable-seeded reference retrieval: controlled pilot

Date: 2026-11-12. Starting HEAD: `ff4e097351d0b64e0f9f03bede98d0d5db7c41fe`, branch `codex`.

## Scope and interpretation

The technical system performs source-validated local-subgraph retrieval against a curated reference library. The scientific experiment below is a **single authored benign lineage**, not a malware corpus, blind replication or independent heldout evaluation. Its labels distinguish resolution of `GetCurrentProcessId` from resolution of `GetTickCount`, declared from source contracts before scoring. They do not assert a broader malicious capability. The target binaries were compiled and statically analyzed, never executed.

Three annotated regions per binary supply a three-reference gallery and three query regions: subject/equivalent share the source contract, while foil resolves another export through the same API. This produces five positive and four negative directed pairs. All automatic query seeds are searched, including unannotated runtime/library regions; only the explicitly annotated regions enter supervised metrics. Seed-count and annotation availability are reported separately. The no-seed arithmetic probe is present but does not receive an invented anchor.

Comparisons reuse frozen A, existing graph-first B, original P-code C, new directional coverage D and existing optional refinement E. No original representation or P-code rule was changed. E's continuous score is B, with a separately evaluated ranking refinement. Missing operational comparisons are null, not zero. MRR=0 in an entirely unavailable condition is the unconditional retrieval convention, not a measured similarity or a comparison-quality estimate.

All pilot data remain discovery-only because they share a source lineage. Classification numbers describe fitted discovery thresholds, **not heldout false-positive rates**. Cross-compiler experiments measure retrieval/score transfer; separately fitted discovery thresholds are not proof of threshold transfer. Pair counts cannot be treated as independent subjects. No confidence intervals or superiority claims are supported by this sample size.

## Observed mechanism and failure analysis

In the GCC O0→O2 experiment, positive scores are 1 for A/B/D. Different-symbol negatives score approximately 0.644444 (A), 0.566667 (B), and 0.75 (D). The same negatives have API coverage 1 and string coverage 0.5; the base-evidence denominator contains two APIs and two literals, of which one literal differs. This is direct evidence that API-only matching cannot discriminate this particular hard negative. It does not isolate a causal benefit of graph relationships from the benefit of distinctive strings.

Operational C preserves some positive pairs at 1 but scores the optimized subject/equivalent against the unoptimized equivalent at 0.083333, below some negatives at 0.333333. Its GCC AUC is 0.70 and its discovery threshold loses two of five positives. Thus a hard P-code acceptance gate would remove genuine source-contract matches preserved by graph evidence in this pilot. The existing optional refinement does not remove candidates and preserves graph score semantics.

In GCC→MSVC, C has AUC 0.425 and MRR 2/3 while graph A/B and coverage D retain AUC/MRR 1 on the annotated regions. The best balanced-accuracy discovery threshold for C predicts no positives (TP=0, FN=5, FP=0, TN=4). A zero false-positive count here is therefore not useful discriminative performance. Do not present it as a successful detector.

Moving the subject observation into a separate query callee exposes a limitation shared by all five conditions: AUC falls to 0.70, while MRR remains 1 and the discovery threshold loses two of five positive pairs. The existing automatic seed moves to the effect-bearing callee; fixed caller/callee extraction bounds change the observed context. Directional value coverage does not automatically eliminate this context sensitivity. Source-region mapping is downstream of detection, and all query seeds remain searched. This experiment is exploratory and correlated with the optimization pilot, not another independent lineage.

| Transition | A AUC | B AUC | C AUC | D AUC | E AUC (B score) | MRR A/B/D/E | MRR C |
|---|---:|---:|---:|---:|---:|---:|---:|
| GCC O0 reference → GCC O2 query | 1 | 1 | 0.70 | 1 | 1 | 1 | 1 |
| GCC O0 reference → MSVC O2 query | 1 | 1 | 0.425 | 1 | 1 | 1 | 0.6667 |
| GCC O0 reference → GCC O2 helper-layout query | 0.70 | 0.70 | 0.70 | 0.70 | 0.70 | 1 | 1 |

Each row has nine directed pairs, three annotated queries and a three-region reference gallery. Across these correlated pilots there are 27 directed comparisons, not 27 independent subjects. All fixed-input reruns match byte-for-byte. Annotated-region recovery is 3/3 per build; automatic query seed counts are respectively 5, 11 and 5, with 2, 8 and 2 unannotated seeds still searched. No arithmetic no-seed probe was selected. Unknown regions are not assigned negative labels.

Every detailed ranking retains full query/reference provenance, separate matched/missing/additional evidence, operational comparison and observability. For the GCC negative example, unknown indirect-call/dynamic-dispatch observations remain warnings. They are not interpreted as known zeros or used to lower semantic scores. There are no contextual constants or section features in that example; their coverage is null, not perfect agreement.

Recall@1 here is relevant-reference recall, not hit rate: a query with two true gallery references can retrieve at most half of them at rank 1. Consequently mean Recall@1 is 2/3 even when every query has a true first hit and MRR=1. Recall@3 and @5 have a gallery of only three entries and are correspondingly weak tests.

## Answers to the research questions

1. **Directional behavior:** exact mathematical tests establish the reference denominator, multiplicity and empty-view semantics. This pilot has equal base feature cardinalities, so it is not itself a strong directional asymmetry experiment.
2. **Malware-associated retrieval:** untested; no authorized independently annotated malware samples were supplied or fetched.
3. **Evidence-value matching:** separates these source-defined symbol-resolution regions, but adds no observed retrieval improvement over A/B in this pilot.
4. **Relationships versus API-only:** API-only overlaps on all hard negatives; full evidence separates them. A relationship-specific advantage remains unproven without a controlled ablation that holds literal evidence fixed.
5. **Complementary P-code:** operational differences are measurable; no added retrieval benefit is demonstrated here.
6. **Lost true matches:** observed under a P-code-only discovery threshold. E preserves candidates rather than treating disagreement as a behavioral contradiction.
7. **Best method:** no general winner. A/B/D tie on these small tasks, C is weaker on the compiler transitions, and all methods degrade under the helper layout.
8. **Seed failure:** measured separately in the machine-readable pilot receipts. Deliberate no-seed probes stay unselected; unannotated automatic seeds remain visible.
9. **Useful categories:** strings are directly discriminative here, APIs alone are not; constants/sections/categories cannot be ranked for usefulness from unavailable evidence.
10. **Compiler/variant transfer:** GCC optimization and GCC→MSVC retrieval have actual observations. They do not establish transfer to unrelated source families or to malware.
11. **Indistinguishable false positives:** an API-only collision is directly observed. Broader structural collisions require a larger independent corpus.
12. **Supported versus unproven:** engineering integrity, exact arithmetic, deterministic fixed-input reruns and this limited benign retrieval experiment are supported. Malware relevance, broad false-positive control, heldout calibration and a general improvement over the original baseline remain unproven.

## Reproduction and evidence

See `BENCHMARK_PROTOCOL.md` for implemented PowerShell commands. `PILOT_RESULTS.json` records the actual experiment summaries, pair scores, seed accounting, source/binary hashes and detailed ranking file hashes. Local full artifacts remain under the recorded `.build-cache/reference-library-pilot-*` paths. They can be regenerated with the runner; no binary needs to be committed. Compiler output timestamps and compiler versions can change binary bytes on rebuilding: byte determinism is asserted for repeated comparisons of the **same inputs**, not arbitrary future recompilation.

The first sandbox compiler launch failed with WinError 623. A separately authorized native launch succeeded. A subsequent O2 Ghidra DWARF import error was preserved, not suppressed; fresh builds without DWARF completed. The historical antivirus-quarantined graph-first study was neither modified nor resumed. These are distinct execution histories.

## Outstanding scientific work

Acquire or author independent, separately grouped lineages covering broader file/network/administrative observations, unresolved behavior and difficult shared-library negatives; preregister genuinely separated discovery, validation and heldout data. Include a targeted relationship ablation and enough independent groups for uncertainty estimates. Real-malware admission additionally requires authorization, isolated static handling and analyst annotations independent of OSGF scores. These limitations are not resolved by passing synthetic tests or by this small benign pilot.
