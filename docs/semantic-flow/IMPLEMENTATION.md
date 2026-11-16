# Recovered semantics research views — 2026-11-09

Scope: requested items 2, 3/7 (one deduplicated effect implementation), 4, 5, 6, 8 and 9. Item 1 is the existing multilevel implementation. These are additive opt-in Python research commands alongside the unchanged Rust operational commands. They do not replace the default or assert function equivalence. No LLM integration is included.

## Recovered parameters and CFG

The new `osgf.recovered-evidence/0.1.0` envelope embeds the unchanged validated High evidence, its exact canonical-JSON digest, parameter occurrences, CFG blocks and operation-to-block membership. Existing P-code schemas and extractors were not edited. A wrapper captures primitive evidence while Ghidra's HighFunction is alive, before the original extractor disposes the decompiler.

A parameter occurrence is admitted only when Ghidra reports a HighParam, nonnegative slot, input Varnode, no SSA definition, matching full width and symbol offset -1 (whole symbol). Inconsistent slot/storage mappings are discarded with a warning. No parameter names or function names enter semantic features. Slot and width replace storage only for these occurrences; other boundaries remain unresolved physical storage. This is decompiler-recovered evidence, not trusted ABI truth. It does not infer argument permutation or aliases.

Sources: [Ghidra HighParam API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighParam.html) and [HighVariable implementation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/HighVariable.java). The local real preflight used Ghidra 12.0.4 and recovered two parameter occurrences for each of three previously observed routines, with complete CFG mapping.

## Effect-centered slice (items 3 and 7)

Roots include RETURN, STORE, calls, LOAD, INDIRECT, indirect branches, unsupported operations and explicit memory/stack destinations. LOAD is retained because alias, volatility and trapping behavior are not proved. Backward closure includes recovered SSA predecessors and controlling predicates. Control dependence uses postdominance over recovered basic blocks with a virtual exit. Incomplete, over-budget or non-exiting CFGs retain all conditions conservatively.

This is ordinary recovered-CFG control dependence, not a proof of termination-sensitive equivalence. Cycles and expression-depth/visit bounds remain explicit barriers; the implementation does not rewrite loops. Missing effects, incomplete call recovery or alias information cannot be treated as proof of absence. Indirect and memory effects carry warnings. The full source and retained/root/guard operation IDs remain available.

RETURN input zero is the control destination, not the returned payload. Return payload features use subsequent inputs and record whether one was recovered. Void and unrecovered returns are not inferred equivalent from payload absence. Loads retain output width; direct memory destinations retain their exact storage. See the [P-code operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html).

## Algebraic rules

`osgf.semantic-flow-fingerprint/0.1.0` carries five separate views: physical-expression baseline, parameter-normalized expressions, effect expressions, algebra-normalized effect expressions, and semantic role families. Expression nodes are content-addressed and retain widths, exact constants, signedness and operand order. Only documented commutative integer comparisons/operations sort inputs. Expression depth is fixed at 8, visits at 100,000 per view; truncation/cycles cannot claim complete evidence.

Algebra uses equal input/output widths of one to eight bytes: addition/subtraction by zero, multiplication by one, AND by the full mask, OR/XOR by zero, and constant folding of ADD/SUB/MULT/AND/OR/XOR modulo the output bit width. Equal-width COPY forwarding is separately logged. No cast/extension, signed division, floating-point, memory, alias or loop rewriting is performed. Every applied rule retains source operation IDs in a ledger. Tests include exhaustive 8-bit neutral identities and explicit overflow/width/cast guards. They are not a whole-program formal proof.

The semantic-family view separately describes effect/control/data roles, operation family/opcode, signedness, input/output widths and constants. It is a coarse complementary view; it is not pooled silently with expression features and cannot prove equivalence. Provenance is excluded from semantic digests but included in serialized fingerprints; loaders reconstruct the entire expected fingerprint before comparison.

## Audits

`audit_semantic_layers.py` audits aligned immutable pair labels. It reports Pearson and average-tie-rank Spearman correlations, equal-score counts, class-specific common/complementary errors, and fixed leave-one-out means. Threshold-transfer tables retain discovery-only calibration, distributions by class, confusion counts and explicit reject-all cases. There is no heldout threshold optimization or automatic promotion.

On the historical value corpus's heldout slice, depth0/depth1 Pearson is 0.977986 and Spearman 0.967327; all three levels have the same four false positives and ten false negatives at their respective discovery thresholds. On the older operational corpus, depth1/2 reject all 15 positives at those thresholds. Thus high ranking metrics can coexist with poor threshold transfer; these observed-corpus audits are descriptive, not independent validation.

## Prospective benchmark protocol

The generic extraction/scoring/evaluation method and executable were locked before new source files were authored. Six new behavior families are partitioned as complete families (two per discovery/validation/heldout). Each has a source-proved equivalent implementation and a foil flipping output bit zero. All arguments are unsigned 32-bit scalars with no environmental input. Each family's independent Python arithmetic oracle checks 1,051 corner/random tuples; this does not execute or empirically prove the compiled target.

GCC O0/O2 and MSVC O0 produce 18 binaries and 54 routine cases. Fresh Ghidra projects supply both original operational/multilevel and new semantic fingerprints. Same-build pairs are excluded. Source-family labels, not similarity, define ground truth. Cross-family negatives are included and same-family performance is reported separately.

Eight conditions are fixed: exact, multilevel, physical, parameters, effects, algebra, families and combined. Primary combined score is the equal mean of the existing exact/multilevel mean and the algebra-effect score; it requires both. The primary threshold maximizes discovery TPR subject to discovery FPR <= 0.05, then prefers lower FPR and higher threshold. A separate unchanged balanced-accuracy calibration is reported for diagnosis. No validation/heldout result chooses a condition or threshold. A discovery FPR constraint is not a test-set guarantee.

This is a new internally authored prospective pilot, not externally blinded independent replication. Only two source families per split and correlated builds limit statistical inference. No population-level significance or near-perfect recall is promised. After scoring, no method tuning is allowed in this study. Any later change requires a new study.

## Commands

```powershell
python scripts/semantic_flow.py fingerprint recovered.json --output new-fingerprint.json
python scripts/semantic_flow.py compare query.json reference.json --output new-comparison.json
python scripts/audit_semantic_layers.py datasets/osgf_multilevel_flow_v0_1/value_corpus_results.json --output new-audit.json
python -m pytest -q tests/test_semantic_flow.py
```

Outputs must be new. Real benchmark data/runtime tools are not added as generic CI dependencies. New unit and fixture-level tests run in the normal Python suite. See FINAL_REPORT.md for actual commands/results and DONE TESI synchronization.
