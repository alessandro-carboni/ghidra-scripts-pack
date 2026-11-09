# High SSA value-flow view — 2026-11-06

This additive research view extends Step 10B. It does not replace the exact operational view, change the frozen structural v0.1 pipeline, infer source-level parameters, or introduce an LLM. Starting branch: codex; HEAD 4aeeed5264ca3b790feba104dc1c0eb6dbc935c8 (the user's commit includes the preliminary implementation).

## Motivation and scope

The development diagnostic on 27 previously observed routines/81 pairs measured positive mean set similarity 0.044028 and negative mean 0.043159. Unconditionally erasing storage slots raised both means to 0.168582 and 0.146754. That unsafe ablation is not deployed: it demonstrates sensitivity, not justified value equivalence. The corpus contains 536 linked inputs, including 291 register inputs, and 79 COPY operations out of 516 operations. Full diagnostic: development_divergence_audit.json.

The implementation normalizes only explicit recovered High SSA definitions, retaining unknown register/stack identities and existing conservative treatment of other unresolved boundaries. No HighParam mapping, memory-alias analysis, ABI inference, interprocedural summaries, or algebraic expression rewriting is added. Raw documents are explicitly rejected by the new command; legacy Raw/High commands remain available.

## Contract and rules

New contract: `osgf.value-flow-fingerprint/0.1.0`, embedding the unchanged validated OperationalFingerprint. New comparison: `osgf.value-flow-similarity/0.1.0`, embedding the original four-view comparison plus normalized set/multiset results and a fixed mean of exact/normalized operational scores. The mean requires both operands comparable. No production decision threshold is introduced; `decision` is null.

| Rule | Preconditions and transformation | Justification and provenance | Tests and limits |
|---|---|---|---|
| VF-DEF-01 | Input has exactly one validated recovered-SSA producer and register/unique storage, not stack; replace its physical kind/slot with width and bounded producer description | Dependency validator verifies producer output equals consumer input. Original operands/edges stay embedded | Renamed defined register/unique values match; unknown register inputs retain identity; width/constants/signedness remain distinct |
| VF-OUT-01 | Register/unique non-stack output becomes a width-qualified defined value | Producer operation is retained; physical allocation is not used to identify that produced value | Synthetic register-to-unique relocation; memory outputs remain separate |
| VF-COPY-01 | COPY has one linked input, equal input/output width, both register/unique non-stack, and an observed consumer; redirect consumers through the copy | Bit-preserving copy of the same observed SSA value; every removed operation maps to its surviving producer in contracted_copies; original network remains embedded | Copy-chain equality, no contraction for casts/width changes/stack destinations, no guessing through unresolved leaves; unused copies remain |
| VF-BOUND-01 | At most 64 copy hops; cycles/over-budget chains remain | No recursion or guessed cycle equivalence; copy_barriers records each retention reason | Cycle and long-chain regressions; resource exhaustion never means missing evidence |
| VF-COLOR-01 | Two fixed rounds of predecessor descriptor refinement | Producer descriptions avoid instruction addresses or extraction IDs as semantic identities. Operand order and same-producer input groups remain explicit | SUB/shift/inequality swaps differ; allowed commutative swap matches; same producer versus distinct producers distinguished. Bounded descriptions can still collide and are not whole-function equivalence proofs |
| VF-FEATURE-01 | Operation, directed dependency and bounded two-edge-path patterns on the retained network | Each occurrence points to source canonical operation handles; contraction ledger traces removed copies; counts equal occurrence multiplicities | Permutations, exact counts, valid references, repeated bytes, forged count/version/ledger rejection; original path budget retained and truncation reported |

Unknown parameters stay unknown. Incomplete extraction retains baseline support and null-comparison behavior; comparison completeness also checks the new path-truncation flag. Positive self-similarity does not imply complete evidence. CAST, extensions, phi nodes, INDIRECT, STORE and control operations are not contracted. COPY normalization applies to SSA value descriptions, not a rewrite of the executable or a proof that architectural register side effects are irrelevant in all contexts.

## Integration and commands

Implementation: rust_engine/src/value_flow.rs, imported by the isolated operational crate. CLI dispatch lives in runtime_operational.rs. Existing command outputs and semantic code are unchanged; the new commands are explicit opt-in extensions.

```powershell
cargo build --locked --manifest-path rust_engine/operational/Cargo.toml
& rust_engine/operational/target/debug/osgf_operational.exe value-fingerprint exact-operational-fingerprint.json new-value-fingerprint.json
& rust_engine/operational/target/debug/osgf_operational.exe value-compare query-value-fingerprint.json reference-value-fingerprint.json new-value-result.json
python -m pytest -q tests/test_value_flow.py
```

Output paths must not exist. Loaders reconstruct expected fingerprints from embedded source and reject tampering. New module/tool source and new dataset artifacts have scoped UTF-8/LF checkout rules; existing frozen-file attributes are not changed. Experimental implementation/executable hashes identify the actual recorded run and are not silently normalized on rebuild.

## Evaluation design

The old 27-case corpus is development-only. Method and executable hashes were locked before writing three new source families: weighted positional sum (discovery), byte population count (validation), and saturating accumulation (heldout). Each has source-proved equivalent and negative variants, compiled with GCC O0/O2 and MSVC O0. Families never cross splits. Source algebra plus deterministic independent Python arithmetic checks justify labels; analyzed PE programs are never executed.

The unchanged baseline evaluator runs real Ghidra extraction and A/B/C/D comparisons; evaluate_value_flow.py then tests exact operational, normalized, and their fixed equal-weight mean. Each condition selects its threshold only from discovery using the existing balanced-accuracy/highest-threshold tie policy. ROC-AUC, MRR, relevant-item Recall@K, ties, nulls, false-positive/true-positive rates, positive stability and negative exact collisions are reported. No parameter is tuned after scores are observed.

One family per split and correlated pairs make this a small investigator-authored pilot, not an external blinded benchmark or a population significance test. Two-round descriptors may become more specific and lose matches when upstream lowering differs; a higher average similarity is not itself success. Fresh and development results must be reported separately, including degradation. See FINAL_REPORT.md for actual outcomes and promotion decision.
