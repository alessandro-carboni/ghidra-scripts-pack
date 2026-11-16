# Proposed deterministic v0.2 — human approval required

No change below has been implemented or shown to improve generalization. The current held-out cohort is now diagnostic development material, not an untouched final test. v0.1 artifacts and results remain frozen.

## Design review A–J

| Direction | Evidence / required information | Version and provenance contract | Main risks | Independent gate / complexity |
|---|---|---|---|---|
| A. Improve fingerprint on the same graph | ROOT-LOCAL-GRAPH-01; role/distance-sensitive features already available | New fingerprint identity; retain source supports for every feature | Invariance may collapse real call-layout differences; cannot separate identical input representations | Source-proven wrappers plus structurally similar hard negatives; medium |
| B. Preserve already extracted facts | Edge-context synthetic probe; direct/indirect flags and context API names exist upstream | New fingerprint contract; distinguish observed fact from inferred meaning | Compiler-dependent or heuristic context can introduce false distinctions; context association is not argument dataflow | Mutate one real supported fact at a time, verify provenance and negative controls; medium |
| C. Seed and local boundaries | 41 low-positive comparisons; helper/runtime context varies | Version extraction configuration and seed coverage; preserve explicit-anchor diagnostic route | Narrow boundaries lose behavior; broad boundaries include unrelated runtime evidence | Same inputs with preregistered context policies and coverage accounting; medium/high |
| D. Evidence support / abstention | ROOT-OBSERVABILITY-01: 32 score-one negatives use topology alone | Version decision policy separately from similarity; missing evidence stays unknown | Abstention can hide hard cases and lower coverage; sparse genuine positives remain important | Report risk versus coverage, preserve all anchor-only cases, independent acceptance/abstention oracle; medium |
| E. Complement Jaccard | Correct math; overlapping class distributions; exploratory min-view is not a solution | New score version, development-only fitting, separately frozen calibration | Reweighting cannot repair identical features; optimizing current held-out outcomes overfits | Fixed comparisons on new family-disjoint validation; no claim from post-hoc threshold sweep; medium |
| F. Intraprocedural CFG/P-code | ROOT-EXTRACTION-01; arithmetic and predicates absent from current schema | New typed graph schema, operation identities, block/edge provenance, explicit analysis failures | Compiler lowering creates false distinctions; overly broad abstractions erase predicates | Independent arithmetic/predicate counterexamples plus compiler-equivalent routines; high |
| G. Constants, operations, dataflow | Current constants are API-window selected, not routine-wide semantics | Bit widths, signedness, operations and use-def provenance; no alias inference without evidence | Literal overfitting, relocation constants, overflow and undefined-behavior confounds | Unsigned/defined C contracts, boundary values, value-use association and negative witnesses; high |
| H. Discrimination plus invariance | Both score-one negatives and low positives exist | Version feature composition; transformation applicability/observability remain explicit | Invariance that removes distinguishing behavior; compiler-specific signatures | Paired source-proven transformations AND same-shape non-equivalent controls; high |
| I. Hard-negative coverage | 67/67 negatives within the same PE; six components | New independently grounded dataset, immutable labels before similarity | Shared scaffolding or witnesses can leak labels; finite tests alone do not prove equivalence | Independently authored families, cross-binary hard negatives, witness and source review; medium/high |
| J. Retrieval and evaluation | 48/114 eligible galleries positive-only; constant control competitive | Version judgments and gallery eligibility; unknown relevance remains unknown | Easy positives inflate MRR; unjustified global negatives bias retrieval | Mixed judged galleries, stable K denominators, constant/random controls and family-aware uncertainty; medium |

All directions are hypotheses about a stronger deterministic foundation, not permission to optimize the current dataset. An LLM must not be credited with reconstructing semantics never observed by extraction. Any later LLM comparison requires the same new input evidence, galleries and provenance constraints as its deterministic control.

## Phased roadmap and gates

### Phase 0 — approve scope and restore reproducibility

Objective: human review of this audit and the antivirus-limited real experiment. Components: audit scripts, host execution environment, versioned proposal. No production changes. Gate: diagnostic replay, unchanged freeze inventories, all feasible acceptance checks, explicit disposition of the blocked micro.exe probe. Preserve every v0.1 golden and report. No blanket antivirus exception is a research requirement.

### Phase 1 — evidence contract and counterexamples

Objective: specify the minimum intraprocedural facts needed to distinguish arithmetic and predicate witnesses. Components: Ghidra typed exporter, graph schema/loader, source-reference validation. Expected behavior: different defined operations/predicates remain distinguishable, with absent analysis represented as unknown. Independent tests: fresh controlled PE extraction in an approved environment, source/mathematical oracles, malformed provenance, overflow/signedness boundaries, indirect/unresolved calls. Risks: Ghidra/compiler variance and schema migration. Gate: approved v0.2 schema plus deterministic extraction on multiple compilers; no scoring claim yet. v0.1 stays readable and byte-identical.

### Phase 2 — fingerprint and context robustness

Objective: construct source-supported discriminative descriptors and test helper-layout invariance. Components: local-subgraph policy, fingerprint/motif generation, provenance sidecars. Expected behavior: useful semantics survive wrappers and optimization without merging negative predicates. Independent tests: seven micro-case families, duplicate-edge versus occurrence accounting, relocation, input permutation, controlled truncation, deliberate non-equivalence. Risks: path explosion and over-normalization. Gate: preregistered synthetic acceptance plus versioned runtime/memory budgets and complete provenance; no production replacement based only on micro-tests.

### Phase 3 — scoring and evidence support

Objective: distinguish sparse structural agreement from sufficiently supported semantic comparisons. Components: versioned similarity/decision interfaces, null/support reporting and discovery calibration. Independent tests: exact math oracles, no-positive galleries, ties, null/empty views, abstention coverage, no hidden score-dependent exclusion. Risks: selective reporting and calibration overfit. Gate: policy locked on development/validation families before final test; unchanged v0.1 scores remain available for paired reference.

### Phase 4 — new controlled evaluation

Create a separate `osgf_baseline_evaluation_v0_2` identity only after approval. Add independently authored routine families, cross-binary same-shape negatives, API/constant/section stressors, rich and sparse cases, compiler/optimization diversity and Step 9-style transformations. Group all descendants, equivalent source bodies and shared artifact dependencies before splitting. Reserve genuinely unseen source components, with labels and binaries sealed before model selection; external malware evaluation is a separate domain claim, not implied by benign controlled results.

Preregister primary mixed-gallery MRR/Recall@K with fixed denominators, FPR/TPR at a development-selected operating point, hard-negative and cross-compiler results, coverage/null/abstention rates, feature churn, rank stability, time, memory and determinism. Include all-gallery results as secondary context. Compare v0.1 and v0.2 on identical new inputs/judgments wherever contracts permit; explicitly state any extraction-coverage changes. Use source-component-level paired uncertainty, with enough independently sampled components before inferential intervals. Never treat 218 correlated pairs as 218 independent experiments.

Proposed acceptance principle, requiring approval rather than a claimed numeric improvement: better hard-negative discrimination at the preregistered sensitivity/support target, no hidden loss of coverage or equivalent-routine robustness, uncertainty compatible with a practically meaningful improvement across unseen families, and all provenance/regression gates passing. Set numerical targets before observing the new test cohort. If component coverage is insufficient, report descriptive results and defer the generalization claim.

### Phase 5 — consider LLM only after deterministic review

Gate: human acceptance of the untouched deterministic v0.2 evaluation. Specify any LLM intervention separately, preserve deterministic fallback, record model/input versions and source-supported transformation justifications, and compare against the same stronger deterministic baseline. Step 11 is not started by this audit.
