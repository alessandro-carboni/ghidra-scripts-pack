# Baseline Evaluation v0.1 — Step 10.0 technical audit

Date: 2026-10-21. Scope: **10.0 only**. No empirical OSGF scores, ranking metrics,
threshold selection, evaluation protocol freeze or Step 10.1 implementation.

Inspected branch `codex`, HEAD `c2fdcced4a19d583d72374a07bd0f5dfb1cda867`.
The working tree was clean before this audit. All changes for this step are new
Step 10 files. No reset, commit, push, Step 11 or frozen-data modification.

## Roadmap and inspected contracts

A repository file search found no dedicated roadmap/TODO document. The existing
Obsidian `TODO TESI.md`, discovered in the user's Sapienza vault, contains the same
Step 10 protocol supplied in chat. That protocol is the current scope authority;
this audit does not assume an additional roadmap exists. The protocol requires
one microstep followed by review. TODO is preserved pending that review.

Read: canonicalization_baseline_v0_1.md, fingerprint_baseline_v0_1.md,
similarity_v0_1.md, controlled_dataset_v0_1.md, transformation_harness_v0_1.md,
both Step 8/9 ACCEPTANCE.md files, dataset_manifest.py, dataset_splits.py,
step9_preflight.py, and actual Rust command routing/runtime/validation code.

## Immutable evidence and counts

`datasets/osgf_baseline_evaluation_v0_1/preliminary_audit.json` is explicitly
versioned preliminary audit evidence, not an evaluation protocol/results manifest.
It contains the exact Step 9 protected inventory of **161 physical file SHA-256s**:
all Step 8 dataset files, controlled C sources and all scientific golden fixtures.
It also pins the Step 9 baseline inventory itself, lists all sample binary references
and expected hashes, all catalog field names, and every query's independently judged
candidate IDs/pair IDs/labels for three clearly marked audit scenarios.

- Step 8 scientific digest: `095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2`.
- Exact manifest SHA-256: `0758de28ff2b49473b66de1dc90ab7561495eb1f84618114796f81a3be815c42`.
- Preliminary audit SHA-256: `2a9f746d9d8008bf0bc7c9d8f6b76cc13f5431dcbe0567583c0d35b921af683a`.
- Inventory matches Step 9's pinned baseline exactly. No golden or freeze updated.

All checkpoint counts match: **35 samples, 27 builds, 68 routines, 120 canonical
graphs, 218 labeled pairs**. All 120 canonical files and referenced controlled
sources are readable and hash-verified. All 35 sample binaries are additionally
present/readable locally and match their recorded SHA-256. These ignored binaries
are provenance/replay inputs, not required for later evaluation of already frozen
canonical graphs. Missing binaries on another checkout must be disclosed, not
misreported as newly validated runtime evidence.

| Split | Graphs | Pairs | Equivalent | Non-equivalent |
|---|---:|---:|---:|---:|
| discovery_train | 61 | 115 | 80 | 35 |
| validation | 27 | 39 | 26 | 13 |
| held_out_test | 32 | 64 | 45 | 19 |
| Total | 120 | 218 | 151 | 67 |

Manifest validation_status is automatically_grounded for all 218 records. The
separate frozen manual review has 14 accepted decisions; these facts must not be
conflated into a claim that all pairs were individually reviewed by a human.

The Step 9 six-build default run remains local/ignored (confirmed with git
check-ignore), and is not consumed by the Step 10 audit. It is an optional future
supplementary cohort, with discovery ancestry and two anchor graphs per PE.

## Field inventory and joins

| Meaning | Actual field/source |
|---|---|
| Pair identity and judgment | pairs[].pair_id, left_graph_id, right_graph_id, equivalence_label, validation_status, ground_truth.method/label/evidence or proof/counterexample |
| Pair category/family | pair_category, transformation_family, transformation_parameters; optional negative_category, negative_tags, difficulty |
| Pair source/split | source_group_id, source_group_ids, split; source-component split_config.json and split_protocol.configuration_sha256 |
| Graph identity | graphs[].graph_id, sample_id, routine_id, source_group_id, split, variant |
| Canonical artifact | graphs[].path, sha256 (physical bytes), canonical_digest (scientific content) |
| Source mapping | graphs[].typed_graph_sha256, anchor_function_id, mapping_provenance; full typed file path is not in this graph record |
| Build join | pairs[].left_build_id/right_build_id, or graphs[].sample_id -> samples[].build_id -> builds[].build_id |
| Compiler/provenance | builds[].compiler, compiler_version, optimization, flags, architecture, source_path/source_hash, build_hash, behavior/input, independent_environment_observation |
| Routine source | routines[].routine_id, artifact_group, source_group_id, source_path, body_sha256, optional contract/variant/provenance |
| Binary sample | samples[].path, sha256, origin, provenance, architecture, build_id (null for the eight unrelated benign System32 samples) |
| Canonical provenance | source_document, node_sources, edge_sources, unresolved_sources, provenance_map, coverage_ledger |
| Observability | local_graph_truncation; source_document.truncation, unresolved_calls, VISIBILITY_INDICATOR nodes/properties; frozen graph_signal_audit.json and evaluation_strata.json |
| Strata/holdouts | evaluation_strata.json binds manifest/audit hashes; family_holdouts.json preserves source splits |

Canonical source_document is the embedded, validated LocalSubgraphDocument. It can
provide the common local input for a future research adapter. A typed_graph_sha256
alone is not proof that the complete external Ghidra export is available. Source
names, symbols and labels remain provenance, not matching features. Preserve
anchor-only graphs and limited/unavailable observations; do not select by scores.

## No-Canonicalization gate — unsupported by the frozen CLI

main.rs routes to runtime_fingerprint.rs and runtime_similarity.rs.
Fingerprinting deserializes CanonicalSubgraph, then OsgfFingerprint::with_config
calls normalized_canonical, which verifies reconstruction. SimilarityComparison
validates both fingerprints against their canonical sources. canonical.rs validate
reconstructs the entire expected document from source_document, including facts,
IDs, provenance, coverage and versions. No option disables this contract.

Actual executable probes reject TypedGraph, LocalSubgraphDocument and a forged
canonical document in both commands; no fingerprint or comparison output is
admitted. The positive setup canonicalizes the existing local fixture and produces
its valid frozen fingerprint only; no Step 8 empirical score is computed.
The filename canonical_local_v0_1.json denotes a LOCAL fixture, not canonical output.

Research options for Step 10.2, **not implemented or approved here**:

1. Separate adapter on the same embedded local source, with identical structural
   roles, feature families/counts, motif budgets and Jaccard semantics for A/B.
   Explicitly toggle only the chosen semantic normalizations. Require B parity with
   the frozen engine and no-op A/B parity before accepting comparisons.
2. A separately versioned research module could reuse/refactor pure feature-building
   logic, provided the frozen CLI, schemas and goldens remain untouched. API/value
   node merging and structural ordering must be assessed as potential confounds.
3. If parity cannot be demonstrated, mark A unsupported and propose a named limited
   B-only or alternative study for approval. Byte comparisons or relabeled canonical
   fingerprints are not a No-Canonicalization control.

Structural ordering and caller/callee role assignment are preprocessing even in A.
Raw addresses must not become semantic features accidentally. API case/decoration,
constant/section normalization, multiplicities, unresolved observations and provenance
must be explicitly covered at the later gate. No adapter or new features exist here.

## Judged-gallery eligibility — counts, not retrieval results

Each graph is considered as a possible query. Only an explicit frozen pair supplies
a candidate and its label, symmetrically; no transitive equivalence inference and no
unjudged negative. Eligibility here means at least one judged positive, not score
comparability. Same-graph entries are forbidden. No query/reference partition or
ranking is selected yet. Query-specific galleries are generally different.

The 218 judgments cover only 218 of 2,677 possible within-split unordered pairs
(7,140 across the entire graph catalog). Therefore this can only support limited-
judgment retrieval, not population-wide retrieval. Future A/B common eligibility
also depends on successfully admitted comparable scores, not yet measured.

| Scenario / split | Positive-eligible queries | >=3 candidates | >=5 candidates | With both positive and negative |
|---|---:|---:|---:|---:|
| Graph identity only / discovery | 61 | 31 | 31 | 37 |
| Graph identity only / validation | 22 | 16 | 4 | 10 |
| Graph identity only / held-out | 31 | 16 | 15 | 19 |
| Exclude equal canonical digest / discovery | 40 | 10 | 6 | 12 |
| Exclude equal canonical digest / validation | 22 | 8 | 0 | 8 |
| Exclude equal canonical digest / held-out | 18 | 3 | 2 | 3 |
| Exclude same binary SHA-256 / discovery | 55 | 27 | 4 | 0 |
| Exclude same binary SHA-256 / validation | 16 | 12 | 0 | 0 |
| Exclude same binary SHA-256 / held-out | 27 | 15 | 2 | 0 |

Graph-identity-only eligible gallery-size histograms (size: query count):

- Discovery: 1:24, 2:6, 5:14, 6:13, 11:2, 12:2.
- Validation: 2:6, 3:12, 5:4.
- Held-out: 1:12, 2:3, 4:1, 6:13, 12:2.

There are six graphs without a known positive (five validation, one held-out).
The complete per-query evidence and all scenario histograms are in the JSON audit.
There are only 35 distinct canonical scientific digests among the 120 source-bearing
graphs; equal scientific content does not mean identical physical provenance.
Excluding every equal-digest reference can remove legitimate positive cases.
Similarly, all 67 negatives are same-binary different-routine counterexamples:
blanket same-binary exclusion removes every judged negative. Neither sensitivity is
an adopted policy. Step 10.1 must distinguish duplicate physical copies from valid
function-level same-PE comparisons and pre-register how galleries smaller than K
are marked unsupported. Unknown references must never be used to pad a gallery.

## Proposed isolated layout and stop gates

Created now: evaluation_preflight.py, test_evaluation_preflight.py, this document,
preliminary_audit.json, a directory-local .gitignore for runtime/, and .gitattributes
for deterministic LF audit metadata. `--write-audit` uses exclusive creation;
`--check` requires exact reproduction and never overwrites old evidence. Input
hash inventories are verified before derived data is accepted. Runtime command
logs/probes remain in ignored .build-cache/ or temporary directories.

Proposed later, NOT created: protocol.json and methodology in 10.1; approved research
adapter in 10.2; graph catalogs/fingerprints/scores/query galleries/results/runtime
observations in separate versioned later-stage directories; final freeze only 10.10.
The preliminary inventory is not a scientific evaluation freeze.

10.1 can be reviewed next, but must resolve duplicate/same-binary rules, gallery
eligibility and K>N treatment before protocol approval. Thresholds, primary metrics,
nulls, tie policy and uncertainty are not selected here. 10.2 is blocked until that
protocol is approved and A/B parity is demonstrated. No A/B result or downstream
retrieval claim may be reported before those gates. STOP after this audit.

See datasets/osgf_baseline_evaluation_v0_1/VALIDATION.md for actual commands/outcomes.
# Step 10.1 preregistration (2026-10-22)

Current progression: 10.1 completed; 10.2 approved by the user; 10.3 materialized
all 120 graphs in both conditions, with full source replay and an independent
byte-identical repeat. See
[`research_adapter/METHOD.md`](../datasets/osgf_baseline_evaluation_v0_1/research_adapter/METHOD.md)
for the precise intervention and limitations, and
[`CATALOG.md`](../datasets/osgf_baseline_evaluation_v0_1/CATALOG.md) for the 10.3
artifact contract. No Step 10 corpus pair scores or retrieval metrics have
been computed; 10.4–10.10 remain pending. Historical 10.0 status below is retained
as an audit trail rather than a description of the current implementation.

The user authorized inclusion of 10.1 before continuing through the later steps;
scientific admission gates remain mandatory. No benchmark scores have been read
or computed to choose this design. `protocol.json` is registered with SHA-256
`35a4d37ba175e1316e4f2bd179179da5da28e2c534bfb7a1fa1005ddabb040eb`.
Its schema locks every policy, input binding and eligible gallery. Re-registration
refuses to overwrite files. Loading verifies physical bytes, schema, current
protected inventory and recomputed judgments. Revisions require a new version
and rationale, never silently replacing these bytes.

Primary score: unweighted mean of comparable semantic Multiset Jaccards.
Per-view and aggregate Set Jaccards are secondary. Both-empty is null; one-empty
is zero; no comparable views means no score. Observability does not enter scores;
incomplete motifs remain included with warnings. Paired condition deltas require
identical comparable components. Similarity never creates a label.

Retrieval is **judged-gallery / limited-judgment evaluation**. Each endpoint of
an admitted frozen judgment is a query, references are only its directly judged
same-split neighbors. Unknown relevance is never a negative or a transitive
positive. Self and repeated physical functions (binary SHA + anchor function ID)
are excluded; same-PE distinct functions and equal-content graphs with distinct
provenance remain legitimate. Physical duplicate candidates retain the smallest
graph ID; contradictory labels fail. Every query needs a known positive.

Ranking uses primary score descending, then exact reference graph ID ascending.
A null candidate makes the entire query unavailable for scored retrieval; its
original gallery remains in coverage reports. A/B comparisons use common complete
queries and identical galleries. For K=1/3/5, K>N is explicitly unsupported/null.
Recall@K is known positives retrieved / all known positives in that gallery;
Hit@K is a separate binary indicator. MRR uses reciprocal rank of the first
positive. Macro means disclose query IDs and denominators separately per split/K.
Eligible query counts discovery/validation/held-out: 61/22/31; K>=3:31/16/16;
K>=5:31/4/15. Six queries have no positive and remain explicitly ineligible.

Threshold calibration uses discovery only: maximize balanced accuracy over
distinct discovery scores plus reject-all, choose the largest threshold on ties,
then freeze before validation/held-out. Score >= threshold predicts a match;
false-match rate is negative scored pairs predicted match / scored negatives.
Both classes are required. A/B calibration uses the same eligible discovery IDs.
Positive and negative distributions report counts, mean, median, extrema and
linear-interpolated quantiles without treating nulls as zeros.

Churn is descriptor symmetric-difference / union (presence) and sum absolute
count differences / sum maximum counts (multiplicity); empty unions are null.
Align exact descriptors, not hashed IDs, and only approved mappings across
conditions. Rank stability requires identical references: normalized absolute
rank difference, top-K overlap/K, and Spearman with average tie ranks. Undefined
correlations and K>N remain null. Source/compiler/signal strata remain separate.

Uncertainty uses frozen connected source/artifact/near-duplicate components,
never independent-pair resampling. Fewer than ten independent clusters supports
descriptive summaries only. Otherwise the registered paired cluster bootstrap
uses 2000 replicates, seed 101 and percentile intervals; undefined replicates are
reported. No test-set tuning or unqualified significance claims are permitted.

Runtime design fixes one warmup and five repetitions, alternating A/B order,
monotonic nanoseconds, common cohorts and explicit stage boundaries. Startup and
language differences are confounds; shared Ghidra cost is excluded. Cache hits
are not execution timings. Timing data is separate from deterministic scientific
artifacts. All 218 judgments remain the intended pairwise cohort. Condition A
is still unadmitted until Step 10.2; this protocol does not assert adapter parity.


## Evaluation commands and result boundaries (Steps 10.4–10.10)

The approved research control is bound by research_adapter/approval.json.
Earlier pending statements describe the preregistration stage, not current approval.
From the repository root, after both pinned engines and the admitted catalog exist:

```powershell
python scripts/evaluation_pairs.py --score
python scripts/evaluation_pairs.py --verify
python scripts/evaluation_galleries.py
python scripts/evaluation_metrics.py
python scripts/evaluation_stability.py
python scripts/evaluation_stratification.py
python scripts/evaluation_runtime.py --observation-id runtime-001
python scripts/evaluation_replay.py
python scripts/evaluation_acceptance.py
python scripts/evaluation_acceptance.py --freeze
```

Creation commands refuse collisions. Derived result commands recompute and require
identical existing bytes. A mismatching result is an error, never an instruction to
replace expected hashes. A freeze requires the completed regression-command record
and a second fresh-directory replay. No command commits, pushes or starts Step11.

Pair scores preserve original directional provenance. Rankings may reuse the
symmetric numeric value in reverse, with an explicit original score-record pointer.
Unknown relationships are absent, never negative. A null candidate excludes the
whole query, and K above gallery size remains unsupported. Six positive-free queries
per condition remain in coverage. Recall and Hit are different metrics; K-specific
denominators are explicit. Discovery thresholds are persisted before other metrics.

Cross-condition descriptor churn lacks an approved mapping and is unsupported.
Feature churn within each condition retains observability and truncation qualifiers.
Family holdout tables preserve frozen memberships; family-specific FPR is unsupported
because no family-excluded calibration protocol was registered. Six independent
source components permit descriptive summaries only, not inferential intervals.

Runtime observations are separate immutable experiment files. The same debug engine
bytes are used for A/B and fresh-directory replay. Adapter/extraction cannot be split
inside the approved A executable, so the primary matched stage combines both; B-only
substage measurements are diagnostic. Process startup and IO remain explicit costs.
Memory RSS and fresh Ghidra extraction are not claimed. No benchmark should run
concurrently with regression/replay work initiated by this evaluator.

The fresh-directory replay copies source files and pinned executable bytes, then
regenerates catalog and pair artifacts, verifies exact bytes, and recomputes derived
outputs. It is not a fresh compiler build or hosted clean-checkout CI run.
The final freeze separates scientific identity from variable runtime observations.
Detailed limitations and failure examples accompany acceptance; the benign dataset
supports function-equivalence evaluation, not a malware or LLM effectiveness claim.
