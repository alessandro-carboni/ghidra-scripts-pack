# Transformation Harness v0.1.0

Step 9 generates controlled benign source variants, independently checks behavior,
and records what the compiler and Ghidra actually preserve. It prepares artifacts
for future Step 10 experiments; it does not perform fingerprint robustness scoring,
LLM training, binary rewriting or similarity-based labeling.

## Using the completed harness

The default versioned experiment selects frozen `sum_array`, all six families,
seed 9 and MinGW GCC O0. It produces one source/executable per family, with original
and transformed entry points in the same PE. Each build checks 1,024 inputs against
an independent Python oracle. Ghidra produces one full typed graph per PE and Rust
extracts two canonical anchor subgraphs (caller depth 0, callee depth 3).

Required for the complete example: Windows, Python 3.11+, pytest/Ruff, the Rust
engine built with the locked Cargo dependencies, MinGW GCC producing runnable PE,
and Ghidra with a working PyGhidra headless launcher. Tool paths are configurable.
MSVC integration exists through the existing compiler inventory; its Step 9 matrix
was not exercised in this acceptance run. Clang was unavailable. Portable Python
unit tests and pure C family tests do not substitute for the Windows PE integration.

Run these PowerShell commands from the repository root on branch `codex`:

```powershell
# Set this to your actual installation; the placeholder is not an example path.
$env:GHIDRA_HOME = '<GHIDRA_INSTALLATION>'
$engine = 'rust_engine/target/debug/rust_engine.exe'
$config = 'datasets/osgf_transformations_v0_1/config/default.json'
$run = 'datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9'

cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json --ghidra-dir "$env:GHIDRA_HOME"
python -m pytest -q tests/test_transformation_schema.py
python scripts/transformation_harness.py generate --config $config
python scripts/transformation_harness.py build --run $run
python scripts/transformation_harness.py extract --run $run --ghidra-dir "$env:GHIDRA_HOME" --engine $engine
python scripts/transformation_harness.py map --run $run --engine $engine
python scripts/transformation_harness.py validate --run $run --engine $engine --split-policy datasets/osgf_transformations_v0_1/config/split_policy.json
python scripts/replay_transformation_harness.py --run $run --ghidra-dir "$env:GHIDRA_HOME" --engine $engine
python scripts/transformation_harness.py report --run $run --engine $engine

# Equivalent orchestration, including a fresh isolated compiler/Ghidra replay:
python scripts/transformation_harness.py run --config $config --ghidra-dir "$env:GHIDRA_HOME" --engine $engine --fresh-replay
```

Check `$LASTEXITCODE` after each command when composing a script. The unified `run`
command stops on a failed/incomplete phase, preserves failure records, and emits a
failure report when the phase has returned structured diagnostics. Missing external
tools are not accepted as empty valid graphs. Generation/build/extract/report CLI
commands return nonzero when their requested admission is not successful.

`build` performs independent behavioral validation before publishing a PE;
`validate` executes the PE again and compares exact input vectors, oracle results and
transcripts, re-derives source bytes, reconstructs canonical bytes with Rust, and
checks mapping and split evidence. `report` revalidates successful runs before
writing deterministic `report.json` and `report.md`. Per-run acceptance is distinct
from the repository regression evidence in `datasets/osgf_transformations_v0_1/ACCEPTANCE.md`.

## Parameters and supported source contracts

All families require an explicit pure-byte contract: readable nonvolatile input,
length 0..255, trailing NUL, unsigned 32-bit result, no concurrent mutation or
externally observable effects. Environmental/OS routines are explicitly unsupported.
The generator accepts only fixed templates and validated parameter values, not C
snippets. Every output carries its original frozen source/body provenance and proof
obligations; source-level expected equivalence is never automatically marked verified.

| Family | Main parameters | Observable scope |
|---|---|---|
| transparent_wrapper | depth 1..8; direct delegation | Surviving function identities and calls |
| thunk | depth 1..8; fixed-pointer delegation | Resolved calls and indirect-call visibility |
| function_splitting | 2..8 balanced contiguous partitions; proven reduction | Surviving helper/call topology |
| dead_branch | `n > 255`; bounded constant payload; entry insertion | Source proof only; graph has no branch guards |
| harmless_strand | 1..8 unsigned pure strands; discarded result | Helpers/calls if preserved; not a semantic effect |
| instruction_reordering | left/right permutation of independent partition reductions | Source proof only; graph has no instruction order |

Common parameters are stable-hash naming and `noinline` or `allow_inline` hints.
Splitting/reordering require a known associative sum/xor/max reduction with zero
empty identity. Unsupported search/weighted reductions are rejected explicitly.
The seed affects deterministic names; it is not an unrecorded random experiment.

## Records, artifacts and reproducibility

Seven strict record types separate specification, generation, build, behavior,
graph, mapping and run state. Four versioned JSON Schema documents are checked
against their runtime contracts. IDs derive from the actual configuration/source/
toolchain inputs; references and artifact hash inventories must be complete.

Each local `runs/run-<id>/` contains `sources/`, `binaries/`, `extraction/`,
`generation.json`, `manifest.json`, `splits.json`, `validation.json`, optional
`fresh_replay.json`, and the two reports. Original/derived source and PE artifacts
are never overwritten on rerun: existing bytes are verified. Interrupted staging is
retained outside admitted runs; an unexpected pending manifest fails closed.
Failures remain recorded and are not automatically retried as new successful runs.
A changed configuration creates a different run; a conflicting artifact requires
investigation rather than deleting evidence or weakening its hash.

All run bundles are ignored by Git because the validated PE and full evidence must
travel together. Code, schemas, baseline inventory, configuration and acceptance
records are versioned. On a fresh checkout run the commands above to create a complete
local bundle. Do not commit an incomplete run manifest while omitting its binaries.
Ghidra projects, raw tool output, compiler staging and replay workspaces remain under
ignored `.build-cache/`; no personal paths enter versioned scientific metadata.

Serialization is UTF-8/LF JSON with sorted keys; exact generated C compilation bytes
are CRLF. Ghidra JSON is converted to the declared LF serializer before initial hash
registration. Canonical bytes are the existing Rust serializer output. Physical
SHA-256 hashes, canonical `sha256:` digests and frozen scientific JSON digests are
separate fields. No normalization retroactively replaces compiled-source provenance.
The fresh replay regenerates sources, recompiles, re-executes the oracle, reanalyzes
with Ghidra and compares artifact hashes, IDs, build/behavior/graph/mapping records,
splits and validation bytes. Same-environment reproducibility was verified; different
compilers/OS libraries/Ghidra releases are not assumed to produce identical binaries.

## Mapping, observability and experimental isolation

Mapping levels are source, generated function, binary function, typed graph and
canonical subgraph. Source/binary associations describe controlled derivation, not
isomorphism or a proof of functional equivalence. Graph relations use exact source
identities within the same analyzed PE, coverage ledgers and provenance maps. Shared
edge claims must preserve types and mapped endpoints. One-to-one, one-to-many,
many-to-one, unmatched, unknown and ambiguous relations are represented explicitly.
Unmatched introduced functions and unknown observations remain in the report.

The six-family example observed wrapper, thunk, splitting and strand call topology.
Dead branch and instruction order are `not_observable` in this graph abstraction.
Absence alone never implies `optimized_away`; no such case was asserted in the real
run. Compiler inlining/merging, unresolved calls and traversal depth may limit what
can be established. Anchor-only graphs are retained and never filtered to improve
results. No similarities or labels are generated by Step 9.

Derived variants inherit frozen source components and roles. Source group, artifact,
exact source hash, routine body and declared near-duplicates cannot cross splits.
The guard reuses Step 8 leakage validation and rejects duplicate/reversed pairs and
cross-split references. Held-out artifacts are evaluation-only, not parameter-selection
material. Family holdouts filter the inherited partitions and never move sources.
The default example contains only discovery data, so all complete family-holdout
views honestly report `unsupported` for missing validation/held-out partitions.
The supported pure templates exclude the frozen validation partition's OS/API
routines; a complete real holdout experiment requires separately justified
support rather than reassigning frozen sources.

## Scientific limitations and future use

Finite oracle coverage is not a universal equivalence theorem. The supported pure
source templates are a small controlled subset, not arbitrary C/C++ transformations.
Source proofs, executable tests and graph observations answer different questions.
No malicious sample, LLM, learned label or similarity threshold is used. Step 10 may
consume these separately validated artifacts for robustness, holdout or rewrite
experiments, but those experiments are not implemented here.

## Implementation and verification journal

The dated entries below record what was verified at each microstep. Statements such
as “not yet run” refer to that historical point; current evidence is in ACCEPTANCE.md.

## Frozen boundary and initial audit (9.0)

Development branch: codex. Initial HEAD: 47810b07328652c54538a88cb530802f768f9bc3.
The initial working tree is clean. Step 8 final acceptance passes with 35 samples,
27 builds, 68 routines, 120 canonical graphs, 218 pairs and 14 accepted reviews.
Freeze scientific digest:
095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2.
This differs from the physical freeze-file SHA-256.

All of datasets/osgf_pairs_v0_1 is read-only. The preflight also inventories
controlled source bytes and Rust scientific fixtures. A missing or inconsistent
freeze, manifest, human review, source hash or canonical hash fails closed. It
reports unrelated working-tree changes and never resets or repairs them.
The baseline inventory is stored in the separate Step 9 dataset, not in Step 8.
Ignored local executables are validated separately by Step 8 final acceptance.

## Reuse and isolation

| Existing component | Reuse / boundary |
|---|---|
| controlled_corpus.ROUTINES, compiler_inventory | Original C implementations and discovered toolchain identity; never invoke its dataset-building main |
| controlled_variants.variant_source / FAMILIES | Semantic precedent for wrappers, thunks, splitting, dead branches, pure strands; Step 9 adds bounded parameters and reordering rather than calling the fixed Step 8 generator |
| controlled_build.build_pe, pe_architecture, sanitize_text | Isolated staging, bounded access/compile retries, oracle-before-publication, portable diagnostics |
| validate_controlled_corpus.expected | Independent Python oracle; unavailable oracle must remain unsupported |
| validate_structural_variants.validate | Existing 1,024-case input domain and baseline regression |
| export_research_graph.py | Real typed graph and exported symbols with input binary hash |
| dataset_artifacts.analyze / register_graph | Study extraction and mapping protocol; their hardcoded Step 8 destinations prevent direct use. The Step 9 adapter reuses the exporter/engine in its own workspace |
| extract_controlled_graphs.py | Reference PE export to anchor association; no Step 8 registration from new runs |
| canonical.rs / local_subgraph.rs / local_subgraph_schema.rs | Existing canonicalize-research-anchor, caller/callee traversal, unresolved/truncation and provenance contracts; unchanged |
| fingerprint.rs / similarity.rs | Frozen scientific contracts, regression only; never labeling or mapping proof |
| dataset_manifest.validate, dataset_review.content_hash / validate_decisions | Pinned manifest/reference and human review validation |
| dataset_splits.validate_leakage / family_holdout | Frozen components and source-preserving holdout policy |
| validate_dataset_portability.verify | Exact CRLF source hashes and LF JSON/audit/strata bindings |
| validate_dataset_acceptance.py | Read-only final acceptance of the existing freeze |
| rebuild_controlled_dataset.py | Must not run during Step 9; it would target frozen Step 8 |

## Implemented data flow

| Component | Input | Output |
|---|---|---|
| Transformation contracts | Versioned JSON and frozen references | Strict validated records, explicit expected vs verified status |
| Source generator | Routine, contract, parameters, deterministic seed | Exact source bytes, proof obligations, source-level mapping |
| Orchestrator | Experiment configuration and pinned freeze | Bounded stable plan, isolated run, explicit unsupported/failure records |
| Build and behavior validator | Generated source and compiler matrix | Validated PE, exact hashes, independent original/variant/oracle transcripts |
| Ghidra adapter | Verified binary and local tool paths | Actual typed graph, symbols, canonical subgraphs and observability |
| Mapping | Source relationships plus verified graph provenance | Separate source/binary/typed/canonical relations, unknown/unmatched/ambiguous retained |
| Split guard | Frozen components and derived ancestry | Inherited splits, held-out isolation, explicit family holdout support |
| Acceptance validator | All records and exact artifact bytes | Positive/negative/integration checks with PASS/FAIL/BLOCKED |
| Reporter | Validated run records | Deterministic counts, failures, limitations and reproducibility commands |

Artifacts are generated only under datasets/osgf_transformations_v0_1, with
temporary build/Ghidra work under .build-cache/step9-extraction and .build-cache/step9-replays. Metadata uses UTF-8/LF,
sorted keys and repository-relative paths; source bytes retain explicit CRLF.
No machine paths enter scientific identifiers. Exact physical hashes and scientific
JSON/canonical digests have distinct fields.

The six requested families are transparent wrapper, fixed-target thunk,
source/function splitting, contract-dead branch, harmless strand, and conservative
independent-operation source reordering. Linear chains are configurable wrapper/
thunk depth, not an extra substitute for reordering. Compiler survival and graph
observability remain separate from source generation and behavioral equivalence.

## Commands

```powershell
python scripts/step9_preflight.py --ghidra-dir '<GHIDRA_INSTALLATION>'
python scripts/dataset_review.py check
python scripts/validate_dataset_acceptance.py
python -m pytest -q tests/test_step9_preflight.py
```

Environment availability is detected, not assumed. A verified installation is
distinct from a successful Step 9 extraction. No additional dependency is required
for preflight; later real build/extraction stages must explicitly report missing tools.

### 9.0 evidence

PASS: 13 preflight tests; real Step 8 review check and FINAL ACCEPTANCE PASS.
161 protected files inventoried in datasets/osgf_transformations_v0_1/baseline.json.
Python 3.11.2, pytest 9.1.1, Ruff 0.15.6, Cargo/Rust 1.94.0, MSVC
19.44.35225 x86 and MinGW GCC 6.3.0 available. Ghidra 12.0.4 installation
and launcher verified; Step 9 extraction not yet executed. Clang unavailable.
No frozen file changed. The temporary Git test initially exposed a CRLF
alternates-file issue, corrected to explicit LF before the successful rerun.

## 9.1 versioned contracts — PASS

Seven strict record types cover specifications, generation executions, builds,
behavior observations, graph extraction, mappings and experiment runs. Four
Draft 2020-12 JSON Schema documents mirror the stdlib validator; additional
scientific record fields are rejected. Cross-reference validation distinguishes
expected equivalence (never verified by default) from observed validation.
Explicit enums represent failures, unavailable evidence and mapping cardinalities.
Exact source/binary/graph hashes, scientific canonical digests and frozen-reference
identities remain separate. JSON serialization rejects NaN, sorts keys, emits UTF-8/LF;
ordered arrays retain their meaning and the orchestrator will order catalog records.
Parameters remain objects whose family-specific safety checks belong to 9.2.
Artifact evidence resolution belongs to later build/extraction/mapping validators.
Step 9 attributes specify LF metadata and CRLF C; Step 8 attributes unchanged.
Tests: 26 schema tests plus 13 preflight tests, all PASS; Ruff PASS; all 161
baseline file hashes unchanged. No build or graph execution claimed by schemas.

## 9.2 controlled source families — PASS

Six families use known pure Step 8 source bodies and explicit parameter dictionaries.
Wrapper/thunk depth and strand counts are bounded 1..8; splitting uses 2..8 balanced
contiguous partitions with proven sum/xor/max combination and zero empty identity.
Dead branches only accept the proven n>255 guard. Harmless strands use discarded
unsigned scalar arithmetic. Reordering swaps two pure disjoint partition reductions;
it rejects side effects, dependency templates and uncertain aliasing. Search/weighted
reductions without the required partition proof are explicitly unsupported.
All emit source-level expected mappings and obligations, never binary observations.
Naming/seed/preservation parameters are deterministic; generated C bytes use CRLF.
Tests: 21 PASS, including 18 real GCC O0 executables across six families and three
routines, each checking all 256 lengths against original, variant and independent
reference arithmetic (4,608 input cases). This is family integration only; the
1,024-case run/build protocol and real Ghidra pipeline are subsequent steps.
Ruff PASS; frozen baseline inventory unchanged.

## 9.3 deterministic generation — PASS

The generate command validates the pinned freeze, source/body hashes, explicit
contracts, parameters, bounded variant/build counts and compiler matrix. Plans sort
selections before deriving stable IDs. Generated C includes a 1,024-case dual-output
harness; this stage generates but does not run it. Source and metadata hashes bind
the published run. Interrupted staging remains isolated and is never admitted.
Existing runs are re-derived and verified, never overwritten. Traversal and reparse
redirection are rejected, including an actual Windows junction tested after symlink
creation proved unavailable. The canonical digest schema was aligned with the real
Step 5 sha256: prefix (physical file hashes remain plain hexadecimal).
Default configuration generated six variants in run-aba4cd955a9a4166b0e0d6c9;
two consecutive CLI generations produced the same ID and verified existing bytes.
Tests: initial combined harness/preflight 24 PASS and one symlink privilege skip;
replacement real junction test PASS with 26 schema regressions (27 PASS). All 12
harness cases and 13 preflight cases have passed across these runs. Ruff PASS.
Frozen inventory unchanged; no build/extraction claimed yet.

```powershell
python scripts/transformation_harness.py generate --config datasets/osgf_transformations_v0_1/config/default.json
```

## Step 9.4 — compilation and independent behavior validation — PASS (2026-10-20)
Implemented scripts/transformation_build.py and build CLI, with isolated PE staging, bounded retries, exact source/binary provenance, explicit compiler/access/validation failure records and independent 1,024-input behavioral oracles. Added tests/test_transformation_build.py and tightened behavior/specification cross-references. Existing validated artifacts are verified and preserved.
Actual commands (PowerShell, repository root):
```powershell
python -m pytest -q tests/test_transformation_build.py tests/test_controlled_build.py tests/test_transformation_schema.py
python -m ruff check scripts/transformation_build.py scripts/transformation_harness.py tests/test_transformation_build.py
python scripts/transformation_harness.py build --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9
```
Results: 51 tests and 143 subtests PASS; Ruff PASS. Six actual GCC O0 builds PASS, one for each family, 6,144 independent input cases / 12,288 original-transformed outputs. Repeated build command verifies and retains all six artifacts. Frozen baseline comparison: all 161 protected files unchanged. MSVC/other optimization matrices and Ghidra extraction were not executed in this microstep. No Step 8 metadata, labels, splits, golden, commit or push changed.
Next: Step 9.5 real Ghidra extraction and canonical provenance validation.

## Step 9.5 — real Ghidra extraction — PASS (2026-10-20)
Created scripts/transformation_extraction.py, tests/test_transformation_extraction.py and extract CLI. Reused unchanged export_research_graph.py and Rust canonicalize-research-anchor (caller 0/callee 3). Six real GCC O0 PE binaries analyzed in isolated Ghidra 12.0.4 projects: 12/12 canonical graphs admitted, exact binary provenance, anchor identities, typed and canonical hashes, coverage ledger and truncation retained. Each canonicalization was repeated and compared byte-for-byte; a second extract CLI reconstructed all registered canonical bytes successfully. JSON exported by Ghidra is serialized as LF before initial registration; compiled CRLF source provenance is untouched. Toolchain source hashes and Rust executable hash recorded separately.
Observations: wrapper, thunk, splitting and harmless strand have observed helper/call topology. Dead branch and instruction reordering are explicitly not_observable at this typed-graph abstraction; no optimized_away inference from missing symbols. Ghidra emitted external-library export-cache warnings; no external library was imported as experimental input. Symbols are identity provenance, never equivalence evidence.
Actual PowerShell commands:
```powershell
python scripts/transformation_harness.py extract --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9 --ghidra-dir "$env:GHIDRA_HOME" --engine rust_engine/target/debug/rust_engine.exe
python -m pytest -q tests/test_transformation_extraction.py
python -m pytest -q tests/test_step9_preflight.py tests/test_transformation_schema.py tests/test_transformation_families.py tests/test_transformation_harness.py tests/test_transformation_build.py
python -m ruff check scripts/transformation_extraction.py tests/test_transformation_extraction.py
```
Results: extraction 12 PASS; 20 extraction tests PASS including actual graphs and timeout/partial/missing/invalid cases; 84 previous Step 9 regressions PASS; Ruff PASS. Initial adapter field-name error was corrected before successful execution. All 161 protected baseline files unchanged. No Step 8/golden/labels/splits changes. Next: Step 9.6 evidence-based mappings.

## Step 9.6 — verified provenance mappings — PASS (2026-10-20)
Created scripts/transformation_mapping.py and tests/test_transformation_mapping.py; added map CLI. Five distinct levels: source derivation, generated function declarations, observed controlled binary identities, typed local evidence, canonical provenance. Source associations do not claim graph isomorphism or equivalence. Shared graph elements are matched only through exact source identities within the same analyzed PE, including coverage ledger and provenance maps. Extra generated functions are unmatched; insufficient observations remain unknown. Structural edge claims check mapped endpoints and type. All cardinalities are supported; ambiguous relations remain explicit.
Commands executed from repository root (PowerShell):
```powershell
python -m pytest -q tests/test_transformation_mapping.py
python -m ruff check scripts/transformation_mapping.py tests/test_transformation_mapping.py
python scripts/transformation_harness.py map --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9
```
Results: 17 tests PASS including real Ghidra mappings, reordered input determinism and corrupted/dangling/false correspondence rejection. Ruff PASS. Actual mapping statistics: 25 original and 87 transformed element references across levels; 30 verified provenance relations, 18 unmatched elements, 24 unknown elements, 0 ambiguous relations, 10 one-to-many relations. These are descriptive counts, not equivalence scores. Repeating map re-derives and verifies identical records. A relative-path CLI issue was corrected and covered by regression. Frozen inventory unchanged. No labels/splits/golden changes. Next: Step 9.7 inherited splits and leakage prevention.

## Step 9.7 — split inheritance and leakage prevention — PASS (2026-10-20)
Created scripts/transformation_splits.py, tests/test_transformation_splits.py and config/split_policy.json. Reuses frozen dataset_splits.validate_leakage. Derived variants retain source routine/group/artifact/hash/body, transitive source component and frozen split. Exact duplicates, near-duplicates and shared artifacts cannot cross splits. Pair validation rejects reversal, duplication, self pairs and cross-split graph references. Family holdouts are filtered experiment views; they never move sources. Held-out role is evaluation-only, with no parameter selection.
Actual commands (PowerShell):
```powershell
python -m pytest -q tests/test_transformation_splits.py
python -m ruff check scripts/transformation_splits.py tests/test_transformation_splits.py
python scripts/transformation_harness.py validate --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9
```
Results: 17 tests PASS, including inheritance from real frozen held-out count_digits source; Ruff PASS before final added regression. Real default run: six discovery executions and six original/transformed pairs; zero validation/held-out executions. Therefore all six family-holdout experiment views are explicitly UNSUPPORTED for this run (missing partitions), not falsely covered. Holdout filtering behavior separately tested on complete fixtures. Frozen inventory unchanged. At this microstep validate performs split admission only; combined acceptance follows in 9.8. Next: full regression/acceptance and deterministic replay.

## Step 9.8 — full acceptance and fresh end-to-end replay — PASS (2026-10-21)
Created scripts/validate_transformation_harness.py, scripts/replay_transformation_harness.py and tests/test_validate_transformation_harness.py. Combined validation now re-derives source bytes/IDs, checks complete artifact inventories and requested build matrix, replays each executable against the independent oracle, reconstructs canonical bytes with Rust, re-derives mappings and verifies inherited splits. Empty phases cannot be forged as PASS. All six families have one actual GCC O0 build, 1,024 independent cases and two real canonical graphs each.
Actual results recovered from the completed executions on 2026-10-20: full Python suite 261 PASS / 175 subtests; Rust 252 PASS; canonical acceptance 7 PASS; fingerprint acceptance 11 PASS; similarity acceptance 20 PASS; 25/25 real Notepad graphs deterministic (75 comparable views; 10 graphs with observability warnings). Ruff, cargo fmt/clippy/build, git diff --check all PASS. Step 8 review check verified 14 decisions; final dataset acceptance and leakage validation PASS, including 36,864 existing structural oracle checks.
After tightening admission checks: 62 targeted harness/schema/build/validation tests PASS, including the additional negative and replay tests. Fresh replay rebuilt all six binaries and reran Ghidra in an isolated workspace. Sources, IDs, compiler metadata, PE hashes, behavioral transcripts, typed/canonical graphs, scientific digests, mappings, split reports and validation reports match exactly. On 2026-10-21 the comparison was extended to the complete scientific artifact hash inventory: PASS. The temporary workspace pointer was removed from derived replay evidence and retained in the local diagnostic archive; no compiled bytes, scientific IDs, graphs or frozen metadata changed. All 161 baseline protected files remain unchanged.
PowerShell commands used (repository root):
```powershell
python scripts/transformation_harness.py validate --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9 --engine rust_engine/target/debug/rust_engine.exe
python scripts/replay_transformation_harness.py --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9 --ghidra-dir "$env:GHIDRA_HOME" --engine rust_engine/target/debug/rust_engine.exe
python -m pytest -q tests/test_transformation_harness.py tests/test_transformation_schema.py tests/test_transformation_build.py tests/test_validate_transformation_harness.py
pwsh -NoProfile -File .build-cache/step9-regressions.ps1
```
Local logs: .build-cache/step9-live.log, .build-cache/step9-regressions.log and step9-regressions-results.json. Full individual regression commands are recorded in the repository acceptance document. Run bundles (including required PE outputs) are now wholly local/ignored, avoiding an incomplete tracked manifest without its binaries; versioned configuration and code regenerate them on a fresh checkout. No commit/push or Step 10. MSVC/O2/O3 Step 9 integrations NOT RUN; Clang unavailable. Family-holdout views of the default discovery-only run remain UNSUPPORTED; dead branches/instruction ordering remain not_observable at the graph level. Next: Step 9.9 unified CLI, deterministic report and final documentation.

## Step 9.9 — final delivery — PASS / STEP 9 COMPLETED (2026-10-21)
Implemented scripts/transformation_report.py and tests/test_transformation_report.py. Unified CLI now exposes generate/build/extract/map/validate/report/run; incomplete phases stop with nonzero exit codes and explicit failure evidence. Actual unified run completed against all six families. JSON and Markdown reports derive their counts from admitted artifacts; unsupported holdouts and unavailable observations remain explicit. Completed docs/transformation_harness_v0_1.md and datasets/osgf_transformations_v0_1/ACCEPTANCE.md, including the full list of 30 new repository files and two modified existing files (.gitattributes, .gitignore), PowerShell reproduction commands, architecture and limitations.
Actual latest results: full Python suite 273 tests PASS and 175 subtests PASS; final targeted evidence suite 57 PASS after strengthening observability/truncation/toolchain tamper rejection (three additional cases, counts overlap and are not additive). Reporter tests 8 PASS. Explicit Ruff check and format check of all 21 new Python files PASS. git diff --check PASS. Existing verified Rust result remains 252 PASS, with fmt/clippy/build and Steps 5-7 acceptance suites PASS; no Rust/golden change since those executions.
Real run: six GCC O0 builds, 6,144 independent cases, 12 canonical graphs from six real Ghidra typed exports. Fresh full replay reproduced scientific artifact hashes, IDs, metadata, graphs, mappings and validation bytes. Final reports re-generated byte-identically; hashes: report.json fae063c1affe1da64d54655dafdd5bf74e1400e0ea63454bc7c6ea2ab257ee94; report.md a1249a73adf63fb545ea876770526e4d2f2c1a32b4ee77f96586ebb6cd512232. All 161 protected baseline files unchanged. Branch codex and HEAD 47810b07328652c54538a88cb530802f768f9bc3 unchanged. No tracked Python caches, unexpected changes, commits or pushes.
Commands actually executed for this microstep (PowerShell, repository root):
```powershell
python -m pytest -q tests/test_transformation_report.py
python scripts/transformation_harness.py run --config datasets/osgf_transformations_v0_1/config/default.json --ghidra-dir "$env:GHIDRA_HOME" --engine rust_engine/target/debug/rust_engine.exe
python scripts/transformation_harness.py report --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9 --engine rust_engine/target/debug/rust_engine.exe
python -m pytest -q tests
python -m pytest -q tests/test_transformation_extraction.py tests/test_transformation_mapping.py tests/test_validate_transformation_harness.py tests/test_transformation_report.py
python -m ruff check scripts/step9_preflight.py scripts/transformation_*.py scripts/validate_transformation_harness.py scripts/replay_transformation_harness.py tests/test_step9_preflight.py tests/test_transformation_*.py tests/test_validate_transformation_harness.py
python -m ruff format --check scripts/step9_preflight.py scripts/transformation_*.py scripts/validate_transformation_harness.py scripts/replay_transformation_harness.py tests/test_step9_preflight.py tests/test_transformation_*.py tests/test_validate_transformation_harness.py
git diff --check
```
Limitations: Step 9 MSVC/O2/O3 end-to-end matrices and hosted/non-Windows CI NOT RUN; Clang unavailable. Default real run is discovery-only, so complete family holdouts remain UNSUPPORTED. The current pure-template subset excludes the frozen validation partition's OS/API routines. Dead branch and instruction order are not_observable in the typed graph; no optimized-away case is invented. No global equivalence beyond the stated source/input contract. Unknown/unmatched mappings retained. No Step 10 implemented.
Resume checkpoint: Step 9.0 through 9.9 are complete and ready for user review. No implementation microstep remains. Final review document: datasets/osgf_transformations_v0_1/ACCEPTANCE.md. Local detailed run report: datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9/report.md. Await user review; do not automatically start Step 10 or commit/push.
