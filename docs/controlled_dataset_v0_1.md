# Controlled research data

The dataset is built before LLM tuning. Source contracts, compiler provenance and
behavioral counterexamples establish labels; OSGF similarity never establishes
ground truth. Source names, paths, hashes and exported symbols are identity and
provenance metadata, not scientific matching features.

## Corpus construction

```powershell
python scripts/controlled_corpus.py
python scripts/validate_controlled_corpus.py
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/extract_controlled_graphs.py --ghidra-dir C:/path/to/ghidra --engine rust_engine/target/debug/rust_engine.exe
python scripts/dataset_manifest.py datasets/osgf_pairs_v0_1/manifest.json --root .
```

Controlled C source lives under `samples/controlled/source`; builds under
`samples/controlled/builds` are local artifacts. The corpus records exact compiler
versions, flags, source/build SHA-256, PE architecture and runtime transcripts.
MSVC O0/O2 and GCC O0/O2/O3 are attempted when detected. Failed configurations are
explicitly recorded and never admitted as successful samples. Sixteen deterministic
input vectors per routine are checked by an independent Python oracle for pure
functions. API probes are checked for boolean status and agreement across builds
on the same host. The initial `read_file` probe checks file attributes;
`read_registry_value` probes opening the HKCU Software key; neither modifies files
or registry values. `create_socket` opens/closes an unconnected socket and balances
Winsock initialization. These probes intentionally expose limited, documented API
behavior rather than claiming full file/registry implementations.

Eight known System32 executables are copied into `samples/benign_realworld` with
hash/origin/architecture metadata. Originals remain untouched; these binaries are
validation material, never automatically positive pairs.

## Graph provenance and manifest

Ghidra's existing typed-evidence exporter analyzes actual compiled code. A small
research adapter exports symbols separately for source-to-anchor mapping. The Rust
`canonicalize-research-anchor` command reuses the seeded extractor's traversal,
evidence and truncation implementation with caller depth 0 and callee depth 3.
It needs an existing FUNCTION anchor and does not fabricate malware-style seed
evidence for benign routines. Canonicalization and fingerprint semantics are unchanged.

`manifest.schema.json` fixes the serialization contract; `dataset_manifest.py`
adds referential integrity, symmetric pair uniqueness and independent-ground-truth
checks. Sample/build metadata is normalized into catalogs; pair build references
resolve compiler/version/optimization/source hash/build hash without duplication.
Graph IDs bind executable hash, source routine and extraction configuration. Every
graph has canonical bytes, SHA-256, canonical digest and explicit mapping provenance.
Labels are exactly `equivalent` or `non_equivalent`. Missing references, unknown
families/splits, contradictory labels and nonexistent behavioral witnesses fail
validation. A same-source label requires identical source hashes and variant identity.

## Structural variants and negative pairs

Six source-level families have six examples each: transparent wrapper, fixed
function-pointer thunk, associative reduction splitting, contract-unreachable dead
branch, discarded pure helper call and linear delegation chain. Registry version
0.1.0 binds the original/transformed routine, parameters, rationale and validation.
The admitted domain is a readable buffer of 0–255 bytes with a trailing NUL;
unsigned arithmetic is 32-bit. There are 1,024 test inputs per transformed routine
(all lengths, four patterns), not exhaustive coverage of all byte sequences.
Equivalence relies on the source argument as well as independent oracle tests.
These are source transformations, separate from compiler variation and future
binary rewriting. Optimizers may erase a transformation; source metadata does not
promise a particular machine-code shape at every optimization level.

Negative pairs use actual same-harness runtime counterexamples, including explicit
input bytes and unequal results. The controlled API examples cover helper-mediated
calls, identical APIs with changed return values, opposite predicates on the same
literal, and single-call topology with different API evidence. These builds are
benign, pure string operations. MSVC is preferred for this small API corpus because
the local MinGW/Ghidra combination exposed import stubs as internal functions and
lost typed API evidence. The test suite checks the extracted API evidence, rather
than assuming source API calls guarantee exporter visibility. No OSGF score is
read by the label generators. Similarity collisions are valid evaluation outcomes.

## Splits

`split_config.json` is the deterministic source-component assignment. Every source
artifact, source group and derived variant stays in one split. Numeric and memory
artifacts are co-located because `sum_array` and `copy_buffer` have the same observable
byte-sum behavior. The two API length-plus-one implementations are also explicitly
near-duplicates. Exact source/body hashes and source paths are checked in addition
to these declared groups. This is a small controlled corpus, not a claim of exhaustive
semantic duplicate detection over arbitrary binaries.

`family_holdouts.json` contains six optional experiments. They exclude a family
from discovery/validation and select it in the existing held-out source groups.
They never move a variant of a training routine into test. Statistics distinguish
source groups, pairs, compilers, optimization levels, families and negative categories.
The partitions are intentionally small and category coverage differs by partition;
the API-focused negatives belong to validation, while text routines form held-out.

## Reproduction and review

```powershell
python scripts/rebuild_controlled_dataset.py --ghidra-dir C:/path/to/ghidra --engine rust_engine/target/debug/rust_engine.exe
python scripts/validate_dataset_acceptance.py --technical-only --replay
python scripts/dataset_review.py prepare
```

The rebuild uses deterministic generators, installed compilers and Ghidra; it needs
no LLM. The compiler inventory and failed configurations are recorded, so another
machine can produce a different available build matrix. Byte-identical binaries
are only expected with the same toolchain/environment; content-bound graph IDs
change with the binary. Keep the same toolchain for reproducing this exact catalog.
The initial machine lacked Clang and could not rebuild two locked MSVC O2 outputs;
those configurations were excluded, while GCC supplies O0/O2/O3 for every artifact.

`review/REVIEW.md` is a 14-pair human review packet. Source paths, routine names,
contracts, runtime witnesses and proposed rationales support the review. The human
fills `review_decisions.json` with reviewer, accept/reject/ambiguous, matching status,
notes and reason. Pending entries are not manually verified. Tests use synthetic
reviewers only in temporary directories and never populate the real review.

```powershell
python scripts/dataset_review.py check
python scripts/dataset_review.py freeze
python scripts/validate_dataset_acceptance.py
```

The freeze stores the full manifest snapshot, its digest and reviewed records.
Review records are an authoritative status overlay; the original manifest retains
its automatic-grounding provenance. A freeze is never overwritten. A revision must
name `--supersedes` and `--reason`, use a new output file, and preserve the prior file.
Changed manifest/pair content invalidates the old review. Rejected or ambiguous
held-out entries block freezing; remove them from the main evaluation and prepare
a new reviewed subset with all required categories before a revision. Existing
review files are never silently regenerated. Final acceptance fails when the review
or freeze is missing; `--technical-only` explicitly does not declare Step 8 complete.

Frozen Step 5–7 fixtures and golden digests are outside this dataset and unchanged.
Step 9 and LLM training are not part of this implementation.
