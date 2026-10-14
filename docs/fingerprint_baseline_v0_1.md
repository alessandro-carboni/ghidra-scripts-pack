# OSGF Fingerprint Baseline v0.1

Frozen on 2026-10-13. `OSGF_FINGERPRINT_VERSION = "0.1.0"`.
Input: verified CanonicalSubgraph 0.1.0 from Canonicalization Baseline v0.1.
No similarity score, capability interpretation, classification or LLM call is
part of this stage.

## Command

```powershell
cargo build --locked --manifest-path rust_engine/Cargo.toml
.\rust_engine\target\debug\rust_engine.exe fingerprint-canonical canonical.json fingerprint.json
```

The command creates:

- `fingerprint.json`: portable fingerprint with four views, canonical support
  references, coverage metadata and two SHA-256 digests.
- `fingerprint.json.provenance.json`: source-bearing sidecar linking every
  feature occurrence through its canonical elements to original source
  collection/index/property pointers. It embeds the original local document
  and canonical source Coverage Ledger, and binds to the fingerprint digest.

Input and either output must be different files. Both outputs are validated
and serialized before writing. Invalid input creates neither output. The two
filesystem writes are not a cross-file transaction: an I/O failure is reported
as failure and may leave a sidecar without the new fingerprint; rerun after
correcting the filesystem problem.

Optional limits:

```powershell
.\rust_engine\target\debug\rust_engine.exe fingerprint-canonical canonical.json fingerprint.json --max-topology-motifs 1024 --max-interaction-motifs 2048
```

## Views and counting

| View | Feature families | Count meaning |
| --- | --- | --- |
| Rooted topology | Root roles and caller/callee distance distributions | Number of functions supporting each descriptor |
| Rooted topology | Directed function-call relations | Source call occurrences |
| Rooted topology | Anchor-containing two-edge paths and incoming/outgoing forks | Structural motif instances; each contributes one |
| Typed evidence | Function-role to API, literal string, constant or section | Source edge occurrence count |
| Typed evidence | Explicit FUNCTION → STRING → STRING_CATEGORY chains | Structural chain instances; each contributes one |
| Interaction | Function call followed by typed evidence or a string-category chain | Structural motif instances; each contributes one |
| Observability | Indirect calls, unresolved-indirect calls, explicit dynamic dispatch | Indicator records; observed site counts are descriptor facts |
| Observability | Unresolved call records | Source unresolved occurrences |
| Observability | Extraction completeness and canonical coverage summary | One metadata observation |

This preserves the structural-count correction in commit `3496abe`: motif and
category-chain counts are **not products of callsite counts**. Direct relation
and typed-evidence occurrence counts remain available in their own features.
Descriptors contain role/distance facts, explicit relation types and normalized
evidence, never original addresses. Category chains require both explicit edges.
Rooted paths use a node-equality pattern to preserve cycles. Interaction motifs
record whether the call is recursive.

The observability view is separate from all three semantic views. Unknown site
lists remain `null`, not zero. Unresolved records have no invented target.
An unconnected visibility indicator has an unknown owner. Missing evidence is
not interpreted as a hidden API or capability. Changes limited to visibility
or extraction-completeness metadata do not change the semantic payload when
the observed semantic graph is unchanged.

## Limits

The default retains at most 4096 topology motif instances and 4096 interaction
motif instances, before aggregation into features. Each limit can be 0–100000.
Length is fixed: two call edges for rooted paths/forks; a function call plus
an evidence edge, optionally followed by a category edge, for interactions.

Retention uses the lexicographic descriptor/support order established in step
6.8. Structural candidates all have multiplicity one. Counts are not weights
or importance rankings. Each motif family records enumerated, retained,
omitted and truncated counts. These limits do not suppress root-role,
function-relation, direct typed-evidence or observability features.

The existing enumeration budget is 1,000,000 checks per motif family. Exceeding
it fails without emitting a partial fingerprint. Technical truncation metadata
and provenance remain outside the semantic comparison payload.

## Determinism, digests and provenance

Features are identified by SHA-256 of `[view, descriptor]` compact JSON. Equal
features aggregate counts while retaining each supporting occurrence. Views
are sorted by feature ID and support occurrences are sorted deterministically.
Canonical node/edge/unresolved array permutations are accepted after checking
the complete input against reconstruction from its source. Other malformed or
tampered canonical data is rejected, not silently repaired.

The portable document contains no source paths, original addresses, raw source
IDs or timestamps. Equivalent canonical scientific input, including relocated
copies, produces byte-identical portable fingerprint JSON. The sidecar changes
with source provenance and must travel with its own sample; it must not be
reused solely because another sample has an equal fingerprint digest.

Digest definitions use UTF-8 compact JSON with lexicographically sorted object
keys (array ordering is specified above):

- `semantic_digest`: SHA-256 of an object containing `schema_version`,
  `canonicalization_version`, `rooted_topology_view`, `typed_evidence_view` and
  `interaction_motif_view`.
- `fingerprint_digest`: SHA-256 of the complete portable document except its
  own `fingerprint_digest` field. It includes the semantic digest, observability,
  source canonical digest, technical metadata and canonical provenance index.

Neither digest is a similarity score. Different full digests can have equal
semantic digests because observability or metadata differ.

Every canonical node, edge, unresolved record and supported metadata marker
appears in `canonical_coverage`, either represented by feature IDs or excluded
with a deterministic reason. Unattached evidence is retained in the canonical
source rather than silently becoming a feature. `source_coverage_totals`
propagates the previous stage's totals. The sidecar retains its full ledger,
including evidence excluded before fingerprinting.

`validate_against` rebuilds the fingerprint against its canonical source and
checks the complete result: features, counts, ordering, IDs, coverage,
configuration, supports and digests. Sidecar validation also compares all
resolved origins and embedded source data.

## Acceptance

```powershell
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
python scripts/test_fingerprint_baseline.py
python scripts/test_fingerprint_baseline.py --canonical-dir reports/canonical-notepad-step5
```

On Linux/macOS pass `--engine rust_engine/target/debug/rust_engine` after
building. CI runs both canonicalization and fingerprint acceptance suites.

The checked-in `canonical_local_v0_1.json` and
`fingerprint_v0_1_digests.json` freeze the input and expected digests. Python
hashlib independently verifies both hashes. Acceptance covers relocation,
reordering, repeatability, semantic-change sensitivity, observability separation,
full traceability/coverage, limits, malformed-input rejection, no score/labels
or fabricated targets, and preservation of the user's structural counting fix.
Real-data replay runs each supplied canonical Notepad document twice.

Changes to these scientific semantics or serialization require an explicit
version and acceptance-fixture update. Similarity remains the next roadmap stage.
