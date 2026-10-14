# Canonicalization Baseline v0.1

Frozen contract: `CANONICAL_SUBGRAPH_VERSION = "0.1.0"` and
`CANONICALIZATION_VERSION = "0.1.0"`. Source contracts are LocalSubgraphDocument
0.1.0 and TypedGraph 0.12.0. This stage is independent of legacy enrichment,
scoring, capability interpretation and the optional GUI.

## Run

```powershell
cargo build --locked --manifest-path rust_engine/Cargo.toml
.\rust_engine\target\debug\rust_engine.exe canonicalize-local-subgraph local.json canonical.json
```

The input is one exported local subgraph, not a raw report or manifest. The
command validates the source, constructs and validates the canonical document,
and writes the output only after these checks succeed. Input and output must
be different files. Local input arrays may be permuted; duplicate source
nodes/edges/unresolved records are rejected under the source contract.

## Scientific identity and provenance

`scientific_value()` consists of the four version fields, canonical nodes,
canonical edges, unresolved observations and local truncation metadata. The
SHA-256 digest covers its compact UTF-8 JSON with lexicographically ordered
object keys. It identifies an exact scientific payload for regression and
scientific cache keys; it is never a similarity or maliciousness score.
Do not reuse another sample's provenance by caching the entire document by this
digest alone.

`seed_id`, `anchor_function_id`, `source_document`, the three `*_sources` maps,
`provenance_map` and `coverage_ledger` are source metadata, outside scientific
identity. Relocation changes these fields while leaving the scientific payload
and its digest unchanged. Reordering an otherwise identical input produces an
identical complete canonical JSON document.

Functions have ANCHOR, CALLER, CALLEE or BOTH roles with independent caller and
callee distances. Local node IDs come from exact labeling of the colored,
directed multigraph, with partition refinement and individualization of
ambiguous cells. Node facts, edge types/facts and unresolved observations color
the graph. Source IDs never enter the scientific comparison key. Automorphic
nodes can exchange provenance mappings under relocation without changing the
scientific graph. All original functions remain distinct.

The labeling search has an explicit budget of 100,000 search states and a
maximum individualization depth of 256. Exhaustion returns an error; there is
no approximate result, address tie-break fallback or silent truncation.

## Frozen normalization policy

| Evidence | v0.1 policy |
| --- | --- |
| API | ASCII case folding, `module!symbol` or `module.dll.symbol`, `__imp_` prefix and `_symbol@digits` decoration. No semantic aliases; A/W and Nt/Zw remain distinct. |
| String | Preserve exact text, including case, whitespace, NUL and Unicode. Raw value lives in provenance; normalized text and existing STRING_CATEGORY nodes remain separate. No inferred categories. |
| Constant | Preserve integer literal. Only `memory_protection` values 4 / 64 with matching source symbolic names gain PAGE_READWRITE / PAGE_EXECUTE_READWRITE semantics. Unknown constants remain literal. |
| Section | Explicit read/write/execute/initialized flags; structural role executable, initialized_data, uninitialized_data or unknown. Names and legacy judgments remain provenance. |
| Visibility | Indirect, unresolved-indirect and explicit dynamic-dispatch site counts remain separate; missing lists stay unknown rather than becoming zero. |
| Unresolved call | Caller and observed flags/occurrences only; no target field. Original reason and callsite remain provenance. |
| Truncation | Preserve source resource limits, depth metadata and source counts separately from evidence. |

All seven supported edge types remain explicit. Edge occurrence counts and
normalized source context APIs are retained. API/constant/category value nodes
may be shared when their normalized facts are identical. Every source node
and every edge occurrence remains traceable. Function, string, section and
visibility nodes are not merged; neither are edge or unresolved occurrences.
This avoids accidentally fusing distinct topological relationships.

Only contract-defined unordered property arrays are sorted. Arbitrary extension
arrays retain their original order. Malformed properties interpreted by the
normalizer are rejected. Missing supported evidence values receive explicit
coverage exclusions, including any incident edges whose endpoint was excluded.

## Coverage and validation

For each canonical element, `provenance_map` identifies source collection/index
and JSON pointers into `source_document`, including all original properties and
sites. The embedded normalized source snapshot retains unmodeled properties;
“represented” does not mean every raw attribute is a scientific feature.
Original legacy scores/labels, if present in raw source extensions, remain
provenance only and never influence scientific output.

The Coverage Ledger contains exactly one entry for every source node, edge and
unresolved record. Each entry is `represented` with canonical IDs or `excluded`
with a deterministic reason. Even excluded evidence remains available in the
source snapshot. Source metadata outside these collections is preserved too.

`CanonicalSubgraph::from_json` and `validate` reconstruct the expected baseline
from the validated source and compare the complete document. This rejects
altered IDs, endpoints, anchor roles, facts, provenance, coverage totals,
versions, ordering or digest. It also rejects extra scientific fields such as
scores/capabilities and invented unresolved targets.

## Acceptance and frozen fixture

```powershell
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
python scripts/test_canonical_baseline.py
```

On non-Windows hosts, pass `--engine rust_engine/target/debug/rust_engine` to
the Python script after building the binary. Optional real-data replay:

```powershell
python scripts/test_canonical_baseline.py --real-source-dir reports/seed-refinement-notepad-20261001-015503
```

The checked-in `canonical_local_v0_1.json` and `.sha256` freeze the baseline.
The CLI suite independently checks the digest with Python hashlib, repeatability,
JSON permutations, nonuniform relocation, complete provenance/coverage,
semantic-change sensitivity, invalid input rejection, and absence of scientific
scores/capability labels or fabricated targets. Rust tests additionally exercise
all roles and edge types, explicit exclusions, semantic deduplication, tampering,
raw extensions and exhaustive permutations of symmetric/asymmetric graphs.

Any change to the frozen normalization or serialization semantics requires a
version change and an explicit acceptance-fixture update. Fingerprints,
similarity and LLM rewrites belong to later roadmap stages.
