# OSGF similarity: steps 7.1–7.7

The separate `SimilarityResult` schema is version `0.1.0`. This implements the
three semantic comparisons and separate observability diagnostics. Missing-evidence
qualification, aggregate computation and the final baseline freeze remain future steps.

```powershell
cargo build --locked --manifest-path rust_engine/Cargo.toml
rust_engine/target/debug/rust_engine.exe compare-fingerprints query query-canonical.json query-fingerprint.json reference reference-canonical.json reference-fingerprint.json new-result.json
python scripts/test_similarity_cli.py --engine rust_engine/target/debug/rust_engine.exe
```

Output must be a new file. Both fingerprints are validated against their canonical
sources before any output is created. Unsupported fingerprint, canonical schema or
canonicalization versions return an error, even if both sides share that unsupported
version. Query and reference identifiers are supplied explicitly. Each identity embeds
the verified source-bearing provenance sidecar, so results may contain raw source data.

Each semantic view retains Set Jaccard and Multiset Jaccard. Matching requires the
entire scientific descriptor, including relative function position. Counts come
directly from fingerprint features; no occurrence products or manual weights are used.
Both empty means `comparable=false` and both similarities `null`; only one empty
means zero. Accumulation uses `u128`, with floating-point division only at the end.

Matched records retain both counts, their minimum and both resolved provenance
lists. `missing_from_query` contains reference-only descriptors;
`missing_from_reference` contains query-only descriptors. Shared-feature count
deficits remain in matched records. Motif truncation makes the corresponding view's
`comparison_complete=false`, including comparisons of identical truncated views.
That field describes retained feature enumeration, not global source observability.

Observability retains per-function features rather than summing potentially overlapping
unresolved and indirect records. It compares indirect calls, unresolved calls,
unresolved indirect calls, explicit dynamic dispatch, local truncation (including
requested/effective depths) and both motif truncation records. Differences contain
both values; provenance is available by feature ID in each input identity.
Unresolved calls, truncation and unavailable observations produce scoped warnings
and possible-incompleteness flags. An unknown count is not zero. Observed indirect
or explicit dynamic calls alone do not imply incompleteness. Lower effective depth
alone may indicate that the reachable graph ended, rather than truncation.

Observability never changes either semantic similarity. Aggregate fields remain
`null`. The output is similarity evidence, not a malware score or probability.
