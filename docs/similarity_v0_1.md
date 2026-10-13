# OSGF Baseline Similarity v0.1

The separate `SimilarityResult` schema is version `0.1.0`, frozen on 2026-10-13
after completing steps 7.1–7.10. It includes three semantic comparisons, separate
observability diagnostics, qualified missing evidence and an optional aggregate.

```powershell
cargo build --locked --manifest-path rust_engine/Cargo.toml
rust_engine/target/debug/rust_engine.exe compare-fingerprints query query-canonical.json query-fingerprint.json reference reference-canonical.json reference-fingerprint.json new-result.json --aggregate
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
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

Each missing feature carries `qualification` and `warnings`. The states are
`observed_absent` and `observed_absent_with_incomplete_observability`. Qualification
uses the absent side's global possible-incompleteness flag, including unresolved
calls, local/motif truncation and unavailable observations. It is deliberately
conservative across views. Feature descriptors and provenance always come from the
side where evidence is actually present. No missing feature is assigned to an
unresolved call, and qualification does not create matches or change metrics.

Observability never changes either semantic similarity. `--aggregate` enables
separate arithmetic means for Set and Multiset across comparable semantic views.
`aggregate_components` lists the selected views in topology/evidence/interaction
order. Empty views are excluded; when no view is comparable both means are `null`.
Without the flag, both means are `null`, the component list is empty and
`aggregate_requested=false`. With the flag it is true even when no view is comparable.
Truncated but nonempty views remain comparable; their warnings remain visible.
The output is OSGF similarity evidence, not a malware score or probability.

## Determinism and freeze verification

The same validated inputs, IDs and aggregate setting produce byte-identical pretty
JSON. BTreeMap descriptor order stabilizes matched/missing feature lists; the
aggregate has a fixed component order. The checked-in
`rust_engine/tests/fixtures/similarity_v0_1_golden.json` freezes the SHA-256 of the
complete identical-fixture result with aggregate enabled and IDs `query`/`reference`.
Tests never regenerate this golden reference.

Relocation and source reordering preserve scientific descriptors, metrics, missing
qualification and aggregate. Raw snapshots and source indices in provenance must
still reflect their actual inputs, so the full source-bearing report is not expected
to have identical bytes across different source documents. Repeated runs of each
same input are byte-identical. Unrelated evidence can still share generic root-role
features; the baseline does not force the topology similarity to zero.

The acceptance suite covers identical, relocated, reordered, partial-overlap,
extra-evidence, topology-only, evidence-only, unrelated, count-only, degraded
observability, qualified absence, local/motif truncation, empty-view, invalid-version,
provenance and deterministic-output cases. An independent Python oracle checks
both Jaccard formulas, matched counts and missing partitions against input features.
CI runs it together with the canonical and fingerprint regression suites and Rust
tests/Clippy. Scientific changes after this freeze require explicit version and
golden-reference review rather than silently updating expected output.
