# Step 10.4 pair matrix

All 218 frozen judgments are evaluated independently in A and B (436 records).
Original left/right order is retained as query/reference. Jaccard values are
symmetric; missing-feature direction, warnings and provenance are not. No
source-bearing result is reused for the opposite direction or another graph.

Condition B invokes the frozen `compare-fingerprints --aggregate` CLI with real
graph IDs. The approved research A CLI uses the literal role handles `query`
and `reference`: its raw output is preserved unchanged. Each matrix record
explicitly binds these handles to ordered real graph IDs, catalog record IDs,
fingerprint digests and the complete original independently judged pair.
This metadata limitation is not concealed by rewriting the research output.

Result files retain all matched/missing descriptors, counts, resolved origins,
observability diagnostics and missing-feature qualifications. Compact matrix
rows include semantic per-view scores/comparability/completeness/warnings,
aggregate components, the preregistered primary Multiset Jaccard aggregate,
secondary Set Jaccard aggregate, and both inputs' motif-truncation metadata.
Null remains null. No observability warning enters semantic arithmetic.

An independent Python descriptor/count oracle checks EVERY result, not a sample.
It uses set intersection/union and sums of integer minima/maxima, converting the
integer multiset totals to binary64 as in the frozen contract. Empty unions are
noncomparable; aggregates average only comparable semantic views. The original
source-bearing sidecars must match the result's query/reference provenance.

Record IDs bind condition, ordered input catalog records and artifacts, frozen
pair metadata, metric configuration, protocol/catalog/executable hashes and
generator source identity. Pair admission and labels are never chosen by score.
The paired-component audit marks A/B comparability without dropping any pair.

Runtime outputs: `runtime/pair_scores-v0_1/`; the versioned `pair_matrix.json`
is an exact copy of `matrix.json`. Paths in artifact records are relative to that
runtime directory. Outputs require a new destination and publish atomically.
Failed comparisons/oracles make the matrix INCOMPLETE and exit nonzero.
`--verify` regenerates the catalog inputs and all pair results in a fresh temporary
directory, then compares every filename and every byte including the matrix.

```powershell
python -m pytest -q tests/test_evaluation_pairs.py
python scripts/evaluation_pairs.py --score
python scripts/evaluation_pairs.py --verify
```

No retrieval metrics, threshold selection or scientific conclusions belong to
this microstep. Tests of relocation, unresolved targets and truncation in the
unchanged frozen acceptance suites and Step 10.2 adapter gate remain applicable;
Step 10.4 adds numeric oracles, directional provenance and full-corpus replay.
