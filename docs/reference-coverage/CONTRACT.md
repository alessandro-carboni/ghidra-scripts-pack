# Reference coverage 0.1.0

Additive opt-in comparison over source-validated `osgf.graph-first/0.1.0` fingerprints. Existing extract/fingerprint/compare/search, frozen Rust mathematics, operational views and defaults remain unchanged. This increment implements chapters 0–6 of the supplied final-realignment specification, not its later library/benchmark stages.

## Commands

```powershell
python scripts/reference_coverage.py compare query-fingerprint.json reference-fingerprint.json --engine rust_engine/target/debug/rust_engine.exe --output new-coverage.json
python scripts/reference_coverage.py validate new-coverage.json --engine rust_engine/target/debug/rust_engine.exe
```

Output must not already exist. The query and reference are graph-first envelopes created through the existing commands; automatically detected seed provenance remains distinguishable from provided local contexts. The comparator invokes the existing graph-first/Rust validation and comparison path. Result validation reconstructs all projections, support, scores and explanations from the embedded inputs; unknown schema, extra fields, altered counts/provenance or incorrectly typed scores fail. No new API aliasing or canonicalization is performed.

## Mathematics

For descriptor collections Q and R:

- Set coverage = `|distinct(Q) intersect distinct(R)| / |distinct(R)|`.
- Multiset coverage = `sum_f min(count_Q(f), count_R(f)) / sum_f count_R(f)`.
- Empty reference denominator means `null`, including both-empty collections.
- Nonempty reference with no matches means `0.0`.
- Weights are one. No label-derived or malware-specific weights.

All arithmetic uses exact Python integer totals and rational division. JSON includes the unreduced exact numerator and denominator for each ratio, plus a finite floating-point representation in [0,1] when comparable. Percentages are not rounded into the scientific result. An extra query observation does not lower directional coverage, but is reported explicitly and remains visible in the unchanged symmetric comparison.

## Collections and accounting

The main `reference_coverage` explicitly uses the **normalized base evidence-value collection**. Values are projected read-only from existing typed-evidence descriptors, after validation. Its disjoint family tags are APIs, literal strings, contextual constants and locally attached section facts. Each normalized value contributes once to set coverage. Its multiset count sums unique supported occurrences/attachments, retaining source multiplicities. Repetition beyond the reference count cannot increase matched mass. Counts are not confidence or independent statistical trials.

String categories are reported separately because they are derived through explicit string/category chains. They do not give the underlying string a second vote in overall base-value coverage. Seed triggers likewise add no votes. Normalized section facts are admitted only through existing local function-to-section evidence; arbitrary whole-executable properties are not copied to every region. All normalization is the frozen canonical contract.

Relation-aware coverage compares complete descriptors independently in rooted topology, typed evidence, interaction motifs and graph-first co-observations. Function roles, distances and attachment relationships are retained. An API can match in value coverage and fail in relation-aware coverage when it is attached differently. `relation_aware_coverage.overall_if_defined` is null: no aggregate across correlated views is defined. Derived motifs may have their own per-view multiplicities but are never summed with base observations as independent support.

## Result schema: osgf.reference-coverage/0.1.0

- `identities`: original query/reference anchor, trigger mode and source identities.
- `reference_coverage`: explicit basis, unit-weight policy, set/multiset ratios, exact fractions and query/reference counts.
- `evidence_value_coverage`: per-family ratios, declared disjoint base aggregate and exclusions.
- `relation_aware_coverage`: per-view ratios and explicit undefined aggregate.
- `symmetric_similarity`: the original baseline result and existing graph-first graph-similarity object, passed through without changing their mathematics or fields.
- `matched_evidence`: descriptor/count intersection with separate query/reference supporting occurrences and source references.
- `missing_reference_evidence`: fully absent descriptors and unmatched count deficits for shared descriptors, with provenance and observability qualification.
- `additional_query_evidence`: query-only descriptors and surplus occurrences, likewise traceable.
- `evidence_support`: original support, coverage/truncation/unresolved diagnostics and separate counts of base observations, relational descriptors and derived categories.
- `interpretation`: reference feature coverage, explicitly not malware probability, calibrated confidence or behavioral equivalence.
- `sources`: complete original source-bearing graph-first envelopes for validation and provenance resolution.

New partitions retain the existing `observed_absent` / `observed_absent_with_incomplete_observability` vocabulary for fully missing descriptors. Shared-feature count deficits are explicitly `observed_count_deficit`, optionally with the same incompleteness suffix; they are not mislabeled as a completely absent descriptor. The legacy result preserves its original warnings/qualifications byte-for-byte. Co-observation omissions additionally qualify their own missing partitions. No hidden API or feature is inferred from an unresolved call or unavailable evidence.

## Scope of validation

Mandatory tests cover 2/3 API coverage, 4/5 disjoint observations, directionality, self comparison, empty/disjoint sets, additional query evidence, changed structural attachment, repeated counts, truncation/unresolved evidence, correlated categories/motifs, locally scoped sections, source tampering, deterministic serialization and unchanged symmetric fields. Exhaustive small multiplicities and totals beyond u64 verify exact arithmetic independently.

Real Notepad self-comparisons, when available, check integration and deterministic accounting only. They do not measure malware retrieval performance or establish scientific improvement. The previous quarantined graph-first benchmark remains untouched and incomplete. No malware reference library, new malware dataset or LLM component is introduced here.
