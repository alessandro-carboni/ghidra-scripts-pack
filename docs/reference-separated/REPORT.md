# Family-separated benign validation: actual outcomes

2026-11-12 — continuation after reference-library microstep 7. HEAD remains `ff4e097351d0b64e0f9f03bede98d0d5db7c41fe` on `codex`. No commit, push, deletion, malware execution or security change.

The new source generator and runner add a prospective three-family corpus, explicit split/source/tool registration, validated reuse of completed extraction artifacts and complete planned-pair availability accounting. They reuse the existing graph, reference-library, benchmark and P-code implementations without changing their semantics. See [PROTOCOL_AND_LIMITATIONS.md](PROTOCOL_AND_LIMITATIONS.md) for source contracts, the disclosed availability amendment, exact commands and blocking conditions.

## Availability is the primary outcome

| Planned partition | Planned pairs | Comparable pairs | Reason |
|---|---:|---:|---|
| Discovery: debugger status | 9 | 0 | Antivirus blocked the first binary before its bytes could be read; user confirmed the block |
| Validation: DLL resource inspection | 9 | 9 | Both builds yielded all annotated regions |
| Heldout: TCP/UDP socket lifecycle | 9 | 0 | Both builds yielded zero seeds for the three annotated regions |
| Total | 27 | 9 | All missing pairs remain explicit with null scores |

The 27 planned pairs have source-derived labels fixed before scoring. No missing binary hash or fingerprint was fabricated. A compiled but blocked program is not a completed experiment. An analyzed binary with runtime seeds is not evidence that its annotated regions were recovered.

On the four analyzed binaries, annotated-region seed recovery is 6/12: resource inspection 3/3 for each optimization; socket lifecycle 0/3 for each. The two discovery builds remain unavailable, not measured seed failures. Deliberate no-seed arithmetic probes remain unselected. The resource query produces five automatic seeds and the socket query three; all eight are searched, including runtime/unannotated regions. Their search candidates do not acquire supervised labels from similarity.

## Conditional performance on the available validation pairs

| Condition | AUC | MRR | Recall@1 | Fitted threshold / classification |
|---|---:|---:|---:|---|
| A: frozen original | 1 | 1 | 2/3 | unavailable |
| B: existing graph-first | 1 | 1 | 2/3 | unavailable |
| C: existing operational-only | 1 | 1 | 2/3 | unavailable |
| D: directional reference coverage | 1 | 1 | 2/3 | unavailable |
| E: existing optional refinement | 1 | 1 | 2/3 | unavailable |

E's continuous score is unchanged B; its ranking policy is separate. Recall@1 is relevant-reference recall, not first-hit accuracy: subject/equivalent queries each have two relevant gallery entries. All methods tie here. This does not establish an improvement of coverage, a general advantage of P-code, or a low classifier false-positive rate. Discovery calibration is unavailable and is not replaced by thresholds selected on validation or heldout.

Heldout AUC/MRR and classification remain null because no annotated region is comparable. The heldout extraction failure is a negative end-to-end finding, not a numerical similarity result. No heldout generalization claim is supported.

## Observed socket extraction boundary

In O0, `subject` calls FUNCTION nodes `fn:004015e8` (`socket`) and `fn:004015f0` (`closesocket`), both internal, size 6, `thunk=false`. O2 likewise records these names as internal FUNCTION nodes (`fn:00401530`, `fn:00401538`) rather than APIs. There are no matching API observations for those routines. The current exporter distinguishes external functions/resolved import thunks from ordinary functions; the API detector therefore has no corresponding observed API trigger.

This localizes a missing-observation problem before fingerprint comparison. It does not justify inferring API identities solely from symbol names. A follow-up should validate PE import tables and actual control-flow/IAT facts, then propose an independently versioned extraction experiment if those facts warrant one. The frozen exporter, seed rules and historical evidence were not patched to make this experiment pass.

## Determinism, integrity and tests

- All four JSON files produced by the available evaluation (three full ranking/explanation files plus the aggregate result) are byte-identical to their rerun counterparts. This tests full explanations, not only score summaries.
- All 27 planned pair records remain present; unavailable comparisons have null scores. Every discovery threshold and classification result is null.
- Python full suite: **652 passed, 175 subtests passed**, 713.15 s. It was started before the final availability-resume regression was added; it is not described as a fictional 653-test run.
- Post-amendment targeted suite: **29 passed**, 51.55 s (`tests/test_reference_corpus.py`, `test_reference_benchmark.py`, `test_reference_library.py`). After the final descriptive preparation-policy correction, the five corpus tests passed again in 0.27 s.
- Original Rust: **252 passed**. Operational Rust: **258 passed**. Both fmt and Clippy checks passed.
- Canonical/fingerprint/similarity acceptance suites: **7 / 11 / 20 passed**.
- Ruff passed; format check: **131 files already formatted**. `git diff --check` passed.
- The original 1,242-path inventory has zero unexpected changes. Only the already-authorized CI and LF attribute files differ among those paths. All **30** evidence artifacts referenced by the earlier three-pilot report retain their byte hashes. Golden fixtures, scientific source, protocols and previous results remain unchanged.

Exact receipts and full ranking hashes are in [RESULTS.json](RESULTS.json); preservation checks are in [integrity.json](integrity.json). Full terminal logs are `.build-cache/reference-separated-pytest.log`, `reference-separated-targeted.log`, `reference-separated-rust.log`, `reference-separated-operational.log`, `reference-separated-canonical.log`, `reference-separated-fingerprint.log`, and `reference-separated-similarity.log`. These are tests executed in this continuation, distinct from earlier pilot results.

## What remains unfinished

The independently testable corpus infrastructure and available comparisons are complete. The **full discovery/validation/heldout experiment is not complete**: discovery is blocked, and the intended heldout observations are not recovered. The user confirmed no authorized malware corpus is available. No successful malware validation is claimed.

Resume with a separately scoped investigation of evidence-backed import-stub recovery and an appropriate approved research environment or a prospectively designed replacement study for discovery. Preserve the original blocked study and partial protocol; do not reassign partitions, restore blocked files, weaken validation or retroactively promote missing observations. Broader independent lineages and independent annotations remain necessary before thesis-level generalization claims.
