# Step 8 acceptance audit

Date: 2026-10-19. Status: FINAL ACCEPTANCE PASS; Step 8 completed after manual review and versioned freeze.

| Requirement | Status | Evidence |
|---|---|---|
| Controlled corpus reproducible without LLM | PASS | C sources, deterministic generators, rebuild_controlled_dataset.py and exact compiler/build metadata |
| Separate real-world benign corpus; no malware | PASS | 8 System32 copies, excluded from automatic pair labels |
| Source/build/sample/graph traceability | PASS | 35 samples, 27 controlled builds, 68 routine records, 120 canonical graphs; source and binary hashes verified |
| Independent positive ground truth | PASS | 100 same-source compiler pairs and 51 source-transformation pairs; no similarity labels |
| Independent negative ground truth and hard negatives | PASS | 67 executed counterexamples; 7 categories; easy/hard cases and typed API evidence tests |
| O0/O2/O3 and cross-compiler pairs | PASS | GCC O0/O2/O3 and available MSVC O0/O2; unavailable/failed builds recorded in corpus.json |
| Controlled structural variants | PASS | 6 families x 6 examples; 36,864 oracle checks; explicit input contract |
| Deterministic splits and no source leakage | PASS | Explicit source/artifact components, declared near-duplicate groups, reversed-pair rejection; manifest byte-identical after regeneration |
| Transformation-family holdouts | PASS | 6 nonempty experiments preserving source splits |
| Complete per-split statistics | PASS | manifest.json split_statistics; 115 discovery, 39 validation, 64 held-out pairs |
| Ambiguous pair handling | PASS | Explicit statuses; ambiguous/rejected held-out decisions rejected by freeze validation; no current ambiguous decisions |
| Manually verified representative subset | PASS | 14/14 decisions accepted and validated: 8 equivalent, 6 non-equivalent |
| Final versioned freeze | PASS | Immutable freeze-001.json generated after REVIEW VERIFIED: 14 |

Regression evidence: 252 Rust tests; 113 Python tests and 174 subtests; canonical acceptance 7, fingerprint acceptance 11, similarity acceptance 20; 25/25 real Notepad graphs with byte-identical repeated comparisons (10 carry observability warnings). Cargo fmt, Clippy with warnings denied, build, Ruff and git diff checks pass. Frozen scientific fixtures/golden digests are unchanged; no Python cache files are tracked.

Runtime replay: all 27 controlled builds matched their recorded transcripts. Source/API evidence used for labels is independent of OSGF similarity. The Notepad similarity smoke above is regression validation only.

Review packet: `review/REVIEW.md`. Decisions: `review/review_decisions.json`. All 14 decisions were manually accepted; reviewer, notes and reasons are recorded in review_decisions.json.

Exact manifest SHA-256: `0758de28ff2b49473b66de1dc90ab7561495eb1f84618114796f81a3be815c42`.

Steps 8.3, 8.4 and 8.5 completed their TODO -> implementation -> test -> DONE -> TODO removal cycle. Step 8.6 and final acceptance are complete. Step 9 has not begun.

Pre-freeze fixes: portable metadata, isolated validated staging builds with bounded retries, deterministic graph-signal audit and refreshed pending review hashes. See `PREFREEZE_FIXES.md`. Both previously failed MSVC O2 configurations remain explicit failures after three compile attempts, each with eight PE-read access attempts; they are not counted as successes.

Final quality fixes: operation-level post-link access retries, separate unknown/observed-incomplete audit fields, three interaction source artifacts and deterministic evaluation strata. Full metrics and failure records: [QUALITY_FIXES.md](QUALITY_FIXES.md). All three splits contain positive and negative interaction-capable material. Five new builds succeeded; the new socket O2 build also remains an explicit access failure. No review/freeze decision is implied.

Pre-review portability correction: current bindings above use explicit UTF-8/LF metadata and CRLF compiled-source checkouts. Dataset contents and compiled provenance are unchanged. See [PREREVIEW_FIXES.md](PREREVIEW_FIXES.md) for the migration, current test results and exact commands; earlier rebuild results above remain historical.


## Final review and freeze ? 2026-10-19

- Human review: 14/14 accepted; 8 equivalent and 6 non-equivalent pairs.
- Review validation: `REVIEW VERIFIED: 14`.
- Frozen dataset: `freezes/freeze-001.json`.
- Freeze content hash: `095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2`.
- Final dataset: 35 samples, 27 builds, 68 routines, 120 canonical graphs, 218 pairs.
- Structural variants: 6 families, 36,864 oracle checks.
- Technical acceptance: PASS.
- Final acceptance: `FINAL ACCEPTANCE PASS: OSGF Equivalent / Non-Equivalent Pair Dataset v0.1`.
- Step 8 status: COMPLETED. Step 9 is next.

The frozen snapshot is immutable. Future dataset changes require
an explicit versioned revision rather than overwriting freeze-001.json.
