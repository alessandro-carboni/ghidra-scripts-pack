# Step 8 acceptance audit

Date: 2026-10-15. Status: technical acceptance passed; Step 8 remains incomplete pending human review and final freeze.

| Requirement | Status | Evidence |
|---|---|---|
| Controlled corpus reproducible without LLM | PASS | C sources, deterministic generators, rebuild_controlled_dataset.py and exact compiler/build metadata |
| Separate real-world benign corpus; no malware | PASS | 8 System32 copies, excluded from automatic pair labels |
| Source/build/sample/graph traceability | PASS | 30 samples, 22 controlled builds, 53 routine records, 95 canonical graphs; source and binary hashes verified |
| Independent positive ground truth | PASS | 96 same-source compiler pairs and 36 source-transformation pairs; no similarity labels |
| Independent negative ground truth and hard negatives | PASS | 47 executed counterexamples; 6 categories; easy/hard cases and typed API evidence tests |
| O0/O2/O3 and cross-compiler pairs | PASS | GCC O0/O2/O3 and available MSVC O0/O2; unavailable/failed builds recorded in corpus.json |
| Controlled structural variants | PASS | 6 families x 6 examples; 36,864 oracle checks; explicit input contract |
| Deterministic splits and no source leakage | PASS | Explicit source/artifact components, declared near-duplicate groups, reversed-pair rejection; manifest byte-identical after regeneration |
| Transformation-family holdouts | PASS | 6 nonempty experiments preserving source splits |
| Complete per-split statistics | PASS | manifest.json split_statistics; 99 discovery, 23 validation, 57 held-out pairs |
| Ambiguous pair handling | PASS | Explicit statuses; ambiguous/rejected held-out decisions rejected by freeze validation; no current ambiguous decisions |
| Manually verified representative subset | PENDING | 14-pair review packet prepared; reviewer and decisions have not been supplied |
| Final versioned freeze | PENDING | Blocked until real review; append-only freeze/revision tooling tested using temporary synthetic fixtures only |

Regression evidence: 252 Rust tests; 105 Python tests and 144 subtests; canonical acceptance 7, fingerprint acceptance 11, similarity acceptance 20; 25/25 real Notepad graphs with byte-identical repeated comparisons (10 carry observability warnings). Cargo fmt, Clippy with warnings denied, build, Ruff and git diff checks pass. Frozen scientific fixtures/golden digests are unchanged; no Python cache files are tracked.

Runtime replay: all 22 controlled builds matched their recorded transcripts. Source/API evidence used for labels is independent of OSGF similarity. The Notepad similarity smoke above is regression validation only.

Review packet: `review/REVIEW.md`. Decisions: `review/review_decisions.json`. The actual decisions remain pending; no human reviewer or approval was fabricated.

Exact manifest SHA-256: `2072fbf9de9d3634700fe26ad2dd0600bed6c2d6af1e401c0c3d0413ac302199`.

Steps 8.3, 8.4 and 8.5 completed their TODO -> implementation -> test -> DONE -> TODO removal cycle. Step 8.6 and acceptance criteria remain in TODO until the manual review requirement is satisfied. Step 9 has not begun.

Pre-freeze fixes: portable metadata, isolated validated staging builds with bounded retries, deterministic graph-signal audit and refreshed pending review hashes. See `PREFREEZE_FIXES.md`. Both previously failed MSVC O2 configurations remain explicit failures after three output-access attempts; they are not counted as successes.
