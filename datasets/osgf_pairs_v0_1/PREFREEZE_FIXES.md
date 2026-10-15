# Step 8 pre-freeze fixes — 2026-10-15

All three technical fixes are implemented. Human review (8.6) and final freeze remain pending. Step 9 was not started.

## Changed files

- New: `scripts/controlled_build.py`, `scripts/audit_dataset_graph_signal.py`, `tests/test_controlled_build.py`, `tests/test_graph_signal_audit.py`.
- Updated: controlled corpus/variant/negative generators, `validate_controlled_corpus.py`, `dataset_review.py`, `rebuild_controlled_dataset.py`, review tests and `docs/controlled_dataset_v0_1.md`.
- Regenerated: corpus/variant/negative metadata, pair manifest and statistics, family holdouts, graph audit and pending review hashes. Graph extraction ran through the local Ghidra installation; unchanged binary hashes reuse verified canonical graph files.

## Portable metadata and build results

All dataset JSON files passed the repository/user-home path scan. Flags retain semantic options and relative source/staging output paths. Compiler names/versions and structured sanitized failure diagnostics are preserved; actual compiler invocations use local resolved paths.

Builds compile to isolated staging directories. Successful exit, PE checks and runtime oracle validation precede atomic publication. Retry limit is three for access/sharing failures only. Missing libraries, source errors and behavioral failures do not retry.

- `numeric-msvc-O2`: FAILED after 3 attempts; PermissionError while reading the staged PE.
- `system_api-msvc-O2`: FAILED after 3 attempts; PermissionError while reading the staged PE.
- Both remain excluded from successful samples. No protection/lock bypass was attempted.

## Final dataset

| Samples | Controlled builds | Routine records | Canonical graphs | Pairs |
|---:|---:|---:|---:|---:|
| 30 | 22 | 53 | 95 | 179 |

The 30 samples include 8 separate System32 validation copies. There are 132 equivalent and 47 non-equivalent pairs.

| Split | Positive | Negative | Total |
|---|---:|---:|---:|
| discovery_train | 72 | 27 | 99 |
| held_out_test | 42 | 15 | 57 |
| validation | 18 | 5 | 23 |

## Graph signal (overlapping properties)

| Property | Graphs |
|---|---:|
| anchor_only | 37 |
| degraded_observability | 82 |
| has_topology | 46 |
| interaction_capable | 4 |
| topology_only | 39 |
| typed_evidence_present | 19 |

Of 82 degraded/unknown-observability graphs, 79 lack visibility observations and 3 contain observed unresolved calls. No local truncation was observed. Unknown is not treated as zero. Interaction capability requires connected callee evidence, not just coexisting topology and evidence. Anchor-only graphs remain in the dataset.

| Pair label | Pairs | Both anchor-only | One anchor-only | Both typed evidence | Both topology | Either degraded |
|---|---:|---:|---:|---:|---:|---:|
| equivalent | 132 | 68 | 30 | 19 | 22 | 132 |
| non_equivalent | 47 | 32 | 10 | 5 | 0 | 42 |

Global pair combinations: 100 both anchor-only, 40 exactly one anchor-only, 24 both typed evidence, 22 both topology, 1 both interaction-capable, 174 degraded on either side. Detailed per-split/category/family/negative-category counts are in `graph_signal_audit.json`.

## Validation

- Full technical rebuild completed using local Ghidra; all 22 admitted controlled builds replayed identically.
- Python: 105 tests and 144 subtests passed, including portable JSON, staging failure/retry, audit categories/determinism/no mutation and pending-review protection.
- Rust: 252 tests passed; fmt, Clippy with `-D warnings`, and locked build passed.
- Canonical acceptance: 7; fingerprint acceptance: 11; similarity acceptance: 20 passed.
- Real Notepad smoke: 25/25 graphs passed; repeated comparison bytes identical; 10 with observability warnings.
- Ruff check/format and git diff checks passed.
- Manifest, 36,864 structural-variant oracle checks, deterministic splits/leakage and technical acceptance passed.
- Audit ran twice with byte-identical output; every source dataset JSON remained unchanged by the audit.
- No Rust/exporter/controlled-C source or frozen fixture/golden digest changed in these fixes. No similarity scores were used to assign labels.
- The 14-pair review packet has current hashes and only pending decisions; no reviewer, human decision or freeze was created.

Manifest SHA-256: `2072fbf9de9d3634700fe26ad2dd0600bed6c2d6af1e401c0c3d0413ac302199`.
Audit SHA-256: `a12518974b968d1b4a788000c65f196300ecc4c288f84e55a76f6c2b7d27f751`.
