# Step 8 — Final pre-freeze quality fixes

Validation completed: 2026-10-19. Technical fixes complete; real human review (8.6) remains pending. No dataset freeze and no Step 9 work.

## Build robustness

The post-link PE-read, execution and atomic-publish operations retry the same staged artifact up to eight times with 200 ms backoff. Only transient access/sharing OSErrors qualify; invalid PE, compiler source/input errors and behavioral validation errors fail without lock retries. The outer compile loop remains bounded to three attempts. Mock tests demonstrate recovery at each operation with exactly one compiler invocation.

| Configuration | Result | Evidence |
|---|---|---|
| numeric-msvc-O2 | Excluded, failed | 3 compile attempts; 24 PE-read access attempts; PermissionError at validate_pe |
| system_api-msvc-O2 | Excluded, failed | 3 compile attempts; 24 PE-read access attempts; PermissionError at validate_pe |
| interaction_socket_kind-msvc-O2 | Excluded, failed | 3 compile attempts; 24 PE-read access attempts; PermissionError at validate_pe |

27 successful controlled builds; 3 failed configurations. Five of six new interaction builds succeeded. No real build needed/recovered via an inner access retry in this run: the three persistent failures exhausted the bounded waits. All failures remain sanitized records; no protection was bypassed and no failed artifact was admitted.

## Dataset

| Metric | Before | After |
|---|---:|---:|
| samples | 30 | 35 |
| builds | 22 | 27 |
| routines | 53 | 68 |
| graphs | 95 | 120 |
| pairs | 179 | 218 |
| equivalent pairs | 132 | 151 |
| non_equivalent pairs | 47 | 67 |

| Split | Pairs before → after | Equivalent | Non-equivalent |
|---|---:|---:|---:|
| discovery_train | 99 → 115 | 80 | 35 |
| held_out_test | 57 → 64 | 45 | 19 |
| validation | 23 → 39 | 26 | 13 |

All original 95 graph IDs/content hashes and 179 pair IDs/labels/splits are preserved. The extension adds three separate source artifacts with helper-mediated file metadata, read-only registry enumeration and unconnected UDP socket inspection. Each source family, bit-flipped hard negative and delegation variants stay in one source split. Source proofs and executed counterexamples establish labels; no OSGF score is consulted.

## Signal coverage: before → after

Graph properties overlap. Per-label graph counts count unique graphs participating in that label; a graph can participate in both labels.

| Graph subset | Graphs | Anchor-only | Typed evidence | Function-call topology | Interaction capable |
|---|---:|---:|---:|---:|---:|
| All | 95 → 120 | 37 → 43 | 19 → 38 | 46 → 65 | 4 → 23 |
| discovery_train | 51 → 61 | 22 → 25 | 2 → 9 | 29 → 36 | 2 → 9 |
| held_out_test | 27 → 32 | 15 → 15 | 0 → 5 | 12 → 17 | 0 → 5 |
| validation | 17 → 27 | 0 → 3 | 17 → 24 | 5 → 12 | 2 → 9 |
| equivalent | 90 → 114 | 37 → 43 | 14 → 32 | 45 → 63 | 3 → 21 |
| non_equivalent | 47 → 72 | 37 → 43 | 7 → 26 | 6 → 25 | 3 → 22 |

| Pair subset | Pairs | Both anchor-only | Both typed evidence | Both topology | Both interaction capable |
|---|---:|---:|---:|---:|---:|
| All | 179 → 218 | 100 → 100 | 24 → 51 | 22 → 49 | 1 → 28 |
| discovery_train | 99 → 115 | 55 → 55 | 1 → 11 | 16 → 26 | 1 → 11 |
| held_out_test | 57 → 64 | 45 → 45 | 0 → 7 | 0 → 7 | 0 → 7 |
| validation | 23 → 39 | 0 → 0 | 23 → 33 | 6 → 16 | 0 → 10 |
| equivalent | 132 → 151 | 68 → 68 | 19 → 32 | 22 → 35 | 1 → 14 |
| non_equivalent | 47 → 67 | 32 → 32 | 5 → 19 | 0 → 14 | 0 → 14 |

Every split has both equivalent and non-equivalent pairs with typed evidence and interaction structure on both sides (tested against actual canonical graphs). Six new anchor-only graphs are retained too: optimization/exported structure does not guarantee rich observed evidence. No score-based selection or pruning was performed.

## Observability

UNKNOWN means missing/null visibility observations, not an observed defect. Observed incompleteness means unresolved records/counts or local truncation. These categories can overlap; complete means required observations available and no observed incompleteness. Before: 79 unknown, 3 observed incomplete, 13 complete, 3 unresolved-call graphs, 0 locally truncated.

| Graph subset | Unknown | Observed incomplete | Complete | Unresolved calls | Locally truncated |
|---|---:|---:|---:|---:|---:|
| All | 85 | 5 | 30 | 5 | 0 |
| discovery_train | 48 | 2 | 11 | 2 | 0 |
| held_out_test | 25 | 2 | 5 | 2 | 0 |
| validation | 12 | 1 | 14 | 1 | 0 |

| Pair subset | Either unknown | Both unknown | Either observed incomplete | Both complete | Either unresolved | Either local truncation |
|---|---:|---:|---:|---:|---:|---:|
| All | 185 | 148 | 21 | 25 | 21 | 0 |
| discovery_train | 104 | 84 | 11 | 10 | 11 | 0 |
| held_out_test | 57 | 55 | 7 | 0 | 7 | 0 |
| validation | 24 | 9 | 3 | 15 | 3 | 0 |
| equivalent | 137 | 110 | 13 | 10 | 13 | 0 |
| non_equivalent | 48 | 38 | 8 | 15 | 8 | 0 |

## Evaluation strata and validation

`evaluation_strata.json` contains all requested sorted pair-ID sets, globally and grouped by split and equivalence label. It derives only from the manifest/audit and changes no input. Audit and strata were each generated twice and verified byte-identical, also matching their persisted output. Stale manifest/graph provenance is rejected.

| Check | Result |
|---|---|
| Python | 113 passed; 174 subtests passed |
| Rust | 252 passed |
| Canonical / fingerprint / similarity acceptance | 7 / 11 / 20 passed |
| Structural variants | 36,864 independent oracle checks |
| New interaction builds | 400 independent oracle outputs across 5 builds |
| Leakage and family holdouts | Passed; six valid source-preserving holdouts |
| Dataset technical acceptance / replay | Passed; all 27 controlled builds replayed |
| Audit / evaluation strata determinism | Byte-identical; inputs unchanged |
| Notepad regression | 25/25; all three views comparable; deterministic; 10 graphs with warnings |
| Ruff check / format | Passed |
| Cargo fmt / clippy -D warnings / build | Passed |
| Full Ghidra rebuild | Completed, including new binaries and canonical graphs |
| Git diff check / cache tracking | Passed; no tracked Python cache |
| Preservation | Original graph/pair IDs, graph bytes, labels and splits unchanged |

The complete rebuild regenerated pairs, splits, holdouts, audit, strata and the 14-pair review packet. All real decisions remain pending with no reviewer or invented approval. Steps 5–7 scientific semantics, frozen fixtures and golden digests are unchanged (no diff under rust_engine or ghidra_scripts). No malware, similarity-derived label, fabricated human decision, freeze or Step 9 work was introduced.

Exact SHA-256 bindings:

- `manifest.json`: `0758de28ff2b49473b66de1dc90ab7561495eb1f84618114796f81a3be815c42`
- `graph_signal_audit.json`: `bd2aecb133d7b1a46dbc4863ea79c1b50b83fb20a3f9b3c23b42bd6284565afd`
- `evaluation_strata.json`: `10097ce3824168668bacd3f518251504f0963dbe039382efef5c642dc20e0017`

Pre-review portability correction: current bindings above use explicit UTF-8/LF metadata and CRLF compiled-source checkouts. Dataset contents and compiled provenance are unchanged. See [PREREVIEW_FIXES.md](PREREVIEW_FIXES.md) for the migration, current test results and exact commands; earlier rebuild results above remain historical.
