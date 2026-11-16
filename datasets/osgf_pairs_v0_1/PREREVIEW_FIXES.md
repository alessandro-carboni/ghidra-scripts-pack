# Step 8.6 pre-review corrections

Date: 2026-10-19. Repository: alessandro-carboni/ghidra-scripts-pack.
Branch checked before edits and after validation: `codex`.
HEAD unchanged: `f1c99d19db4a80e1ca4ef695d455a937f9d51217`.
Initial checkout and real index were clean; no commit, push, freeze or human
decision was made. Only portability and review-evidence corrections were applied.

## Exact-byte protocol and migration

- Controlled C: UTF-8 without BOM, CRLF bytes supplied to the compiler. All four
  generators explicitly write CRLF. `.gitattributes` specifies `text eol=crlf`.
  Git stores LF blobs internally but restores CRLF at checkout, independently of
  `core.autocrlf`. Raw Git blobs/archives are not a compiled-source checkout.
- Dataset JSON/canonical graphs: UTF-8 without BOM, LF. Attributes specify
  `text eol=lf`; metadata writers explicitly write LF. Existing byte writers for
  canonical graphs, audit and strata already emit LF.
- `source_hash` remains SHA-256 of the exact compiled bytes. No source hash was
  normalized, replaced or reinterpreted. All 27 build records, across all catalogs,
  still match their 11 CRLF source files. Source and binary provenance is unchanged.
- Manifest checkout bytes were migrated CRLF -> LF. Parsed JSON is exactly equal
  to reviewed HEAD, including all 120 graphs, 218 pairs, IDs, hashes, labels and
  splits. Graph bytes did not change. No controlled rebuild or new Ghidra extraction
  is necessary: the actual compiled source bytes have not changed.
- Audit and strata were regenerated against the LF manifest. Descriptive properties
  and pair sets are unchanged; only exact-byte hash bindings changed. The existing
  review `content_hash` is a separately defined canonical JSON-content hash and
  therefore remains unchanged; it is not the manifest-file SHA-256.

| Exact file SHA-256 | Before (local CRLF manifest) | After (portable LF manifest) |
|---|---|---|
| manifest.json | f3aa8f068d24635f1c0f538752d7660e50436fba6cd2024b5f1a1e50a18c7b20 | 0758de28ff2b49473b66de1dc90ab7561495eb1f84618114796f81a3be815c42 |
| graph_signal_audit.json | d7843e8bba8c4852445c86959ba4741be7e2f119f3c0c2178e76327bb457866e | bd2aecb133d7b1a46dbc4863ea79c1b50b83fb20a3f9b3c23b42bd6284565afd |
| evaluation_strata.json | 31c71d865e60727bb7976728e761897a2679f3f2cf4045e8296440f4fd07a5f3 | 10097ce3824168668bacd3f518251504f0963dbe039382efef5c642dc20e0017 |

The manifest's new hash is also the existing LF Git blob hash identified in the
review request. This fixes the checkout contract rather than weakening validation.
Current bindings in ACCEPTANCE.md and QUALITY_FIXES.md were updated; their prior
build outcomes remain historical.

## Correct review evidence

The packet now derives each transformation's tested case count from its registered
proof and verifies it against the actual transformed-routine transcript, including
unique case IDs. Missing/mismatched coverage fails instead of claiming 1,024 inputs.
Each side displays its specific source contract. Interaction evidence explicitly
requires stable read-only OS state across calls/builds.

- Legacy variants: 1,024 inputs per transformed routine (all 256 lengths, four
  patterns); 36 routines yield **36,864 oracle checks**.
- Interaction transformations: **16 cases per routine per build**. Each new build
  prints five routines x 16 cases = 80 outputs; five successful builds yield
  **400 outputs**. This total includes base and negative routines and is not 400
  inputs per transformation.

Regression tests cover both evidence classes using the real manifest and transcripts.
The 14-pair packet was refreshed only after both existing JSON files passed the
all-pending/no-reviewer/no-notes/no-reason guard. The initial clean Git state also
confirmed no local human edits to REVIEW.md. Decisions and pair selections remain
unchanged. No automatic test result is presented as a human decision.

## Checks executed for this correction

| Check | Actual result |
|---|---|
| Python | 115 passed, 174 subtests passed |
| Ruff check / format | Passed; 41 files formatted |
| Exact source, graph and metadata integrity | Passed against real versioned files |
| Audit/strata | Regenerated twice in memory, byte-identical to each other and persisted outputs |
| Fresh candidate checkout, autocrlf=false | Passed source hashes, graph hashes, LF JSON, audit and strata |
| Fresh candidate checkout, autocrlf=true | Same checks passed |
| Dataset validation | 35 samples, 27 builds, 68 routines, 120 graphs, 218 pairs |
| Leakage / six family holdouts | Passed; split counts remain 115 / 39 / 64 |
| Structural variant oracles | 36,864 passed |
| Technical acceptance and runtime replay | All 27 builds replayed; includes independent checks of 400 interaction outputs |
| Rust | 252 passed |
| Cargo fmt / Clippy -D warnings / build | Passed |
| Canonical / fingerprint / similarity acceptance | 7 / 11 / 20 passed |
| Real Notepad regression | 25/25, all three views comparable, deterministic reruns; 10 warning-bearing graphs |
| git diff --check | Passed |
| Frozen scientific code/fixtures/goldens | No diff under rust_engine or ghidra_scripts |

The fresh checkouts are materialized with Git checkout-index from a disposable
candidate index containing HEAD plus proposed changes, into new temporary folders.
No commit or branch is created; the real index and HEAD are verified unchanged.
They exercise actual repository content and Git EOL conversion, not coherent
synthetic fixtures. They contain no ignored local binaries, so runtime replay is
reported separately for the primary checkout. Native Linux/macOS execution was
not available/tested; both autocrlf settings were tested on Windows.

Controlled C compilation and full Ghidra rebuild were **not rerun** for this
metadata-only migration. Their earlier outcomes (including three excluded O2
access failures) are historical, not new successes. Current binary integrity and
transcript replay did pass. Rust build and all scientific suites above were rerun.

## Full PowerShell commands

Commands below were run from this directory. The validation runner checked each
exit code and stopped on failure. Output is retained locally in
`.build-cache/prereview-checks.log` and was displayed in PowerShell.

```powershell
Set-Location 'C:\Users\aless\Desktop\ghidra-scripts-pack'
git branch --show-current
git rev-parse HEAD
git remote -v
git status --short

python scripts/audit_dataset_graph_signal.py --output datasets/osgf_pairs_v0_1/graph_signal_audit.json
python scripts/generate_evaluation_strata.py
python scripts/dataset_review.py prepare --refresh-pending

python -m ruff check .
python -m ruff format --check .
python -m pytest -q tests
python scripts/validate_dataset_portability.py --clean-checkouts
python scripts/dataset_manifest.py datasets/osgf_pairs_v0_1/manifest.json --root .
python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check
python scripts/validate_structural_variants.py
python scripts/validate_dataset_acceptance.py --technical-only --replay
 cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
 cargo test --locked --manifest-path rust_engine/Cargo.toml
 cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
 cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
git diff --check
git diff --exit-code -- rust_engine ghidra_scripts
git rev-parse HEAD
git branch --show-current
git diff --cached --stat
```

Steps 5–7 semantics and golden digests are preserved. No similarity-derived labels,
anchor-only exclusions or split changes. Step 8.6 remains pending human review;
no freeze, no Step 9, no commit and no push.
