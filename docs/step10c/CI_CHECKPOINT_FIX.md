# CI checkpoint portability correction — 2026-11-09

The reported failure was an exact-byte mismatch in `test_protected_checkpoint_bytes`, not a Git push transport failure. HEAD inspected: `4aeeed5264ca3b790feba104dc1c0eb6dbc935c8`, branch `codex`. Existing value-flow work was preserved.

The Step 10A checkpoint captured CRLF bytes for `datasets/osgf_baseline_evaluation_v0_1/.gitattributes`, although its own `* text eol=lf` rule materializes LF on checkout. Expanding the regression to all 291 protected paths exposed further portability issues hidden behind that first assertion.

Six administrative/documentation entries migrate to the LF bytes already stored in Git: the evaluation `.gitattributes`, `.gitignore`, `VALIDATION.md`, transformation `ACCEPTANCE.md`, and the baseline evaluation/transformation harness documentation. The latter two had mixed worktree terminators. `ci_checkpoint_portability_migration.json` records each historical hash and its replacement; these are explicit metadata corrections, not newly verified historical bytes. Historical audit reports describe their original runs and are not retroactively rewritten.

The other protected files retain their hashes. Root attributes now explicitly reproduce their recorded LF or CRLF bytes independently of `core.autocrlf`; the protected GIF is binary. No source semantics, source provenance, compiled bytes, IDs, labels, splits, goldens, thresholds or scientific result files were changed. All 161 Step 9 scientific hashes are unchanged. The six migrated files match the existing Git blobs byte-for-byte after LF materialization.

The checkout regression uses actual tracked files in disposable local clones, applies the candidate checkpoint and root attributes, and validates all 291 audit hashes plus the 161-entry production protocol. Both `core.autocrlf=false` and `true` are tested. Negative controls change only line endings and must fail exact validation. The original repository index and HEAD are untouched. No hash normalizer, alternative-hash allowance, skipped integrity assertion or CI error suppression was introduced.

PowerShell validation commands (run from `C:\Users\aless\Desktop\ghidra-scripts-pack`):

```powershell
python -m pytest -q tests/test_frozen_checkout.py tests/test_diagnose_baseline_core.py
python -m pytest -q tests
python .build-cache/check_ci_lf_20261109.py
python -m ruff check .
python -m ruff format --check .
git diff --check
```

The local replay helper creates a fresh LF Git checkout, applies only the candidate checkpoint/test/root attributes, and runs `python -m pytest -q tests` without development runtime binaries. This is Windows with Linux-style Git line endings, not a claim of running Ubuntu or GitHub Actions. The tracked checkout regression covers both Git settings in CI.

The first sandboxed clone attempt was blocked; authorized execution outside the sandbox allowed the tests to run. Early expanded regressions failed on the additional line-ending cases described above; they were corrected without weakening assertions. The final results are recorded below after completion. No commit or push was performed.

Final actual results:

- Targeted checkpoint/checkout tests: 17 passed in 13.79 s.
- Full workspace suite: 548 passed, 175 subtests passed in 214.35 s; exit 0. Log: `.build-cache/ci-checkpoint-pytest-20261109.log`.
- Fresh LF checkout suite: 447 passed, 80 skipped, 175 subtests passed in 139.02 s; exit 0. Log: `.build-cache/ci-clean-lf-20261109.log`. The checkout lacks local development binaries and the unrelated uncommitted value-flow additions; its skips are not counted as passes.
- Ruff check: PASS; Ruff format: 105 files already formatted; `git diff --check`: PASS.
- Exact current inventory: 291/291. Exactly six documented hash migrations, all matching existing LF Git blobs. Step 9 scientific inventory: 161/161 unchanged.

No new Rust build, scientific benchmark, Ghidra extraction or remote GitHub Actions execution was performed for this metadata/checkout fix. Previously reported scientific results are not newly claimed results of this correction. The next user push must confirm the remote Ubuntu workflow result.
