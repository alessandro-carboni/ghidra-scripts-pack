# Step 10.3 — admitted graph catalog, not pairwise scores

The user approved the Step 10.2 A/B definition with “ok continua con step
successivo”. `research_adapter/approval.json` records that instruction and binds
the exact prior gate evidence. The earlier pending-review evidence, method
heading and build banner remain historical snapshots, not the current admission
decision. Catalog planning verifies approval, all approved code/method hashes,
the unchanged dependency inventory and the frozen Step 10.1 protocol.

`scripts/evaluation_catalog.py` includes every one of the 120 frozen graph IDs in
both conditions (240 graph-condition records), preserving sample, build, routine,
source group, split, anchor, original canonical path/hash, canonical scientific
digest, upstream typed-graph hash and embedded local-input serialization hash.
No label, pair relation or measured similarity enters feature generation.
Anchor-only, weak and incomplete-observability graphs are not excluded.

The record identity hashes all source metadata, condition, protocol and approval
hashes, actual executable hashes, generator code/version and motif configuration.
Equal canonical scientific digests are not an identity key: source-bearing
artifacts are produced independently for each graph. A bundle includes the exact
serialized local input plus graph, fingerprint, coverage and verified provenance.
B uses the frozen `fingerprint-canonical` CLI and its original sidecar format.
Original canonical inputs are never rewritten or impersonated by A documents.

Generated files are stored in ignored `runtime/catalog-v0_1/`. The versioned
`graph_catalog.json` is an exact copy of its completed `catalog.json`; artifact
paths in that catalog are relative to the runtime catalog directory. Reproduce
the runtime files from the immutable frozen inputs rather than committing them.
The generated local-input bytes use sorted, indented UTF-8 JSON with LF and one
final newline; their hash is explicitly distinct from the original canonical
file hash and from any compiled-source provenance. Engine outputs are retained
as exact bytes, not reserialized or newline-normalized.

Planning/dry-run creates no output. Materialization uses a temporary staging
directory on the destination volume and publishes through a directory rename.
Existing destinations cause an error; no overwrite or silent cache reuse.
All engine/provenance failures are recorded per graph-condition as failed with
no admitted artifacts; a completed failure-coverage catalog is INCOMPLETE and
the command exits nonzero. An I/O abort cannot publish a partial PASS catalog.
Runtime diagnostics appear on the terminal, not as personal paths in science.

Verification rejects missing, extra, redirected or modified files; stale
input/code/version/config identity; duplicate artifact paths; wrong source
sidecars; incomplete catalogs; and invented record metadata. It always rebuilds
every artifact from the source and compares exact hashes and complete record
metadata. Even an attacker updating a corrupted sidecar's stored hash cannot
make it agree with the reconstructed source. There is no hash-only verification
flag. Cache validation therefore costs extraction, which is deliberate at this
scientific gate and must not be counted as zero-cost runtime later.

Executable hashes bind the local build environment. Another OS/compiler/profile
must produce a new catalog identity, not silently reuse this catalog. Tests run
the actual local frozen/research executables when present; when engines are
unavailable they explicitly skip integration checks. Hosted Linux CI is not
claimed as executed by local Windows validation.

Reproduction (PowerShell, repository root; output directories must be new):

```powershell
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/evaluation_adapter.py --build
python scripts/evaluation_catalog.py --dry-run
python scripts/evaluation_catalog.py --materialize
python scripts/evaluation_catalog.py --verify
python scripts/evaluation_catalog.py --materialize --output datasets/osgf_baseline_evaluation_v0_1/runtime/catalog-replay-v0_1
python -m pytest -q tests/test_evaluation_catalog.py
```

`catalog_validation.json` records the executed coverage and independent replay
proof. Complete regression commands/results are in `VALIDATION.md`. This step
does not calculate the 218 pair scores, thresholds, rankings, Recall or MRR.
Those belong to subsequent steps; no final Step 10 freeze or Step 11 is implied.
