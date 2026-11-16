# Curated reference library v0.1.0

OSGF is an evidence-based, observable-seeded local subgraph similarity and retrieval methodology. A library stores evidence, not malware verdicts.

`osgf.reference-library/0.1.0` is a sorted JSON manifest of immutable, SHA-256-addressed `osgf.reference-entry/0.1.0` records. Each record binds sample SHA-256, acquisition/source authorization, executable format and architecture, optional uncertain family attribution, a separately annotated functional region, automatic seed triggers, extraction configuration, canonical and fingerprint digests, extraction tool version, and provenance reference. Classification is one of documented malicious functionality, malware-associated functionality, generic functionality, benign reference or unknown. Documented malicious functionality requires a verified annotation; this validation cannot certify the truthfulness of an analyst's claim. Family membership never supplies pair labels.

Registration reads and hashes the actual supplied sample; it does not execute it or copy it into the library. The automatically detected seed must bind that same SHA in extraction metadata. This is consistency validation, not independent attestation of the extractor. Manifest/entry hashes detect corruption relative to the current manifest, not an attacker replacing an entire unsigned library. Benchmark preregistration pins the catalog bytes externally.

Stored graph-first envelopes are validated using the original implementation. `osgf.frozen-reference/0.1.0` explicitly wraps existing canonical and frozen fingerprints plus the origin graph. Validation reconstructs their original bytes and derives a transient graph-first adapter; stored source artifacts are not migrated or rewritten. Unknown schemas are incompatible. Optional P-code must have exactly matching structural context and binary provenance. Without an operational engine it is only hash-checked, not semantically revalidated or scored.

Entries and artifacts are immutable. Duplicate stable IDs are rejected, including attempted annotation replacement. A reference ID hashes sample bytes, region ID, canonical digest, semantic digest, and stored schema. Multiple regions and multiple binaries are allowed. Metadata revisions need a new explicit schema/migration policy; no silent in-place update exists. Writers use an exclusive lock and atomic manifest replacement. Failed writes can leave unreferenced content-addressed artifacts; they cannot create a valid catalog entry. A crash can leave a lock requiring explicit inspection. Paths escaping the library or redirected by symlink/junction are rejected.

JSON written here uses UTF-8, deterministic sorted serialization and LF. Imported artifact bytes are preserved exactly; their byte hash differs from semantic digests. New Python modules have LF checkout attributes.

Search validates every candidate and retains unavailable, malformed and incompatible statuses separately. It reports coverage, original symmetric scores, matched/missing/extra evidence with provenance, observability warnings, candidate count and deterministic ties. Policies are separately named/versioned; no malware threshold is introduced. See [coverage contract](../reference-coverage/CONTRACT.md) for exact denominators and empty-view semantics.

Workflow extraction reuses all existing automatic seeds. Each seed has an independent ranking. No seed remains ineligible, not zero similarity. There is no executable-level score. Relation-aware coverage remains distinct from base-evidence coverage; structural agreement does not prove equivalent behavior.

## PowerShell CLI

Run from the repository root. Paths below are user-supplied artifacts, not bundled malware.

```powershell
$engine = '.\rust_engine\target\debug\rust_engine.exe'
python scripts/reference_library.py init --library .build-cache/my-reference-library
python scripts/reference_library.py register --library .build-cache/my-reference-library --engine $engine --artifact path/to/seed-fingerprint.json --sample path/to/authorized-sample --annotation path/to/annotation.json
python scripts/reference_library.py validate --library .build-cache/my-reference-library --engine $engine
python scripts/reference_library.py list --library .build-cache/my-reference-library --engine $engine
python scripts/reference_library.py inspect --library .build-cache/my-reference-library --engine $engine --reference-id 'reference:REPLACE_WITH_ACTUAL_ID'
python scripts/reference_library.py search --library .build-cache/my-reference-library --engine $engine --query path/to/query-fingerprint.json --policy reference_set --output .build-cache/new-ranking.json
python scripts/reference_library.py workflow --library .build-cache/my-reference-library --engine $engine --query path/to/binary.graph.json --output .build-cache/new-all-seed-search
```

Optional `--operational` and `--operational-engine` are accepted for registration and single-seed search. Python workflow callers may supply an anchor-to-operational-artifact mapping. The CLI does not infer operational context or reuse one artifact for unrelated seeds.
