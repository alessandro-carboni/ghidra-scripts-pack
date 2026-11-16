# Steps 10B.5–10B.6 — operational graph and local context

Decision: hybrid envelope. Existing TypedGraph 0.12.0 is retained verbatim as the structural component, with separately typed per-function operation/dependency networks. Flat function attributes alone would lose direction/operand slots. Promoting every P-code operation into the legacy call/evidence graph would alter seed/traversal semantics and inflate node budgets. The new osgf.typed-operational-graph/0.2.0 contract does neither.

Admission validates the original Rust graph contract, recorded research_binary_sha256, P-code source hashes, function membership, one layer per bundle, duplicate functions and common extraction environment. A raw/high mix is rejected. This binds observed IDs within one binary; it does not authenticate arbitrary supplied binary metadata independently of the acquisition protocol.

The osgf.local-operational-subgraph/0.2.0 contract reuses the existing anchor traversal, caller/callee depth and structural node/edge limits without modification. Operational evidence attaches only to selected functions. Source graph digest and binary hash identify the input; the local document does not embed or traverse the entire program's operation networks. Only selected evidence is retained.

ContextConfig separately specifies structural selection and positive max_operational_functions, max_operations, max_dependencies. These are resource budgets, not decision thresholds. Retention is anchor-first then function-ID order, operation-ID order and dependency tuple order. IDs are provenance-based tie breakers under resource exhaustion; no relocation invariance of a truncated selection is claimed. Oversized documents retain a prefix and only valid retained dependencies; partial/truncated state survives. Missing extraction and budget exclusion are separately recorded for every selected function. Empty observed documents remain distinct from missing/unavailable documents.

These modules are in operational_context.rs and operational_schema.rs; the CLI is explicit and opt-in. Legacy nodes/edges, defaults and anchor-only support remain unchanged. Canonicalization and features must consume the selected network with operand direction, provenance and observability intact. Future LLM edits can therefore be verified against bounded, immutable source documents; no LLM transformation is included here.

Packaging correction: the final operational CLI is rust_engine/operational/target/debug/osgf_operational.exe. The original main.rs remains byte-identical to the Step 10A checkpoint; the original single-binary Cargo manifest remains unchanged.

Final packaging: build the isolated crate with `cargo build --locked --manifest-path rust_engine/operational/Cargo.toml`. It shares original source modules by path and uses the same locked third-party dependencies, while preserving the frozen original Cargo.toml/Cargo.lock and main.rs. CI has a dedicated operational-baseline job.
