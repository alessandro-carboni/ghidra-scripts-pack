# Current completion status — 2026-11-04

Final delivery sync (2026-11-05): appended FINAL_REPORT_2026-11-04.md to Obsidian DONE TESI with the completion-sync marker. Verified all 225561 pre-existing bytes unchanged and the exact 5280-byte append. Backup: .build-cache/step10b/DONE-TESI-before-final-sync-2026-11-05.md. Rechecked all 291+161 protected hashes, pinned final implementation/executable and original study result bytes; PASS. No additional test execution is implied by this synchronization.

Step10B.2–10B.10 implementation and technical validation are complete. The historical entries below remain an audit trail, not the current pending state. Current results: [FINAL_REPORT_2026-11-04.md](FINAL_REPORT_2026-11-04.md), [VALIDATION.md](VALIDATION.md), [ACCEPTANCE.md](ACCEPTANCE.md), and [scientific report](../../datasets/osgf_baseline_evaluation_v0_2/REPORT.md).

Final CLI: `cargo build --locked --manifest-path rust_engine/operational/Cargo.toml`, then `rust_engine/operational/target/debug/osgf_operational.exe`. Old main/Cargo/goldens are unchanged. Full Python 526 + 175 subtests, Rust original 252 / isolated 258; scientific replay 279/279 outputs identical. Heldout MRR improves in the small pilot, but balanced accuracy remains 0.50; no general classifier improvement is claimed. No LLM work, commit or push.

---

# Step 10B cumulative implementation report

Latest checkpoint: [REPORT_SYNC_2026-11-04.md](REPORT_SYNC_2026-11-04.md). That report supersedes the intermediate test counts below and records the real extraction results and outstanding gates. It was appended successfully to DONE TESI on 2026-11-04 using an authorized write outside the workspace. The entire pre-existing note byte prefix was verified unchanged and the appended text matched the prepared report. A pre-append backup is in .build-cache/step10b/DONE-TESI-before-sync-2026-11-04.md. This does not change the session's permanent writable roots.

Date: 2026-11-03. Branch codex; HEAD 66bcc9dda267aac29f7ea79a60ff6727a7340ada. Scope requested: 10B.2–10B.10. This report does not claim the whole scope complete.

## MICROSTEP: 10B.2 — Operational evidence model

STATUS: PASS for model/prototype targeted tests; real-data gate pending.

OBJECTIVE: Preserve operational information beyond opcode counts.

SOURCE FILES INSPECTED: export_research_graph.py; existing graph/local/canonical contract map; Step 10A CHECKPOINT.json; Step 10B architecture/API research; controlled numeric/memory sources; Cargo.toml; regression runner; frozen manifest; step9_preflight.py.

FILES CREATED: scripts/pcode_evidence.py; ghidra_scripts/pcode_extraction.py; ghidra_scripts/export_pcode_evidence.py; tests/test_pcode_evidence.py; docs/step10b/OPERATIONAL_MODEL.md; this report.

FILES MODIFIED: No existing production components.

ARCHITECTURAL DECISIONS: Raw-first, separate requested High documents. Instruction-local unique dependencies versus recovered SSA. No inferred ABI arguments, memory aliases or full control dependence.

IMPLEMENTATION DETAILS: Ordered operands, widths, constant bits, signed predicates, output and sequence origin retained. Unsupported operations explicit. Bounded extraction and distinct failure states.

SCHEMA CHANGES: New standalone osgf.pcode-evidence/0.1.0; legacy contracts unchanged.

BACKWARD COMPATIBILITY: Pre-change checkpoint verification PASS, 291/291 exact hashes unchanged. No legacy commands changed.

TEST RESULTS: PASS — `python -m pytest -q tests/test_pcode_evidence.py`: 34 passed. PASS — `python -m ruff check scripts/pcode_evidence.py ghidra_scripts/pcode_extraction.py ghidra_scripts/export_pcode_evidence.py tests/test_pcode_evidence.py`.

SCIENTIFIC EVIDENCE: These are synthetic API adapters, not real binary measurements.

KNOWN LIMITATIONS: No full Raw dataflow, alias proof or return ABI recovery; no v0.2 integration yet.

NEXT MICROSTEP: 10B.3 validation, then 10B.4 real extraction gate.

## MICROSTEP: 10B.3 — Standalone P-code evidence contract

STATUS: PASS for Python contract prototype; empirical extraction reproducibility pending.

OBJECTIVE: Versioned strict validation and deterministic UTF-8/LF serialization.

SOURCE FILES INSPECTED: Existing schema conventions and operational model.

FILES CREATED: Shared files in 10B.2 above.

FILES MODIFIED: No legacy production files.

ARCHITECTURAL DECISIONS: Provenance fields are not portable semantic descriptors; no premature numeric bump to Typed Graph 0.12.0.

IMPLEMENTATION DETAILS: Reject invalid version, duplicate IDs/origins/JSON keys, dangling references, inconsistent storage, invalid widths and budget/completeness contradictions. Explicit complete/partial/unavailable/timeout/cancelled/failed states.

SCHEMA CHANGES: osgf.pcode-evidence/0.1.0 only.

BACKWARD COMPATIBILITY: No frozen scientific output altered.

TEST RESULTS: PASS — same 34 tests include round-trip, order, duplicates, invalid JSON, provenance, truncation and decompiler lifecycle. PASS — `cargo test --locked --manifest-path rust_engine/Cargo.toml`: 252 passed, 0 failed (fresh execution on this date).

SCIENTIFIC EVIDENCE: No synthetic test presented as a real Ghidra experiment.

KNOWN LIMITATIONS: Rust consumer and production integration belong to later gated microsteps.

NEXT MICROSTEP: 10B.4; do not integrate fingerprints before real extraction passes.


## Real scientific replication — 2026-11-05

Executed the full real Ghidra pipeline again with final implementation, fresh projects/settings, 9 builds, 27 routines and 81 cross-build pairs. See [replication report](../../datasets/osgf_baseline_evaluation_v0_2/replication-2026-11-05/REPORT.md). All fingerprints and pair scores match the historical study exactly; repeated within-run outputs are byte-deterministic. Heldout MRR improves 0.666667 to 0.777778, but balanced accuracy remains 0.50. No general classification superiority or new independent heldout is claimed. Old result/protocol bytes and all protected inventories remain unchanged. New driver scripts/run_operational_replication.py selects a separate registered study without modifying evaluation mathematics. Two elevated-launch review timeouts were resolved by successfully running inside the restricted environment; no protections changed.

Obsidian synchronization for the 2026-11-05 real replication: BLOCKED by permission-review timeouts; computer-use alternative unavailable. Report exists locally but was NOT appended to DONE TESI. See replication-2026-11-05/note_sync_status.json. Scientific experiment itself completed successfully.
