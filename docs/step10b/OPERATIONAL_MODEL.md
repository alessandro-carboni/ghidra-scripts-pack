# Step 10B.2–10B.3: experimental operational evidence

Status: implemented prototype contract, not a completed v0.2 baseline. Date: 2026-11-03.

## Architecture decision and file plan

The existing typed graph is 0.12.0, not 0.1.0. The standalone contract is therefore named `osgf.pcode-evidence/0.1.0`; it does not silently advance the typed graph version. Python contract/validation lives in scripts/pcode_evidence.py, the runtime-neutral Ghidra adapter in ghidra_scripts/pcode_extraction.py and the explicit PyGhidra entrypoint in ghidra_scripts/export_pcode_evidence.py. Tests live in tests/test_pcode_evidence.py. Subsequent graph mapping, Rust canonicalization, fingerprint and similarity must remain separate opt-in modules/commands. No existing exporter, loader, seed rule or scientific algorithm is changed.

Raw-first acquisition is retained. High is implemented as a separate requested representation because recovered inter-instruction SSA is needed to investigate behavior; it never silently replaces Raw. Each extraction produces a separate document. Its comparability domain includes representation, Ghidra revision, language, compiler specification and extraction policy. A future representation must reject mismatched domains unless a separately validated compatibility rule exists.

## Operational model

Each operation has an opcode, family, signedness assertion, ordered operands, optional output, stable extraction-local operation ID and original sequence origin. Operands retain byte widths, storage class, address space and offset; constants preserve their exact width-bounded bit patterns. Result width is observable; source-language types and signedness not established by the opcode are **not asserted**. Boolean and bitwise operations remain distinct, as do signed/unsigned division, shifts and predicates. ADD/SUB, all comparison predicates and constants remain distinct.

LOAD/STORE operand positions preserve address/value relationships and access widths. PTRADD/PTRSUB remain explicit analysis operations. Memory region classification, alias equivalence and ABI input/output assignment are not inferred. Control opcodes preserve ordered branch destinations/conditions, calls and return operands, but these are not a recovered CFG, a proof of control dependence or a source-language return-value summary. CALLIND is indirect; CALLOTHER, UNIMPLEMENTED and unknown operations remain visible with unsupported warnings. MULTIEQUAL and INDIRECT are explicitly analysis artifacts.

Dependencies identify producer operation, consumer operation, operand slot and proof basis. Raw admits only preceding exact unique-storage definitions within one machine instruction, invalidates overlapping writes and clears definitions at control transfers. It does not infer cross-instruction register flow. High uses Varnode.getDef() references to retained operations and marks them recovered-ssa. Missing definitions, input registers, memory values and producers outside the budget remain unresolved. A future bounded path can traverse these links; opcode co-occurrence alone is never a dependency.

These relationships can distinguish typed arithmetic, predicate and memory patterns beyond an opcode list, but do not prove equivalence. Return dependencies in Raw often remain unavailable; this is an architectural limit, not a negative behavioral label. High's reconstructed SSA is conditional on analysis settings.

## Contract and serialization

The strict validator rejects unknown/missing fields, unsupported versions, invalid widths/hash/IDs, duplicate operations/origins/JSON keys, dangling or contradictory dependencies and inconsistent completeness/budgets. Function ID is bound to its entry within a source SHA document. Source binary name and original storage/sequence values are provenance, never cross-binary semantic features. High sequence origin is an analysis association, not proof of a one-to-one machine instruction.

Canonical document encoding is UTF-8 without BOM, LF, sorted object keys, operation order by numeric extraction ID, dependency tuple order, sorted unique warnings and one terminal newline. No host paths, durations or wall clocks occur in the document. Stable ordering does not imply compiler-independent canonicalization; that belongs to 10B.7.

Limits default to 10,000 operations, 20,000 dependencies, 30 decompiler seconds per function and are configurable through the extraction API. Operation iteration stops after budget+one and records a lower bound, not a fictitious total. Only retained producers/consumers are linked. Budget exhaustion is partial/truncated, never empty-complete. Decompiler failure, timeout, cancellation and absent HighFunction are explicit states. Complete with zero operations means a successful empty observation, distinct from those failures. Raw unresolved inputs and unsupported operations are retained independently of extraction completeness.

## Remaining gates

10B.4 must validate real sum_array/count_matches/copy_buffer, selected transformations, compiler/optimization variation and repeated-run bytes. No new fingerprint is accepted before that gate. 10B.5 must compare structured attributes, explicit nodes and hybrid attachment; 10B.6 must restrict attachment to already selected functions; 10B.7 must document individually tested rules. 10B.8–10B.10 require Rust integration, support-aware mathematics, ablations and an independent scientific evaluation. Those are not implemented by this contract alone.
