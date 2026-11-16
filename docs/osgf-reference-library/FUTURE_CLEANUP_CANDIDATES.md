# Future cleanup candidates — zero deletions

Inspection date: 2026-11-12. Actions below are proposals, not authorization. Consumers were checked in scripts, tests and CI; absence of a code import does not establish absence of scientific use.

| Class / path | Purpose and consumers | CI | Scientific reproduction | Current reference workflow | Deletion risk | Suggested action |
|---|---|---|---|---|---|---|
| A: `ghidra_scripts/export_report.py`, `export_research_graph.py` | Static graph extraction; graph-first and controlled runners | Python tests; no live Ghidra CI | Yes | Yes | Critical | KEEP |
| A: `rust_engine/src`, `rules/seed_rules.json` | Original detector, local extraction, canonicalization, fingerprints and similarity | Cargo + acceptance | Yes, frozen contracts | Yes | Critical | KEEP |
| A: `scripts/graph_first.py`, `reference_coverage.py`, `reference_library.py`, `reference_benchmark.py` | Existing graph projections, directional coverage, catalog and evaluation | Python and canonical job | Yes | Yes | Critical | KEEP |
| A: `scripts/graph_first_evaluation.py`, `evaluate_operational_baseline.py`, `recovered_evidence.py`, `diagnose_baseline_core.py` | Reused metrics, command/serialization/Jaccard helpers | Python | Yes | Transitive imports | High; not obsolete helpers | KEEP |
| B: `rust_engine/operational`, `ghidra_scripts/export_pcode_evidence.py`, `pcode_extraction.py` | Optional original P-code pipeline and later extensions; controlled optional C/E | Operational Cargo/Python | Yes | Optional | High | OPTIONAL, preserve |
| B: `scripts/evaluate_value_flow.py`, `evaluate_multilevel_flow.py`, `semantic_flow.py` | Value flow, producer contexts, recovered parameters/effects/families; consumers include audit_semantic_layers, run_value_flow_study, run_semantic_benchmark and tests | Python | Yes | Not primary ranking | High; shared AUC helper still consumed | OPTIONAL, preserve |
| C: `datasets/osgf_*`, `tests/fixtures`, historical `docs/step*`, `docs/semantic-flow`, `docs/multilevel-flow` | Registered protocols, fixtures, provenance, labels, results and reports | Integrity and regression tests | Essential | Some indirect | Critical; frozen byte provenance | KEEP; non-destructive index/archive proposal only |
| C: `scripts/run_graph_first_study.py`, `create_graph_first_study.py` | Historical registered experiment; currently antivirus-blocked | Unit/contract tests | Essential to that protocol | Separate from new study | High | KEEP; never replace protocol with new D meaning |
| D: `.build-cache/reference-library-pilot-20261112`, `.build-cache/reference-library-pilot-authorized-20261112` | Failed sandbox/DWARF attempt logs and partial artifacts | No direct CI | Needed to explain this execution | No successful search inputs | Medium until provenance archived | ARCHIVE LATER; no deletion now |
| D: generated `.build-cache/*/projects` and Ghidra settings | Rebuildable development project databases | No direct CI | May be useful for manual diagnosis | Extraction intermediates | Medium; verify exported artifacts and receipts first | REMOVE ONLY AFTER APPROVAL and after evidence export |
| D: overlapping experiment launchers | Similar-looking launchers are not proven redundant: each pins different protocols and consumers | Varies | Yes | Some optional | High | KEEP pending consumer-by-consumer audit; no concrete launcher deletion proposed |

No active dependency is recommended for removal. No historical dataset, protocol, golden, implementation or fixture has been deleted or moved. A later cleanup requires explicit scope and preservation checks.
