## MICROSTEP 5 — Controlled validation and malware admission — 2026-11-12
STATUS: benign pilot and admission infrastructure implemented; broader independent corpus and authorized malware remain outstanding.
OBJECTIVE: exercise actual observable-seeded binaries without executing them or fabricating malware provenance.
EXISTING CODE REUSED: existing Ghidra graph/P-code exporters, Rust automatic detector and optional operational binding; controlled_corpus compiler inventory.
NEW CODE: scripts/run_reference_controlled.py; BENCHMARK_PROTOCOL.md.
FILES MODIFIED: additive runner/documentation only; no historical dataset changes.
TESTS RUN: GCC O0/O2 compilation and Ghidra static extraction completed; 9 source-labeled comparisons, exact deterministic reruns, 3/3 annotated regions recovered per build and 5 automatic seeds searched per query binary. P-code counterpart also completed. Full Python regression: 646 passed, 175 subtests passed in 308.43s; subsequent narrow validation additions are tested separately.
REGRESSION STATUS: original Rust 252 passed, operational Rust 258 passed, both fmt/Clippy passed; canonical 7, fingerprint 11, similarity 20 acceptance tests passed.
SCIENTIFIC RESULTS: this is a small discovery-only benign pilot, not malware validation; comparisons and detailed limitations are in the scientific report.
LIMITATIONS: one authored source lineage; no independently held-out lineage. A first run failed with GCC sandbox WinError 623; approved native execution succeeded. A DWARF O2 import failure was preserved and a fresh no-DWARF run completed. Existing quarantined graph-first study remains untouched.
NEXT STEP: finish cross-compiler pilot, final reporting and cleanup inventory. No malware download/execution or security changes.
