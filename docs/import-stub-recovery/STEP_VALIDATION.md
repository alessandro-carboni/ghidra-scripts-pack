
## Import-stub recovery - real comparison and final validation - 2026-11-13
STATUS: completed opt-in benign experiment; broader scientific acceptance remains incomplete.
IMPLEMENTATION: new derived source views recover 3/3 annotated socket regions per O0/O2 build (previously 0/3), using exact import/call bytes. Original graphs, default detector, old registrations, labels and split assignments remain unchanged. Existing operational exports rebound to six exact new structural contexts.
REAL TEST: nine source-labeled cross-optimization pairs. A/B/D graph and coverage AUC=0.50, MRR=0.833333; C operational-only AUC=1.00, MRR=1.00; E optional refinement MRR=1.00 with unchanged graph-score AUC=0.50. Graph-only evidence does not discriminate this TCP/UDP hard negative. Four complete JSON comparison outputs are byte-identical across reruns.
VALIDATION: fresh full Python suite 670 passed + 175 subtests passed in 229.37s. Targeted suite 68 passed; canonical/fingerprint/similarity acceptance 7/11/20 passed. Ruff/format checks passed. 1242-path inventory has only authorized CI/attributes changes; 30 historical pilot, 10 separated-study and 7 experiment artifact hashes verified. Both new graphs/proofs reconstruct exactly; scientific fixtures/goldens unchanged. No new Rust code; earlier Rust unit/clippy results are historical, not rerun claims.
COMMANDS (PowerShell from C:\Users\aless\Desktop\ghidra-scripts-pack):
```powershell
python -m pytest -q tests
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
git diff --check
```
EVIDENCE: docs/import-stub-recovery/REPORT.md, RESULTS.json, proof-O0.json, proof-O2.json; .build-cache/socket-import-experiment-20261113/; .build-cache/import-stub-full-pytest.log.
LIMITATIONS: small post-observation experiment, not fresh independent heldout evidence. No discovery threshold, classifier/FPR guarantee or malware generalization claim. Discovery fixture remains antivirus-blocked and untouched; authorized independently annotated malware is unavailable. Earlier negative P-code pilot findings remain preserved alongside this positive case.
RESUME POINT: opt-in socket observation recovery and its comparison are complete. Remaining work requires safe available discovery data/calibration and genuinely independent authorized validation; do not repeat completed engineering or silently enable experimental recovery. Branch codex; HEAD ff4e097351d0b64e0f9f03bede98d0d5db7c41fe. No commit, push, deletion or antivirus exclusions.
