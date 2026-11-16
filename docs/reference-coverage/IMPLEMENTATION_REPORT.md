# Chapters 0–6 completion — 2026-11-11

## MICROSTEP 0: preimplementation audit

STATUS: PASS. Fetched origin/codex; actual local/remote HEAD ff4e097351d0b64e0f9f03bede98d0d5db7c41fe. Initial working tree clean. Source, contracts and scientific inventories inspected; see AUDIT.md. Report already appended to DONE TESI. The user explicitly confirmed chapters 0–6 of the attachment (microsteps 0 and 1), not the later library/benchmark microsteps in TODO TESI.

## MICROSTEP 1: reference coverage similarity

STATUS: implementation and required validation PASS.

OBJECTIVE: expose directional reference evidence coverage without replacing existing similarity or extending operational representations.

CURRENT IMPLEMENTATION: new opt-in `scripts/reference_coverage.py` with `compare` and `validate` commands. Exact integer numerators/reference denominators, unit weights and final rational-to-float conversion; empty reference null, no match zero. Matched evidence, occurrence deficits, surplus query observations and source provenance are separately reported. Result reconstruction rejects tampering and incorrectly typed scores. Existing graph-first/Rust validation and Jaccard results are reused unchanged.

ARCHITECTURAL DECISION: the main scalar explicitly measures the disjoint normalized base-value collection (APIs, literal strings, contextual constants and locally attached section facts). String categories remain separately reported derived evidence. Seed triggers and motifs do not add independent votes. Relation-aware coverage retains whole descriptors in each existing view; its overall value is intentionally undefined, avoiding an unjustified aggregate of correlated features. No additional canonicalization, API alias, learned weight, decision threshold or malware verdict.

SOURCE FILES INSPECTED: scripts/graph_first.py and its evaluation/contract; rust_engine/src/canonical.rs, fingerprint.rs, fingerprint_provenance.rs, similarity.rs, similarity_observability.rs; seed/export source and historical experiment contracts described in AUDIT.md.

FILES CREATED: scripts/reference_coverage.py; tests/test_reference_coverage.py; docs/reference-coverage/AUDIT.md, CONTRACT.md, IMPLEMENTATION_REPORT.md and validation/integrity receipts.

FILES MODIFIED: scripts/.gitattributes (only the new script's LF rule); .github/workflows/ci.yml (runs the new source-bound tests alongside graph-first tests after building the original engine). No existing scientific source, protocol, result, fixture or golden changed. No existing graph-first implementation was duplicated.

CONTRACT CHANGES: new `osgf.reference-coverage/0.1.0`; all existing contracts/defaults retained. Full contract and formulas: CONTRACT.md.

LEGACY COMPATIBILITY: 1,230/1,232 previously tracked files remain byte-identical; only the two declared infrastructure files changed. Protected checkpoint 291/291 and scientific inventory 161/161 pass. Existing canonical/fingerprint/similarity goldens pass. Old graph-first protocol and amendments remain untouched.

TESTS EXECUTED (actual results, this increment):

- Targeted coverage: 18 passed in 9.60 s.
- Full Python suite: 624 passed, 175 subtests passed in 258.22 s; no skips/failures in this run.
- Original Rust suite: 252 passed. Cargo format and Clippy with warnings denied passed.
- Canonical acceptance: 7 passed; fingerprint acceptance: 11 passed; similarity acceptance: 20 passed.
- Portability/exact hashes/audit-strata determinism: PASS (35 samples, 27 builds, 68 routines, 120 graphs, 218 pairs).
- Legacy real Notepad similarity: 25/25 graphs, 75 comparable views, 10 warning-bearing graphs, 25/25 deterministic reruns.
- New coverage real Notepad integration: 25/25 self-comparisons; all comparable per-family/per-view scores equal 1, empty reference collections null; full result bytes deterministic across reruns. Base-value counts ranged from 5 to 206. Source/result hashes are in NOTEPAD_SMOKE.json.
- Ruff check PASS; Ruff format check PASS (123 files); git diff --check PASS.

SCIENTIFIC RESULTS: required numerical examples verified through actual canonical/fingerprint inputs: 2/3 APIs, 4/5 observations = 0.8, directional coverage and distinct structural attachment scores. Extra query evidence does not lower coverage but is preserved in symmetric similarity and extra-evidence partitions. These demonstrate mathematical semantics and integration, not malware retrieval quality or better discrimination.

KNOWN LIMITATIONS: unit-weight generic facts are not necessarily distinctive; repeated occurrences are not calibrated confidence; coverage does not prove semantic equivalence. The previous graph-first prospective study remains incomplete and its quarantined file/results remain absent. No attempt was made to change antivirus settings, remove a sample, overwrite that protocol or obtain malware. Operational Rust tests from earlier work are not presented as newly rerun here; existing operational sources are unchanged and the full Python suite passed.

NEXT MICROSTEP: none within the confirmed chapter 0–6 scope. Malware reference library and subsequent benchmark work await a separate instruction. No commit or push.

## Mandatory test matrix

| Requirement | Evidence |
|---|---|
| 1: two matching APIs out of three | Pure arithmetic and real projected API test |
| 2: four distinct observations out of five | Real API/string/local-section source projection = 0.8 |
| 3–5: direction, identity, empty reference | Independent denominator oracle; self/empty/disjoint cases |
| 6–7: query extras preserved | Coverage unchanged; Jaccard lower; surplus occurrence partitions |
| 8: changed structural attachments | Value coverage 1 while typed relational coverage <1 |
| 9: multiplicities | 2/5 occurrences, explicit deficit; exhaustive 4^4 small-count inputs; totals >u64 |
| 10: unresolved/truncated evidence | No invented matches; qualified missing API evidence |
| 11: correlated features | Category/seed/motif evidence excluded from base-value aggregate |
| 12: invalid provenance | Altered canonical provenance rejected by existing source reconstruction |
| 13: deterministic serialization | Repeated full results and result revalidation; CLI overwrite refusal |
| 14: existing Jaccard unchanged | Byte-identical serialized baseline/graph-first fields before/after; frozen acceptance goldens |

## Commands and receipts

PowerShell working directory: `C:\Users\aless\Desktop\ghidra-scripts-pack`.

```powershell
git fetch origin codex
git rev-parse HEAD
git rev-parse origin/codex
git status --short
python scripts/validate_dataset_portability.py
python -m pytest -q tests/test_reference_coverage.py
python -m pytest -q tests
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
python .build-cache/reference-coverage-notepad-smoke.py
python -m ruff check .
python -m ruff format --check .
git diff --check
```

Full-suite log: `.build-cache/reference-coverage-full-pytest.log`. Legacy regression log: `.build-cache/reference-coverage-regressions.log`. New real-data log: `.build-cache/reference-coverage-notepad-smoke.log`. Current-run command receipts and hashes are in this directory. The local smoke helper's exact source is preserved below for reproduction; the Notepad dataset is intentionally local and not added to Git.

<!-- The executed smoke helper is appended verbatim below. -->

```python
import sys

sys.path.insert(0, ".")
from scripts import graph_first as g
from scripts import reference_coverage as rc
from pathlib import Path
import hashlib, json

engine = Path("rust_engine/target/debug/rust_engine.exe")
files = sorted(Path("reports/canonical-notepad-step5").glob("seed_fn_*.json"))
assert files, "Real canonical dataset unavailable or empty"
rows = []
for p in files:
    canonical = g.load(p)
    fp = g.fingerprint(canonical["source_document"], engine)
    result = rc.compare(fp, fp, engine)
    assert g.encoded(result) == g.encoded(rc.compare(fp, fp, engine))
    for collection in [result["reference_coverage"], *result["evidence_value_coverage"]["per_family"].values(), *result["relation_aware_coverage"]["per_view"].values()]:
        assert collection["set"] == (1.0 if collection["reference_distinct"] else None)
        assert collection["multiset"] == (1.0 if collection["reference_occurrences"] else None)
    rows.append(dict(file=p.as_posix(), source_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), result_sha256=hashlib.sha256(g.encoded(result)).hexdigest(), base_reference_values=result["reference_coverage"]["reference_distinct"], warnings=len(result["evidence_support"]["warnings"]), deterministic=True))
    print("PASS", p.name, "base values", rows[-1]["base_reference_values"], "deterministic=yes", flush=True)
Path("docs/reference-coverage/NOTEPAD_SMOKE.json").write_text(json.dumps(dict(status="PASS", graphs=len(rows), purpose="Real-data integration/self-comparison; not retrieval accuracy or malware validation", rows=rows), indent=2) + "\n", encoding="utf-8")
print("SUMMARY", len(rows), "/", len(files), "PASS", flush=True)
```
