# Step 10A diagnostic method

This is an audit of frozen v0.1, not a new evaluation or optimized model. All labels, splits, galleries, thresholds and algorithms remain unchanged. Counts refer to 218 unique judgments or 120 graphs; the two conditions are paired observations, not 436 independent judgments.

Reproduction commands, from the repository root in PowerShell:

```powershell
python scripts/evaluation_adapter.py --build
python scripts/diagnose_baseline_core.py
python scripts/diagnose_baseline_experiments.py --graph --step9
python scripts/diagnose_baseline_report.py
python -m pytest -q tests/test_diagnose_baseline_core.py
```

The scripts require the admitted Step 10 runtime catalog and pair matrix. Missing scientific inputs cause failure; no fixture substitutes for real evidence. Step 9 supplementary analysis requires the existing local run manifest referenced in STEP9_SUPPLEMENT.json. `evaluation_acceptance.py` reproduces the frozen evaluation without `--freeze`. The existing baseline directory is read-only except its explicitly ignored generated runtime.

Diagnostic outputs are UTF-8 LF, sorted JSON, with stable IDs and exact SHA-256 output hashes. Existing output disagreement fails instead of overwriting results. The complete analysis is replayed by `diagnose_baseline_report.py`; graph experiments compare twice and validate source provenance and condition-B parity with the frozen CLI. Runtime bundles, compiler outputs and Ghidra projects stay ignored. Exact prior diagnostic files survived the antivirus incident and were reproduced after source recovery.

Set Jaccard uses exact descriptor equality, not feature IDs. Multiset Jaccard uses integer min/max sums with unbounded Python integers, then the same f64 division order as Rust. Empty/empty is null; one-empty is zero; aggregation averages only comparable views. Zero is not null. Equality to 1 uses the parsed numeric value without rounding. Descriptor/hash collisions are checked separately. No graph is removed for being anchor-only.

Descriptive tags are negative >=0.9 and positive <0.5; these are forensic categories, not selected operating points. The frozen classifier uses >=0.3. The independent discovery search maximizes balanced accuracy with exact fractions and the preregistered highest-threshold/reject-all tie policy. No held-out tuning occurs. The score-only exploratory control is the minimum comparable view; no fitted weights or improvement claim.

ROC-AUC counts pairwise positive/negative wins, with half credit for ties. PR evidence is grouped-threshold average precision, explicitly not trapezoidal PR area. Missing scores and one-class subsets are unsupported, not imputed. Counts and denominators accompany all descriptive comparisons; dependence between source families precludes interpreting pairs as independent samples.

Retrieval uses only frozen judged edges. Rank ties use reference graph ID. K greater than gallery size is unsupported. Zero-positive queries are ineligible. Positive-only, mixed and hard-negative mixed subsets are diagnostics over unchanged galleries. Constant-ID ordering, perfect-label upper bound and twenty reproducible random permutations (seeds 101..120 salted by query ID) supply controls. Random ranges describe permutation variability, not inferential confidence intervals. A per-view ranking with any null candidate is unsupported rather than silently dropping candidates.

Normalization correspondence follows raw source identities within the same local document. A/B is a bundled intervention: per-operation causal effects must not be inferred from the bundle. Node-kind feature changes can be attributed directly where that descriptor explicitly carries the evidence kind; edge context facts are not current semantic feature slots. Graph-level synthetic probes isolate supported operations; they are not binary performance evidence.

The fresh C/Ghidra micro-experiment was interrupted by Bitdefender on 2026-10-27. Its source is retained for inspection, but the CLI now refuses that branch pending detection review. It is NOT RUN to completion, not a passing real extraction. No security exclusions or protection changes were made. Real-data evidence below comes from admitted existing graphs, with newly recomputed source-level witnesses and fingerprint comparisons, clearly distinguished from a fresh binary run.
