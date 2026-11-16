"""Step 10.10: reconstruct all results and publish an immutable baseline freeze."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

try:
    from . import evaluation_stratification as strat
    from . import evaluation_runtime as runtime
    from . import evaluation_replay as replay
except ImportError:
    import evaluation_stratification as strat
    import evaluation_runtime as runtime
    import evaluation_replay as replay

g, m, s = strat.g, strat.m, strat.s
require, serialize = g.require, g.serialize


def check_observation(observation, protocol, matrix, catalog):
    require(observation["status"] == "PASS", "benchmark incomplete")
    require(observation["generator_utf8_lf_sha256"] == g.pairs.sha(Path(runtime.__file__).read_text(encoding="utf-8").encode()), "stale benchmark implementation")
    require(observation["protocol_sha256"] == g.pairs.sha(serialize(protocol)) and observation["matrix_sha256"] == g.pairs.sha(serialize(matrix)) and observation["catalog_sha256"] == g.pairs.sha(serialize(catalog)), "benchmark input mismatch")
    expected = []
    for repetition in range(6):
        for condition in ("A", "B"):
            stages = ["input_validation_loading", "combined_canonicalization_feature_extraction"]
            if condition == "B":
                stages += ["B_only_canonicalization", "B_only_feature_extraction"]
            expected.extend((repetition, condition, stage, r["graph_id"]) for r in catalog["records"] if r["condition"] == condition for stage in stages)
            expected.extend((repetition, condition, "pair_comparison_with_validation_and_io", r["pair"]["pair_id"]) for r in matrix["records"] if r["condition"] == condition)
            expected.append((repetition, condition, "ranking", "all_queries"))
    require(all(r["status"] == "success" for r in observation["observations"]), "failed benchmark sample")
    require(runtime.summarize(observation["observations"], expected) == observation["summary"], "benchmark summary mismatch")


def verified_results():
    protocol, matrix, catalog = g.admitted_scores()
    g.pairs.catalog.verify(g.pairs.CATALOG, g.pairs.catalog.plan())
    galleries = g.galleries(protocol, matrix)
    thresholds = m.calibrate(matrix)
    metrics = m.evaluate(protocol, matrix, galleries, thresholds)
    stability = s.evaluate(matrix, galleries, catalog)
    folder = g.ROOT / "datasets/osgf_pairs_v0_1"
    manifest, strata, holdouts = (json.loads((folder / name).read_bytes()) for name in ("manifest.json", "evaluation_strata.json", "family_holdouts.json"))
    tables = strat.evaluate(manifest, strata, holdouts, matrix, galleries, thresholds, stability)
    tables["frozen_file_sha256"] = {name: g.pairs.catalog.exact_hash(folder / name) for name in ("manifest.json", "evaluation_strata.json", "family_holdouts.json")}
    for name, value in (("judged_galleries.json", galleries), ("discovery_thresholds.json", thresholds), ("primary_metrics.json", metrics), ("feature_rank_stability.json", stability), ("stratified_results.json", tables)):
        require((g.ROOT / g.AUDIT_DIR / name).read_bytes() == serialize(value), "scientific reconstruction differs: " + name)
    return protocol, matrix, catalog, metrics, stability, tables


def acceptance_text(metrics, stability, tables, observation):
    lines = [
        "# OSGF Baseline Evaluation v0.1 — acceptance",
        "",
        "Controlled benign function-equivalence experiment with query-specific judged galleries. No malware labels, no LLM contribution and no open-world retrieval claim.",
        "",
        "## Retrieval on the complete common A/B cohort",
        "",
        "Recall means retrieved positives / all judged positives in each query. Hit@K is separate in primary_metrics.json. K>N is unsupported. Different K denominators mean these columns are not a monotone curve on one cohort.",
        "",
        "| Split | Condition | Recall@1 (N) | Recall@3 (N) | Recall@5 (N) | MRR (N) | Pairwise FPR |",
        "|---|---|---|---|---|---|---|",
    ]
    for cell in metrics["cells"]:
        r = cell["common_retrieval"]
        values = [f"{r['recall'][str(k)]['value']:.9f} ({r['recall'][str(k)]['n']})" for k in (1, 3, 5)]
        lines.append(f"| {cell['split']} | {cell['condition']} | {' | '.join(values)} | {r['mrr']['value']:.9f} ({r['mrr']['n']}) | {cell['pairwise']['false_match_rate']['value']:.9f} |")
    lines += [
        "",
        "Thresholds were selected on identical paired discovery IDs, by the preregistered balanced-accuracy rule, and persisted before validation/held-out evaluation. FPR is negative pairs predicted equivalent / scored negatives; it is not retrieval false-top1.",
        "",
        "## Pair distributions",
        "",
        "| Split | Condition | Label | N | Mean | Median | q05 | q95 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for cell in metrics["cells"]:
        for label in ("equivalent", "non_equivalent"):
            d = cell["pairwise"][label]["aggregate"]
            lines.append(f"| {cell['split']} | {cell['condition']} | {label} | {d['n']} | {d['mean']} | {d['median']} | {d['q05']} | {d['q95']} |")
    lines += [
        "",
        "## Churn and rank stability",
        "",
        (
            f"{len(stability['churn'])} independently equivalent pair-condition records contain exact inserted/deleted/count-changed descriptors for all three views. 114 eligible A/B rankings "
            f"have zero normalized rank difference. Undefined constant/singleton correlations remain null. Cross-condition descriptor churn is unsupported without an approved mapping; "
            f"within-condition churn remains fully reported."
        ),
        "",
        "| Condition | Split | View | Presence mean (N) | Multiplicity mean (N) |",
        "|---|---|---|---|---|",
    ]
    for row in stability["summaries"]:
        if row["family"] is None:
            for view, values in row["views"].items():
                a, b = values["presence"], values["multiplicity"]
                lines.append(f"| {row['condition']} | {row['split']} | {view} | {a['mean']} ({a['n']}) | {b['mean']} ({b['n']}) |")
    lines += [
        "",
        "## Runtime observations",
        "",
        (
            "Warm-up excluded; five measured repetitions on identical cohorts. Wall times include named validation/IO and process startup. Both engines use debug builds. A has one combined "
            "extraction invocation; B uses two. B-only substages are diagnostic, not matched A/B comparisons. OS caches were not flushed. Ghidra is a shared upstream cost not measured here. "
            "Peak RSS is unsupported."
        ),
        "",
        "| Condition | Stage | N | Median ms | q05 ms | q95 ms |",
        "|---|---|---|---|---|---|",
    ]
    for row in observation["summary"]:
        d = row["milliseconds"]
        lines.append(f"| {row['condition']} | {row['stage']} | {d['n']} | {d['median']} | {d['q05']} | {d['q95']} |")
    lines += [
        "",
        "## Limits and failure analysis",
        "",
        (
            f"{len(tables['tables'])} descriptive tables preserve frozen split, signal/observability strata and family holdouts. Six connected source components are below the preregistered "
            f"minimum ten: no inferential interval or significance claim. Overlapping strata must not be counted as independent samples. Family-specific holdout FPR is unsupported because a "
            f"family-excluded threshold protocol was not preregistered. Whole original galleries only are used for cell retrieval; empty cells remain unsupported."
        ),
        "",
        (
            "A and B have identical retrieval outcomes here; this is not evidence of general method equivalence. Held-out FPR=1.0 is a major failure of the calibrated classification threshold "
            "on this cohort. All 142 condition-specific errors, exact pair labels and source-bearing artifact references appear in stratified_results.json; PROVISIONAL_REVIEW.md lists examples. "
            "No label or method was adjusted after seeing these results. Anchor-only graphs and incomplete/truncated observations remain included with warnings. Same-PE anchors remain dependent "
            "observations. Optional Step9 variants were not mixed into frozen partitions."
        ),
        "",
        "## Replay, checks and exclusions",
        "",
        (
            "Fresh-directory replay reconstructs both catalogs, all 436 pair scores and every derived scientific result. Timings are variable experiment observations and are bound separately. "
            "validation_commands.json records complete executed commands and exit codes. Python and Rust suites, Step5–7 acceptance, Step8 manual review/acceptance/leakage and Step9 protected "
            "inventory must all pass. Frozen source inputs and goldens are hash-bound in the scientific manifest."
        ),
        "",
        (
            "NOT RUN: hosted CI/Linux, fresh compiler rebuild in the replay workspace, new Ghidra extraction, new Step9 supplementary experiment, optional peak RSS measurement, malware pilot. "
            "No commit or push was performed. The workspace replay uses the same pinned executable bytes in a new local directory; it is not advertised as a clean git checkout."
        ),
        "",
        "## Future separate experiment and handoff",
        "",
        (
            "The eventual ‘Step 10.5 REAL MALWARE PILOT’ is a separate future study: define authorized sample provenance and containment, independent labels, family/time splits, preregistered "
            "thresholds and evaluation before acquisition. Do not insert malware into this frozen controlled corpus. No samples were ingested here."
        ),
        "",
        "Ready for user review before Step11 implementation, within the explicit supported scope and limitations above. Step11 has not been started. Any baseline revision needs explicit supersession metadata and authorization; freeze-001 cannot be overwritten.",
    ]
    return "\n".join(lines) + "\n"


def freeze(folder, manifest, report, checks, observation_binding=None):
    require(not folder.exists(), "immutable freeze already exists")
    folder.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".freeze-stage-", dir=folder.parent) as temp:
        stage = Path(temp) / "publish"
        stage.mkdir()
        (stage / "scientific_manifest.json").write_bytes(serialize(manifest))
        (stage / "ACCEPTANCE.md").write_text(report, encoding="utf-8", newline="\n")
        (stage / "validation_commands.json").write_bytes(serialize(checks))
        (stage / "runtime_observation_manifest.json").write_bytes(serialize(observation_binding))
        stage.rename(folder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--checks", default=".build-cache/step10-final-regressions-results.json")
    parser.add_argument("--observation", default="runtime-001")
    args = parser.parse_args()
    folder = g.ROOT / g.AUDIT_DIR
    require(not args.freeze or not (folder / "freezes/freeze-001").exists(), "immutable freeze already exists")
    protocol, matrix, catalog, metrics, stability, tables = verified_results()
    observation_path = folder / "observations" / (args.observation + ".json")
    observation = json.loads(observation_path.read_bytes())
    check_observation(observation, protocol, matrix, catalog)
    previous = json.loads((folder / "fresh_workspace_replay.json").read_bytes())
    require(previous == replay.replay(), "second end-to-end replay differs")
    if not args.freeze:
        print("FULL RECONSTRUCTION, RUNTIME AND SECOND END-TO-END REPLAY PASS; no freeze written", flush=True)
        return
    checks = json.loads(g.pairs.safe_path(g.ROOT, args.checks).read_text(encoding="utf-8-sig"))
    require(len(checks) >= 16 and all(c["exit_code"] == 0 and c["status"] == "PASS" for c in checks), "required regression command failed/missing")
    required = [
        "python -m pytest -q tests",
        "python -m ruff check .",
        "python -m ruff format --check .",
        "cargo fmt --manifest-path rust_engine/Cargo.toml -- --check",
        "cargo test --locked --manifest-path rust_engine/Cargo.toml",
        "cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings",
        "cargo build --locked --manifest-path rust_engine/Cargo.toml",
        "python scripts/dataset_review.py check",
        "python scripts/validate_dataset_acceptance.py",
        "git diff --check",
    ]
    require(set(required) <= {c["command"] for c in checks}, "missing required regression")
    branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=g.ROOT, text=True).strip()
    require(branch == "codex", "wrong branch")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=g.ROOT, text=True).strip()
    code_names = [p.relative_to(g.ROOT).as_posix() for glob in ("scripts/evaluation_*.py", "tests/test_evaluation_*.py") for p in g.ROOT.glob(glob)]
    names = [p.relative_to(g.ROOT).as_posix() for p in folder.glob("*.json")]
    names += [p.relative_to(g.ROOT).as_posix() for p in (folder / "research_adapter").glob("*") if p.is_file()]
    scientific = dict(
        schema_version="0.1.0",
        freeze_id="freeze-001",
        status="PASS_supported_preregistered_scope",
        branch=branch,
        head=head,
        scientific_file_sha256={name: g.pairs.catalog.exact_hash(g.ROOT / name) for name in sorted(names)},
        code_text_utf8_lf_sha256={name: g.pairs.sha((g.ROOT / name).read_text(encoding="utf-8").encode("utf-8")) for name in sorted(code_names)},
        hash_protocol="Scientific artifacts and executable bindings hash exact bytes. Python source identity uses explicitly UTF-8 LF-normalized text, matching generator identities; this is not compiled-input provenance. Frozen C source and build hashes remain exact and unchanged.",
        protected_input_inventory=protocol["inputs"],
        configuration=protocol["design"],
        engine_bindings=catalog["plan"]["identity"],
        replay_sha256=g.pairs.catalog.exact_hash(folder / "fresh_workspace_replay.json"),
        runtime_observations="Bound separately by runtime_observation_manifest.json; variable measurements excluded from scientific identity",
        validation_commands_sha256=g.pairs.sha(serialize(checks)),
    )
    observation_binding = dict(path=observation_path.relative_to(g.ROOT).as_posix(), sha256=g.pairs.catalog.exact_hash(observation_path), excluded_from_algorithmic_replay=True)
    freeze(folder / "freezes/freeze-001", scientific, acceptance_text(metrics, stability, tables, observation), checks, observation_binding)
    print("FREEZE-001 PUBLISHED; STOP BEFORE STEP 11", flush=True)


if __name__ == "__main__":
    main()
