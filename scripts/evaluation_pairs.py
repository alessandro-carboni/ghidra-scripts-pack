"""Step 10.4: deterministic source-validated pair scores, never retrieval metrics."""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile

try:
    from . import evaluation_catalog as catalog
except ImportError:
    import evaluation_catalog as catalog

ROOT, AUDIT_DIR = catalog.ROOT, catalog.AUDIT_DIR
require, serialize, sha, safe_path = catalog.require, catalog.serialize, catalog.sha, catalog.safe_path
VIEWS = ("rooted_topology", "typed_evidence", "interaction_motif")
CATALOG = ROOT / catalog.DEFAULT_OUTPUT
OUTPUT = AUDIT_DIR + "/runtime/pair_scores-v0_1"


def oracle(left, right):
    """Independent descriptor/count oracle; empty sets stay noncomparable."""

    def counts(features):
        result = {}
        for feature in features:
            key = serialize(feature["descriptor"])
            require(key not in result, "duplicate scientific descriptor")
            count = feature["count"]
            require(type(count) is int and 0 < count <= 2**64 - 1, "invalid feature count")
            result[key] = count
        return result

    q, r = counts(left), counts(right)
    union = q.keys() | r.keys()
    intersection_count = sum(min(q.get(k, 0), r.get(k, 0)) for k in union)
    union_count = sum(max(q.get(k, 0), r.get(k, 0)) for k in union)
    return dict(comparable=bool(union), set_similarity=len(q.keys() & r.keys()) / len(union) if union else None, multiset_similarity=float(intersection_count) / float(union_count) if union_count else None)


def check_result(result, qfp, rfp, qprov, rprov, qid, rid, condition):
    require(result["schema_version"] == ("research-0.1.0" if condition == "A" else "0.1.0"), "wrong comparison version")
    require(result["query"]["id"] == qid and result["reference"]["id"] == rid, "wrong ordered graph roles")
    require(result["query"]["provenance"] == qprov and result["reference"]["provenance"] == rprov, "wrong comparison source provenance")
    components = []
    expected = []
    for view in VIEWS:
        value = oracle(qfp[view + "_view"], rfp[view + "_view"])
        require(all(result[view][key] == number for key, number in value.items()), "independent Jaccard oracle mismatch: " + view)
        if value["comparable"]:
            components.append(view)
            expected.append(value)
    require(result["aggregate_requested"] is True and result["aggregate_components"] == components, "wrong aggregate components")
    for key in ("set_similarity", "multiset_similarity"):
        number = sum(v[key] for v in expected) / len(expected) if expected else None
        require(result["aggregate_" + key] == number, "independent aggregate oracle mismatch")


def pair_jobs(manifest, records, identity):
    index = {(r["condition"], r["graph_id"]): r for r in records}
    require(len(index) == len(records), "duplicate graph-condition catalog identity")
    seen = set()
    jobs = []
    for pair in sorted(manifest["pairs"], key=lambda p: p["pair_id"]):
        require(pair["pair_id"] not in seen, "duplicate pair identity")
        seen.add(pair["pair_id"])
        require(pair["equivalence_label"] in {"equivalent", "non_equivalent"} and pair["ground_truth"]["label"] == pair["equivalence_label"], "unknown or contradictory label")
        require(pair["left_graph_id"] != pair["right_graph_id"], "self pair forbidden")
        require(pair["validation_status"] in {"automatically_grounded", "manually_verified"}, "pair not independently admitted")
        for condition in ("A", "B"):
            require((condition, pair["left_graph_id"]) in index and (condition, pair["right_graph_id"]) in index, "missing graph-condition input")
            q, r = (index[(condition, pair[k])] for k in ("left_graph_id", "right_graph_id"))
            require(q["split"] == r["split"] == pair["split"], "cross-split pair")
            job = dict(condition=condition, pair=pair, query=q, reference=r)
            job["record_id"] = sha(serialize(dict(identity=identity, job=job)))
            jobs.append(job)
    return jobs


def plan(directory=CATALOG):
    expected = catalog.plan()
    report = catalog.verify(directory, expected)
    require((Path(directory) / "catalog.json").read_bytes() == (ROOT / AUDIT_DIR / "graph_catalog.json").read_bytes(), "catalog differs from versioned admission")
    identity = dict(
        schema_version="0.1.0",
        catalog_sha256=catalog.exact_hash(Path(directory) / "catalog.json"),
        protocol_sha256=expected["identity"]["protocol_sha256"],
        engine_sha256=expected["identity"]["engine_sha256"],
        research_engine_sha256=expected["identity"]["research_engine_sha256"],
        generator_utf8_lf_sha256=sha(Path(__file__).read_text(encoding="utf-8").encode()),
        primary="aggregate_multiset_similarity",
        aggregate="unweighted_mean_comparable_semantic_views",
        direction="frozen_left_as_query_right_as_reference",
        comparison_versions={"A": "research-0.1.0", "B": "0.1.0"},
    )
    manifest = json.loads((ROOT / "datasets/osgf_pairs_v0_1/manifest.json").read_bytes())
    return dict(identity=identity, jobs=pair_jobs(manifest, report["records"], identity))


def load_input(row, directory):
    require(row["status"] == "success", "graph input unavailable")
    paths = {}
    for item in row["artifacts"]:
        path = safe_path(directory, item["path"])
        require(catalog.artifact(directory, path) == item, "graph artifact modified")
        paths[path.name] = path
    if row["condition"] == "A":
        doc = json.loads(paths["bundle.json"].read_bytes())
        require(doc["graph"]["condition"] == "A", "wrong bundle condition")
        fp, prov = doc["fingerprint"], doc["provenance"]
    else:
        fp = json.loads(paths["fingerprint.json"].read_bytes())
        prov = json.loads(paths["fingerprint.json.provenance.json"].read_bytes())
    require(fp["fingerprint_digest"] == row["fingerprint_digest"] and prov["fingerprint_digest"] == fp["fingerprint_digest"], "fingerprint identity mismatch")
    return paths, fp, prov


def score(job, stage, directory=CATALOG):
    q, r, condition = job["query"], job["reference"], job["condition"]
    base = dict(
        record_id=job["record_id"], condition=condition, pair=job["pair"], query_graph_id=q["graph_id"], reference_graph_id=r["graph_id"], query_catalog_record=q["record_id"], reference_catalog_record=r["record_id"], query_fingerprint_digest=q["fingerprint_digest"], reference_fingerprint_digest=r["fingerprint_digest"]
    )
    output = safe_path(stage, condition + "/" + job["record_id"] + ".json")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        qp, qfp, qprov = load_input(q, directory)
        rp, rfp, rprov = load_input(r, directory)
        if condition == "A":
            raw = catalog.run([catalog.executable(), "compare", qp["bundle.json"], rp["bundle.json"]])
            with output.open("xb") as stream:
                stream.write(raw)
            qid, rid = "query", "reference"
        else:
            qcanonical, rcanonical = (safe_path(ROOT, row["canonical_path"]) for row in (q, r))
            require(catalog.exact_hash(qcanonical) == q["canonical_sha256"] and catalog.exact_hash(rcanonical) == r["canonical_sha256"], "canonical changed")
            qid, rid = q["graph_id"], r["graph_id"]
            catalog.run([catalog.ENGINE, "compare-fingerprints", qid, qcanonical, qp["fingerprint.json"], rid, rcanonical, rp["fingerprint.json"], output, "--aggregate"])
        result = json.loads(output.read_bytes())
        check_result(result, qfp, rfp, qprov, rprov, qid, rid, condition)
        views = {view: {key: result[view][key] for key in ("set_similarity", "multiset_similarity", "comparable", "comparison_complete", "warnings")} for view in VIEWS}
        return dict(
            **base,
            status="success",
            artifact=catalog.artifact(stage, output),
            raw_result_role_bindings={qid: q["graph_id"], rid: r["graph_id"]},
            views=views,
            primary_score=result["aggregate_multiset_similarity"],
            aggregate_set_similarity=result["aggregate_set_similarity"],
            aggregate_components=result["aggregate_components"],
            observability_warnings=result["observability_warnings"],
            input_motif_truncation=dict(query=q["motif_truncation"], reference=r["motif_truncation"]),
            oracle="PASS",
        )
    except (ValueError, subprocess.TimeoutExpired) as error:
        return dict(**base, status="failed", reason="timeout" if isinstance(error, subprocess.TimeoutExpired) else "input_comparison_or_oracle_rejected", artifact=None)


def materialize(expected, destination, directory=CATALOG):
    destination = Path(destination)
    require(not destination.exists() and destination.resolve() == destination.absolute(), "output collision or redirection")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".pairs-stage-", dir=destination.parent) as temp:
        stage = Path(temp) / "publish"
        stage.mkdir()
        records = []
        for n, job in enumerate(expected["jobs"], 1):
            row = score(job, stage, directory)
            records.append(row)
            print(f"{n}/{len(expected['jobs'])} {job['condition']} {job['pair']['pair_id']}: {row['status']}", flush=True)
        by_pair = {}
        for row in records:
            by_pair.setdefault(row["pair"]["pair_id"], {})[row["condition"]] = row
        paired = {key: all(r["status"] == "success" for r in rows.values()) and rows["A"]["aggregate_components"] == rows["B"]["aggregate_components"] for key, rows in sorted(by_pair.items())}
        result = dict(schema_version="0.1.0", identity=expected["identity"], status="PASS" if all(r["status"] == "success" for r in records) else "INCOMPLETE", records=records, paired_comparable_components=paired)
        (stage / "matrix.json").write_bytes(serialize(result))
        stage.rename(destination)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--score", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--output", default=OUTPUT)
    args = parser.parse_args()
    require(args.output.startswith(AUDIT_DIR + "/runtime/"), "outputs must stay in evaluation runtime")
    destination = safe_path(ROOT, args.output)
    expected = plan()
    if args.score:
        result = materialize(expected, destination)
    else:
        with tempfile.TemporaryDirectory(prefix="osgf-pairs-replay-") as temp:
            repeated = Path(temp) / "replay"
            result = materialize(expected, repeated)

            def names(path):
                return {f.relative_to(path).as_posix() for f in path.rglob("*") if f.is_file()}

            require(names(destination) == names(repeated), "missing/extra matrix files")
            for name in names(repeated):
                require(safe_path(destination, name).read_bytes() == (repeated / name).read_bytes(), "matrix replay differs: " + name)
        print("ALL MATRIX BYTES AND SOURCES REPLAY VERIFIED", flush=True)
    print("SUMMARY", dict(Counter((r["condition"], r["status"]) for r in result["records"])), "matrix_sha256=" + catalog.exact_hash(destination / "matrix.json"), flush=True)
    require(result["status"] == "PASS", "matrix incomplete; inspect failed records")


if __name__ == "__main__":
    main()
