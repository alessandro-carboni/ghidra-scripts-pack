"""Prospective source registration must prevent post-hoc source/tool changes."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import graph_first as g
from scripts import reference_corpus_sources as source
from scripts import run_reference_corpus as study


def arguments(tmp_path):
    tool = tmp_path / "not-an-executable.txt"
    tool.write_bytes(b"format fixture; never executed")
    return SimpleNamespace(study=tmp_path / "study", engine=tool, operational_engine=tool, compiler=tool, ghidra=Path("unused"), ghidra_python=tool, java_home=Path("unused"))


def test_registered_families_are_distinct_and_source_mutation_stops_before_execution(tmp_path):
    args = arguments(tmp_path)
    study.prepare(args)
    protocol = g.load(args.study / "protocol.json")
    assert {v["split"] for v in protocol["families"].values()} == {"discovery", "validation", "heldout"}
    assert len({v["sha256"] for v in protocol["families"].values()}) == 3
    first = next(iter(protocol["families"].values()))
    path = args.study / first["source"]
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="source changed"):
        study.run(args)
    assert not (args.study / "library").exists()


def test_tool_mutation_and_existing_registration_rejected(tmp_path):
    args = arguments(tmp_path)
    study.prepare(args)
    with pytest.raises(ValueError, match="new study"):
        study.prepare(args)
    args.engine.write_bytes(b"changed tool")
    with pytest.raises(ValueError, match="implementation/tool changed"):
        study.run(args)


def test_label_contract_is_fixed_before_scoring():
    assert source.positive("subject", "equivalent")
    assert source.positive("equivalent", "subject")
    assert source.positive("foil", "foil")
    assert not source.positive("subject", "foil")
    assert not source.positive("foil", "equivalent")
    with pytest.raises(ValueError, match="unknown"):
        source.positive("unannotated_runtime", "subject")


def test_partial_protocol_preserves_sources_splits_and_explicit_blocker(tmp_path):
    args = arguments(tmp_path)
    study.prepare(args)
    parent = args.study / "protocol.json"
    original = parent.read_bytes()
    args.study = tmp_path / "partial"
    args.parent_protocol = parent
    args.unavailable_family = "debugger_status"
    args.unavailable_reason = "confirmed endpoint quarantine; do not rebuild"
    study.prepare(args)
    partial = g.load(args.study / "protocol.json")
    assert partial["families"] == g.load(parent)["families"]
    assert partial["unavailable_families"] == {"debugger_status": args.unavailable_reason}
    assert parent.read_bytes() == original


def test_resume_cannot_accept_a_changed_scientific_tool(tmp_path):
    args = arguments(tmp_path)
    study.prepare(args)
    args.action = "resume-available"
    args.engine.write_bytes(b"changed engine must not pass administrative amendment")
    with pytest.raises(ValueError, match="scientific method, source generator or tool changed"):
        study.run(args)
    assert not (args.study / "continuation.json").exists()
