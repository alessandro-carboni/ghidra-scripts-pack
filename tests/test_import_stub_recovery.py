"""Synthetic PE byte fixtures plus independent rejection oracles; never executed."""

import copy
import struct
import os
from pathlib import Path

import pytest

from scripts import import_stub_recovery as recovery


def fixture():
    raw = bytearray(0x600)

    def word(offset, value):
        struct.pack_into("<H", raw, offset, value)

    def dword(offset, value):
        struct.pack_into("<I", raw, offset, value)

    raw[:2] = b"MZ"
    dword(0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    word(0x84, 0x14C)
    word(0x86, 2)
    word(0x94, 224)
    opt = 0x98
    word(opt, 0x10B)
    dword(opt + 28, 0x400000)
    dword(opt + 92, 16)
    dword(opt + 104, 0x2000)
    dword(opt + 108, 40)
    for i, (va, offset, flags) in enumerate(((0x1000, 0x200, 0x60000020), (0x2000, 0x400, 0xC0000040))):
        s = opt + 224 + i * 40
        dword(s + 12, va)
        dword(s + 16, 0x200)
        dword(s + 20, offset)
        dword(s + 36, flags)
    struct.pack_into("<IIIII", raw, 0x400, 0x2040, 0, 0, 0x2080, 0x2060)
    dword(0x440, 0x20A0)
    dword(0x460, 0x20A0)
    raw[0x480:0x48C] = b"example.dll\0"
    raw[0x4A2:0x4A9] = b"socket\0"
    raw[0x200:0x205] = b"\xe8" + struct.pack("<i", 11)
    raw[0x210:0x216] = b"\xff\x25" + struct.pack("<I", 0x402060)
    graph = dict(
        model_version="0.12.0",
        metadata=dict(research_binary_sha256=recovery.lib.sha(raw)),
        nodes=[dict(id="fn:00401000", type="FUNCTION", address="00401000", external=False, size=5), dict(id="fn:00401010", type="FUNCTION", address="00401010", external=False, size=6, name="misleading_local_name", thunk=False)],
        edges=[dict(type="calls_function", source="fn:00401000", target="fn:00401010", direct=True, indirect=False, unresolved=False, callsites=["00401000"], occurrences=1)],
        unresolved_calls=[],
    )
    return raw, graph


def test_proof_uses_bytes_and_import_not_symbol_and_preserves_inputs():
    raw, graph = fixture()
    before = copy.deepcopy(graph)
    out, proof = recovery.derive(raw, graph)
    assert graph == before
    assert out["edges"][0]["type"] == "calls_api"
    assert out["edges"][0]["target"] == "api:socket"
    assert proof["proofs"][0]["stub"]["dll"] == "example.dll"
    assert proof["proofs"][0]["calls"][0]["file_offset"] == 0x200
    assert recovery.g.encoded((out, proof)) == recovery.g.encoded(recovery.derive(raw, graph))


@pytest.mark.parametrize("offset,value", [(0x210, 0x90), (0x212, 0x61), (0x200, 0x90), (0x201, 0)])
def test_nonmatching_instruction_or_iat_is_not_promoted(offset, value):
    raw, graph = fixture()
    raw[offset] = value
    graph["metadata"]["research_binary_sha256"] = recovery.lib.sha(raw)
    out, proof = recovery.derive(raw, graph)
    assert not proof["proofs"]
    assert out["edges"][0]["type"] == "calls_function"


def test_hash_mismatch_rejected():
    raw, graph = fixture()
    raw[-1] = 1
    with pytest.raises(ValueError, match="provenance"):
        recovery.derive(raw, graph)


def test_ordinal_is_not_guessed_from_symbol():
    raw, graph = fixture()
    for offset in (0x440, 0x460):
        struct.pack_into("<I", raw, offset, 0x80000017)
    graph["metadata"]["research_binary_sha256"] = recovery.lib.sha(raw)
    assert recovery.derive(raw, graph)[1]["proofs"] == []


def test_bound_imports_and_truncated_files_fail():
    raw, graph = fixture()
    struct.pack_into("<I", raw, 0x460, 0x12345678)
    graph["metadata"]["research_binary_sha256"] = recovery.lib.sha(raw)
    with pytest.raises(ValueError, match="bound/mismatched"):
        recovery.derive(raw, graph)
    with pytest.raises(ValueError, match="range"):
        recovery.PE32(b"MZ")


def test_indirect_or_ambiguous_calls_remain_unmodified():
    raw, graph = fixture()
    graph["edges"][0]["indirect"] = True
    out, proof = recovery.derive(raw, graph)
    assert out["edges"][0] == graph["edges"][0]
    assert len(proof["rejected"]) == 1


def test_original_seed_detector_accepts_recovered_evidence_only(tmp_path):
    engine = Path(__file__).resolve().parents[1] / "rust_engine/target/debug" / ("rust_engine.exe" if os.name == "nt" else "rust_engine")
    if not engine.exists():
        pytest.skip("Rust engine built in canonical-baseline CI")
    raw, graph = fixture()
    before = recovery.g.extract(graph, engine, tmp_path / "before")
    derived, _ = recovery.derive(raw, graph)
    after = recovery.g.extract(derived, engine, tmp_path / "after")
    assert before["records"] == []
    assert [r["anchor"] for r in after["records"]] == ["fn:00401000"]
    fp = recovery.g.load(tmp_path / "after" / after["records"][0]["fingerprint"])
    recovery.g.validate(fp, engine)
