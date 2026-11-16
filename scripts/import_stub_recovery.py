"""Opt-in PE32 import-stub evidence view. Never executes or edits the binary/raw graph."""

import argparse
import copy
from pathlib import Path
import struct
import sys

try:
    from . import graph_first as g
    from . import reference_library as lib
except ImportError:
    import graph_first as g
    import reference_library as lib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ghidra_scripts"))
from export_report import canonicalize_api_name  # noqa: E402
from typed_graph_model import build_api_node, build_api_call_edge  # noqa: E402

SCHEMA = "osgf.pe32-import-stub-view/0.1.0"


class PE32:
    """Bounded unbound named-import reader; unsupported formats fail explicitly."""

    def __init__(self, raw):
        self.raw = raw
        g.require(self.take(0, 2) == b"MZ", "missing DOS signature")
        pe = self.u32(0x3C)
        g.require(self.take(pe, 4) == b"PE\0\0", "missing PE signature")
        g.require(self.u16(pe + 4) == 0x14C, "only i386 PE32 supported")
        count = self.u16(pe + 6)
        optional_size = self.u16(pe + 20)
        optional = pe + 24
        g.require(0 < count <= 96 and optional_size >= 112, "invalid PE header sizes")
        g.require(self.u16(optional) == 0x10B, "only PE32 supported")
        self.base = self.u32(optional + 28)
        g.require(self.u32(optional + 92) >= 2, "import directory unavailable")
        self.import_rva = self.u32(optional + 104)
        self.import_size = self.u32(optional + 108)
        g.require(self.import_rva and self.import_size >= 20, "import directory unavailable")
        self.sections = []
        for i in range(count):
            start = optional + optional_size + 40 * i
            self.take(start, 40)
            size = self.u32(start + 16)
            va = self.u32(start + 12)
            offset = self.u32(start + 20)
            self.take(offset, size)
            self.sections.append(dict(rva=va, size=size, offset=offset, flags=self.u32(start + 36)))

    def take(self, offset, size):
        g.require(isinstance(offset, int) and 0 <= offset and 0 <= size and offset + size <= len(self.raw), "PE range outside file")
        return self.raw[offset : offset + size]

    def u16(self, offset):
        return struct.unpack("<H", self.take(offset, 2))[0]

    def u32(self, offset):
        return struct.unpack("<I", self.take(offset, 4))[0]

    def location(self, rva, size=1, executable=False):
        matches = [s for s in self.sections if s["rva"] <= rva and rva + size <= s["rva"] + s["size"]]
        g.require(len(matches) == 1, "RVA missing or ambiguous in raw sections")
        section = matches[0]
        g.require(not executable or section["flags"] & 0x20000000, "code outside executable section")
        return section["offset"] + rva - section["rva"]

    def string(self, rva):
        result = bytearray()
        for i in range(512):
            value = self.take(self.location(rva + i), 1)[0]
            if value == 0:
                g.require(bool(result), "empty import name")
                return result.decode("ascii", errors="strict")
            g.require(32 <= value < 127, "non-ASCII import name")
            result.append(value)
        raise ValueError("unterminated import name")

    def imports(self):
        result = {}
        for i in range(min(self.import_size // 20, 4096)):
            offset = self.location(self.import_rva + 20 * i, 20)
            original, timestamp, forwarder, name, iat = struct.unpack("<IIIII", self.take(offset, 20))
            if not any((original, timestamp, forwarder, name, iat)):
                return result
            g.require(original and iat and name and timestamp == 0, "bound or missing lookup table unsupported")
            dll = self.string(name)
            for j in range(16384):
                lookup = self.u32(self.location(original + 4 * j, 4))
                target = self.u32(self.location(iat + 4 * j, 4))
                g.require(lookup == target, "bound/mismatched import address table unsupported")
                if lookup == 0:
                    break
                if lookup & 0x80000000:
                    continue  # Ordinals are not mapped to guessed names.
                imported = self.string(lookup + 2)
                address = self.base + iat + 4 * j
                g.require(address not in result, "duplicate IAT slot")
                result[address] = dict(dll=dll, import_name=imported, iat_va=address, iat_file_offset=self.location(iat + 4 * j, 4), lookup_rva=lookup)
            else:
                raise ValueError("unterminated import lookup table")
        raise ValueError("unterminated import directory")


def derive(raw, document):
    digest = lib.sha(raw)
    g.require(document.get("metadata", {}).get("research_binary_sha256") == digest, "binary/graph provenance mismatch")
    pe = PE32(raw)
    imports = pe.imports()
    nodes = {n["id"]: n for n in document["nodes"]}
    g.require(len(nodes) == len(document["nodes"]), "duplicate node IDs")
    stubs = {}
    for node in document["nodes"]:
        if node.get("type") != "FUNCTION" or node.get("external") is not False or node.get("size") != 6:
            continue
        try:
            address = int(node["address"], 16)
            offset = pe.location(address - pe.base, 6, executable=True)
        except (ValueError, KeyError, TypeError):
            continue
        code = pe.take(offset, 6)
        if code[:2] != b"\xff\x25":
            continue
        slot = struct.unpack("<I", code[2:])[0]
        if slot in imports:
            stubs[node["id"]] = dict(function_id=node["id"], stub_va=address, stub_file_offset=offset, stub_bytes=code.hex(), **imports[slot])
    output = copy.deepcopy(document)
    output_nodes = {n["id"]: n for n in output["nodes"]}
    edges = []
    proofs = []
    rejected = []
    existing = {(e["type"], e["source"], e["target"]) for e in document["edges"]}
    added = set()
    for index, edge in enumerate(document["edges"]):
        proof = stubs.get(edge.get("target")) if edge.get("type") == "calls_function" else None
        if not proof:
            edges.append(copy.deepcopy(edge))
            continue
        try:
            sites = edge["callsites"]
            g.require(edge.get("direct") is True and edge.get("indirect") is False and edge.get("unresolved") is False, "only resolved direct calls supported")
            g.require(isinstance(sites, list) and sites and len(set(sites)) == len(sites) and edge["occurrences"] == len(sites), "ambiguous static call multiplicity")
            call_proofs = []
            for site in sites:
                address = int(site, 16)
                offset = pe.location(address - pe.base, 5, executable=True)
                code = pe.take(offset, 5)
                g.require(code[0] == 0xE8 and address + 5 + struct.unpack("<i", code[1:])[0] == proof["stub_va"], "call bytes do not target verified stub")
                call_proofs.append(dict(callsite=site, file_offset=offset, bytes=code.hex()))
            normalized = canonicalize_api_name(proof["import_name"])
            api = build_api_node(normalized, [proof["import_name"]])
            key = ("calls_api", edge["source"], api["id"])
            g.require(key not in existing and key not in added, "parallel API edge aggregation unsupported")
            if api["id"] in output_nodes:
                g.require(output_nodes[api["id"]]["type"] == "API" and output_nodes[api["id"]]["normalized_name"] == normalized, "API identity conflict")
                output_nodes[api["id"]]["original_names"] = sorted(set(output_nodes[api["id"]]["original_names"] + [proof["import_name"]]))
            else:
                output_nodes[api["id"]] = api
            new_edge = build_api_call_edge(edge["source"], api["id"], sites, [proof["import_name"]], indirect=False)
            edges.append(new_edge)
            added.add(key)
            proofs.append(dict(source_edge_index=index, original_edge=edge, recovered_edge=new_edge, stub=proof, calls=call_proofs))
        except (ValueError, KeyError, TypeError) as error:
            edges.append(copy.deepcopy(edge))
            rejected.append(dict(source_edge_index=index, reason=str(error)))
    output["nodes"] = sorted(output_nodes.values(), key=lambda n: n["id"])
    output["edges"] = edges
    metadata = output.setdefault("metadata", {})
    metadata["node_count"] = len(output["nodes"])
    metadata["edge_count"] = len(edges)
    for kind, items in (("node", output["nodes"]), ("edge", edges)):
        counts = {}
        for item in items:
            counts[item["type"]] = counts.get(item["type"], 0) + 1
        metadata[kind + "_type_counts"] = counts
    metadata["import_stub_view"] = dict(schema_version=SCHEMA, source_graph_sha256=lib.sha(g.encoded(document)), binary_sha256=digest, changed_edges=len(proofs), interpretation="Named PE import + exact x86 jump/call bytes; no symbol-name inference. Experimental source view, not the frozen Ghidra graph.")
    receipt = dict(
        schema_version=SCHEMA,
        binary_sha256=digest,
        source_graph_sha256=lib.sha(g.encoded(document)),
        derived_graph_sha256=lib.sha(g.encoded(output)),
        implementation_sha256=lib.sha(Path(__file__).read_bytes()),
        proofs=proofs,
        rejected=rejected,
        limitations="Only unbound i386 PE32 named imports, 6-byte FF25 stubs and direct E8 caller sites. Ordinals skipped, bound tables and unsupported formats rejected. Original stub nodes retained. No default extraction or seed-rule changes.",
    )
    return output, receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--graph", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    g.require(not a.output.exists(), "fresh output directory required")
    raw = a.binary.read_bytes()
    original = a.graph.read_bytes()
    graph, receipt = derive(raw, g.load(a.graph))
    receipt["source_graph_file_sha256"] = lib.sha(original)
    a.output.mkdir(parents=True)
    g.write(a.output / "graph.json", graph)
    g.write(a.output / "proof.json", receipt)
    print("PASS verified import-stub view:", len(receipt["proofs"]), "edges recovered;", len(receipt["rejected"]), "rejected")


if __name__ == "__main__":
    main()
