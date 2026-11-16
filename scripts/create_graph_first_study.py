"""Author fresh buffer families AFTER graph-first method registration; never execute PEs."""

import argparse
import itertools
from pathlib import Path
import random

try:
    from . import graph_first as g
    from . import evaluate_operational_baseline as base
except ImportError:
    import graph_first as g
    import evaluate_operational_baseline as base


FAMILIES = (
    ("buffer_ascii_upper_count", "discovery", "r += (p[i]>=65 && p[i]<=90);", "r += ((unsigned)(p[i]-65)<26);"),
    ("buffer_high_nibble_sum", "discovery", "r += p[i] >> 4;", "r += p[i] / 16;"),
    ("buffer_adjacent_equal_count", "validation", "if(i) r += p[i]==p[i-1];", "if(i) r += !(p[i]^p[i-1]);"),
    ("buffer_low_nibble_xor", "validation", "r ^= p[i] & 15;", "r ^= p[i] % 16;"),
    ("buffer_nonascii_count", "heldout", "r += p[i]>=128;", "r += p[i] >> 7;"),
    ("buffer_saturated_byte_sum", "heldout", "r += p[i]>31 ? 31 : p[i];", "unsigned x=p[i]; r += x - (x>31 ? x-31 : 0);"),
)


def oracle(family, data):
    if family == "buffer_ascii_upper_count":
        return sum(65 <= b <= 90 for b in data)
    if family == "buffer_high_nibble_sum":
        return sum(b // 16 for b in data)
    if family == "buffer_adjacent_equal_count":
        return sum(a == b for a, b in zip(data, data[1:]))
    if family == "buffer_low_nibble_xor":
        value = 0
        for b in data:
            value ^= b % 16
        return value
    if family == "buffer_nonascii_count":
        return sum(b >= 128 for b in data)
    return sum(min(b, 31) for b in data)


def create(study):
    g.require((study / "protocol.json").is_file(), "register method before source authoring")
    g.require(not (study / "manifest.json").exists(), "refuse replacing study")
    (study / "sources").mkdir()
    rng = random.Random(20261110)
    inputs = [[], [0], [1], [15, 16], [65, 90, 91], [128, 255], [1, 1, 2], [31, 32]] + [[rng.randrange(256) for _ in range(rng.randrange(17))] for _ in range(512)]
    sources = []
    for family, split, forward, reverse in FAMILIES:
        source = """#include <windows.h>
#include <stdint.h>
#if defined(_MSC_VER)
#define KEEP __declspec(noinline)
#else
#define KEEP __attribute__((noinline,used))
#endif
#define OBSERVE() do { void *a=VirtualAlloc(0,64,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(a) VirtualFree(a,0,MEM_RELEASE); } while(0)
KEEP unsigned compute(const unsigned char *p, unsigned n) { unsigned r=0; for(unsigned i=0;i<n;i++){FORWARD} return r; }
KEEP unsigned compute_equivalent(const unsigned char *p,unsigned n) { unsigned r=0; unsigned i=n; while(i){--i; REVERSE} return r; }
KEEP unsigned subject(const unsigned char *p,unsigned n) { OBSERVE(); return compute(p,n); }
KEEP unsigned effect_helper(const unsigned char *p,unsigned n) { OBSERVE(); return compute_equivalent(p,n); }
KEEP unsigned subject_equivalent(const unsigned char *p,unsigned n) { return effect_helper(p,n); }
KEEP unsigned foil(const unsigned char *p,unsigned n) { OBSERVE(); return compute(p,n)^1u; }
KEEP unsigned no_seed(unsigned x) { return (x+1u)*3u; }
KEEP unsigned unresolved_probe(unsigned (*callback)(unsigned),unsigned x) { return callback(x); }
int main(void) { unsigned char data[16]={0}; volatile unsigned value=subject(data,16)+subject_equivalent(data,16)+foil(data,16)+unresolved_probe(no_seed,2); return (int)value; }
""".replace("FORWARD", forward).replace("REVERSE", reverse)
        path = study / "sources" / (family + ".c")
        path.write_bytes(source.encode())
        # Reversed enumeration of a sum/xor of per-index terms preserves its value.
        # For adjacency the term still uses p[i-1], not a reversed buffer.
        outputs = [oracle(family, data) for data in inputs]
        sources.append(
            dict(
                family=family,
                split=split,
                path=path.relative_to(base.ROOT).as_posix(),
                sha256=base.sha(path),
                source_contract="n in [0,16], readable unsigned-byte buffer; return value plus alloc/free API event sequence, same stable OS availability; addresses/timing excluded",
                equivalence_basis="Reverse order of associative/commutative unsigned sum or xor of equal per-index terms; total sum <=4080. Equivalent wrapper moves the allocation seed to effect_helper; no arithmetic overflow.",
                oracle_cases=len(inputs),
                oracle_output_digest=g.digest(outputs),
                negative_witness=dict(inputs=[], subject=0, foil=1),
            )
        )
    witnesses = []
    for split in ("discovery", "validation", "heldout"):
        families = [f for f, s, _, _ in FAMILIES if s == split]
        for left_foil, right_foil in itertools.product((0, 1), repeat=2):
            witness = next((data for data in inputs if oracle(families[0], data) ^ left_foil != oracle(families[1], data) ^ right_foil), None)
            g.require(witness is not None, "cross-family negative contract needs a witness")
            witnesses.append(dict(split=split, families=families, foil_flags=[left_foil, right_foil], inputs=witness, outputs=[oracle(f, witness) ^ flag for f, flag in zip(families, (left_foil, right_foil))]))
    g.write(
        study / "manifest.json",
        dict(
            schema_version="osgf.graph-first-corpus/0.1.0",
            protocol_sha256=base.sha(study / "protocol.json"),
            generator_sha256=base.sha(Path(__file__)),
            sources=sources,
            builds=[],
            witnesses=witnesses,
            oracle_inputs=inputs,
            limitations="Python contract examples and source algebra, not compiled execution proof; internally authored",
        ),
    )
    print("AUTHORED six new buffer families; source contract witnesses", len(witnesses), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    create(parser.parse_args().study.resolve())
