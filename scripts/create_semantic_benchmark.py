"""Author new scalar-function families only after freezing the semantic method."""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess

try:
    from .evaluate_operational_baseline import ROOT, require, save, sha
except ImportError:
    from evaluate_operational_baseline import ROOT, require, save, sha

MASK = 2**32 - 1


def spread(x):
    x &= 65535
    for shift, mask in [(8, 0x00FF00FF), (4, 0x0F0F0F0F), (2, 0x33333333), (1, 0x55555555)]:
        x = (x | (x << shift)) & mask
    return x


def create(study):
    method = study / "method.json"
    require(method.exists(), "lock method before authoring data")
    require(not (study / "manifest.json").exists(), "never overwrite corpus")
    recipes = [
        ("unsigned_distance", "discovery", "return x >= y ? x-y : y-x;", "unsigned lo=x,hi=y; if(lo>hi){lo=y;hi=x;} return hi-lo;", "return (x >= y ? x-y : y-x)^1u;", "Ordering selects max-min, in [0,2^32-1].", lambda x, y, z: abs(x - y), lambda x, y, z: max(x, y) - min(x, y)),
        (
            "gray_encoding",
            "discovery",
            "return x^(x>>1);",
            "unsigned r=0,i; for(i=0;i<32;i++) r|=(((x>>i)^((x>>1)>>i))&1u)<<i; return r;",
            "return (x^(x>>1))^1u;",
            "Each output bit is input bit i xor bit i+1; bit32 is zero.",
            lambda x, y, z: x ^ (x // 2),
            lambda x, y, z: sum((((x >> i) & 1) ^ ((x >> (i + 1)) & 1)) << i for i in range(32)),
        ),
        (
            "median_three",
            "validation",
            "unsigned a=x,b=y,c=z,t; if(a>b){t=a;a=b;b=t;} if(b>c){t=b;b=c;c=t;} if(a>b){t=a;a=b;b=t;} return b;",
            "return x>y ? (y>z?y:(x>z?z:x)) : (x>z?x:(y>z?z:y));",
            "unsigned a=x,b=y,c=z,t; if(a>b){t=a;a=b;b=t;} if(b>c){t=b;b=c;c=t;} if(a>b){t=a;a=b;b=t;} return b^1u;",
            "Three compare-exchanges sort; nested inequalities select middle order statistic including ties.",
            lambda x, y, z: sorted([x, y, z])[1],
            lambda x, y, z: (y if y > z else z if x > z else x) if x > y else (x if x > z else z if y > z else y),
        ),
        (
            "byte_reversal",
            "validation",
            "return ((x&255u)<<24)|((x&65280u)<<8)|((x>>8)&65280u)|(x>>24);",
            "unsigned r=0,i; for(i=0;i<4;i++) r=(r<<8)|((x>>(8*i))&255u); return r;",
            "return (((x&255u)<<24)|((x&65280u)<<8)|((x>>8)&65280u)|(x>>24))^1u;",
            "Disjoint byte masks map byte i to position 3-i; iterative assembly gives same permutation.",
            lambda x, y, z: int.from_bytes(x.to_bytes(4, "little"), "big"),
            lambda x, y, z: sum(((x >> (8 * i)) & 255) << (8 * (3 - i)) for i in range(4)),
        ),
        (
            "morton_interleave",
            "heldout",
            "unsigned r=0,i; for(i=0;i<16;i++){r|=((x>>i)&1u)<<(2*i); r|=((y>>i)&1u)<<(2*i+1);} return r;",
            "unsigned a=x&65535u,b=y&65535u; a=(a|(a<<8))&0x00ff00ffu; a=(a|(a<<4))&0x0f0f0f0fu; a=(a|(a<<2))&0x33333333u; a=(a|(a<<1))&0x55555555u; b=(b|(b<<8))&0x00ff00ffu; b=(b|(b<<4))&0x0f0f0f0fu; b=(b|(b<<2))&0x33333333u; b=(b|(b<<1))&0x55555555u; return a|(b<<1);",
            "unsigned r=0,i; for(i=0;i<16;i++){r|=((x>>i)&1u)<<(2*i); r|=((y>>i)&1u)<<(2*i+1);} return r^1u;",
            "Successive disjoint masks spread low16 bits into even positions; y occupies odd positions. Higher input bits are ignored.",
            lambda x, y, z: sum(((x >> i) & 1) << (2 * i) | ((y >> i) & 1) << (2 * i + 1) for i in range(16)),
            lambda x, y, z: spread(x) | (spread(y) << 1),
        ),
        (
            "unsigned_average",
            "heldout",
            "return (x&y)+((x^y)>>1);",
            "return (x>>1)+(y>>1)+((x&1u)&(y&1u));",
            "return ((x&y)+((x^y)>>1))^1u;",
            "x+y=2*(x&y)+(x^y); quotient/remainder decomposition also yields floor((x+y)/2) without 32-bit overflow.",
            lambda x, y, z: (x + y) // 2,
            lambda x, y, z: (x // 2) + (y // 2) + ((x & 1) & (y & 1)),
        ),
    ]
    rng = random.Random(20261109)
    inputs = list(itertools.product([0, 1, MASK], repeat=3)) + [tuple(rng.randrange(2**32) for _ in range(3)) for _ in range(1024)]
    old = subprocess.check_output(["git", "ls-files", "-z", "*.c"], cwd=ROOT).decode().split("\0")
    old_hashes = {sha(ROOT / p) for p in old if p and (ROOT / p).is_file()}
    sources = []
    (study / "sources").mkdir(exist_ok=False)
    for family, split, original, equivalent, foil, proof, oracle, alternative in recipes:
        expected = [oracle(*x) for x in inputs]
        require(all(0 <= n <= MASK for n in expected), "oracle range")
        require(expected == [alternative(*x) for x in inputs], "independent oracle disagreement")
        require(all(n != (n ^ 1) for n in expected), "negative witness failed")
        text = "/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.\n * " + proof + "\n * Foil flips result bit0; differs for every valid input.\n */\n#define API __declspec(dllexport) __declspec(noinline)\ntypedef char require_u32[(sizeof(unsigned)==4)?1:-1];\n"
        for name, body in [("subject", original), ("subject_equivalent", equivalent), ("foil", foil)]:
            text += f"API unsigned {name}(unsigned x,unsigned y,unsigned z) {{ {body} }}\n"
        text += "int main(void) { return 0; }\n"
        path = study / "sources" / (family + ".c")
        path.write_bytes(text.encode())
        require(sha(path) not in old_hashes, "source duplicates an existing tracked source")
        sources.append(
            dict(
                family=family,
                split=split,
                path=path.relative_to(ROOT).as_posix(),
                sha256=sha(path),
                source_proof=proof,
                contract="all unsigned32 x/y/z; no environmental input; foil=result XOR 1",
                oracle_cases=len(inputs),
                oracle_outputs_sha256=hashlib.sha256(json.dumps(expected).encode()).hexdigest(),
                negative_witness=dict(inputs=inputs[0], subject=expected[0], foil=expected[0] ^ 1),
            )
        )
    save(
        study / "manifest.json",
        dict(schema_version="osgf.semantic-benchmark/0.1.0", method_sha256=sha(method), generator_sha256=sha(Path(__file__)), oracle_seed=20261109, sources=sources, builds=[], independence="New source behavior families authored after generic method lock; internal prospective benchmark, not externally blinded"),
    )
    (study / ".gitignore").write_text("runtime/\n", encoding="utf-8")
    (study / ".gitattributes").write_text("* text eol=lf\n", encoding="utf-8")
    print("PASS new corpus:", len(sources), "families;", len(inputs), "independent Python oracle cases per family; no target execution")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    create(parser.parse_args().study.resolve())
