"""Compile registered value-flow sources; never execute the produced programs."""

import argparse
import json
from pathlib import Path

try:
    from .controlled_corpus import compiler_inventory
    from .evaluate_operational_baseline import ROOT, command, require, save, sha
except ImportError:
    from controlled_corpus import compiler_inventory
    from evaluate_operational_baseline import ROOT, command, require, save, sha


def build(study):
    study = study.resolve()
    manifest_path = study / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    compilers, unavailable = compiler_inventory()
    compilers = {c["compiler"]: c for c in compilers}
    require(all(c in compilers for c in ("gcc", "msvc")), str(unavailable))
    completed = {b["id"]: b for b in manifest["builds"]}
    for source in manifest["sources"]:
        src = ROOT / source["path"]
        require(sha(src) == source["sha256"], "registered source changed")
        for compiler, optimization in (("gcc", "O0"), ("gcc", "O2"), ("msvc", "O0")):
            ident = f"{source['family']}-{compiler}-{optimization}"
            folder = study / "runtime/builds" / ident
            folder.mkdir(parents=True, exist_ok=True)
            binary = folder / (ident + ".exe")
            if ident in completed:
                require(sha(binary) == completed[ident]["sha256"], "previous build changed")
                continue
            require(not binary.exists(), "unregistered executable exists")
            c = compilers[compiler]
            if compiler == "gcc":
                flags = ["-" + optimization, "-fno-inline", "-fno-ipa-icf", "-Wl,--no-insert-timestamp", str(src), "-o", str(binary)]
            else:
                flags = ["/nologo", "/Od", "/Brepro", "/W3", str(src), "/Fo" + str(folder / (ident + ".obj")), "/Fe" + str(binary), "/link", "/INCREMENTAL:NO", "/OPT:NOICF", "/IMPLIB:" + str(folder / (ident + ".lib"))]
            receipt = command([c["path"], *flags], folder / "compile.log", env=c["env"])
            manifest["builds"].append(dict(id=ident, family=source["family"], split=source["split"], compiler=compiler, compiler_version=c["version"], optimization=optimization, path=binary.relative_to(ROOT).as_posix(), sha256=sha(binary), source_sha256=sha(src), compile=receipt))
            save(manifest_path, manifest)
            print("PASS compiled, never executed:", ident, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-dir", type=Path, required=True)
    build(parser.parse_args().study_dir)
