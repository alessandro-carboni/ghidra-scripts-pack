"""Rebuild the benign controlled corpus without an LLM or similarity-derived labels."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

try:
    from .controlled_build import BuildFailure, assert_portable_metadata, build_pe, pe_architecture
except ImportError:
    from controlled_build import BuildFailure, assert_portable_metadata, build_pe, pe_architecture

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets/osgf_pairs_v0_1"
SOURCE = ROOT / "samples/controlled/source"
BUILDS = ROOT / "samples/controlled/builds"

# Unsigned arithmetic is modulo 2**32. Input contract: p points to n bytes,
# 0 <= n <= 255, with a trailing NUL available for the API routines.
ROUTINES = {
    "numeric": {
        "sum_array": "unsigned r=0,i; for(i=0;i<n;i++) r+=p[i]; return r;",
        "find_max": "unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>r) r=p[i]; return r;",
        "count_matches": "unsigned r=0,i; for(i=0;i<n;i++) if(p[i]==32) r++; return r;",
    },
    "text": {
        "count_digits": "unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>=48 && p[i]<=57) r++; return r;",
        "count_letters": "unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>=65 && p[i]<=90) r++; return r;",
        "search_string": "unsigned i; for(i=0;i+1<n;i++) if(p[i]==65 && p[i+1]==66) return i+1; return 0;",
    },
    "memory": {
        "copy_buffer": "unsigned char dst[256]; unsigned i,r=0; memcpy(dst,p,n); for(i=0;i<n;i++) r+=dst[i]; return r;",
        "xor_buffer": "unsigned r=0,i; for(i=0;i<n;i++) r^=p[i]; return r;",
        "weighted_buffer": "unsigned r=0,i; for(i=0;i<n;i++) r+=(i+1)*p[i]; return r;",
    },
    "system_api": {
        "read_file": 'DWORD a; (void)p; (void)n; a=GetFileAttributesA("C:\\\\Windows\\\\System32\\\\kernel32.dll"); return a!=INVALID_FILE_ATTRIBUTES;',
        "create_socket": "WSADATA w; SOCKET s; unsigned r; (void)p; (void)n; if(WSAStartup(MAKEWORD(2,2),&w)) return 0; s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); r=s!=INVALID_SOCKET; if(r) closesocket(s); WSACleanup(); return r;",
        "read_registry_value": 'HKEY k; LONG e; (void)p; (void)n; e=RegOpenKeyExA(HKEY_CURRENT_USER,"Software",0,KEY_READ,&k); if(e==ERROR_SUCCESS) RegCloseKey(k); return e==ERROR_SUCCESS;',
    },
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    assert_portable_metadata(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def execute(command, **kwargs):
    for attempt in range(3):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False, **kwargs)
            break
        except PermissionError:
            if attempt == 2:
                raise
            time.sleep(1)
    if result.returncode:
        raise RuntimeError(f"command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def generate_sources():
    SOURCE.mkdir(parents=True, exist_ok=True)
    catalog = []
    for group, routines in ROUTINES.items():
        lines = ["#include <winsock2.h>", "#include <windows.h>", "#include <winerror.h>", "#include <stdio.h>", "#include <string.h>", "#define API __declspec(dllexport) __declspec(noinline)"]
        for name, body in routines.items():
            lines.append(f"API unsigned {name}(const unsigned char *p,unsigned n) {{ {body} }}")
            catalog.append(dict(routine_id=name, source_group_id=name, artifact_group=group, source_path=f"samples/controlled/source/{group}.c", contract="bytes_0_255_trailing_nul", body_sha256=hashlib.sha256(body.encode()).hexdigest(), provenance="controlled_authored_source", variants=["original"]))
        lines.append("int main(void) { unsigned i,j; unsigned char p[256]; for(i=0;i<16;i++) { for(j=0;j<i*7;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[i*7]=0;")
        for name in routines:
            lines.append(f'printf("{name} %u %u\\n",i,{name}(p,i*7));')
        lines.append("} return 0; }")
        (SOURCE / f"{group}.c").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return catalog


def compiler_inventory():
    available, unavailable = [], []
    vcvars = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars32.bat"
    if vcvars.is_file():
        shell = f'call "{vcvars}" >nul && set'
        env = os.environ.copy()
        for line in execute(f'cmd.exe /d /s /c "{shell}"').splitlines():
            if "=" in line and not line.startswith("="):
                key, value = line.split("=", 1)
                env[key.upper()] = value
        cl = shutil.which("cl.exe", path=env.get("PATH"))
        if cl:
            info = subprocess.run([cl], env=env, capture_output=True, text=True, check=False)
            available.append(dict(compiler="msvc", path=cl, version=(info.stderr or info.stdout).splitlines()[0], env=env, optimizations=["O0", "O2"]))
    if not any(c["compiler"] == "msvc" for c in available):
        unavailable.append("msvc: vcvars32/cl not available")
    for name, command in (("clang", "clang"), ("gcc", "gcc")):
        path = shutil.which(command)
        if path:
            available.append(dict(compiler=name, path=path, version=execute([path, "--version"]).splitlines()[0], env=os.environ.copy(), optimizations=["O0", "O2", "O3"]))
        else:
            unavailable.append(f"{name}: not available on PATH")
    if not available:
        raise ValueError("No compiler available")
    return available, unavailable


def build_corpus():
    try:
        from .validate_controlled_corpus import validate_behavior
    except ImportError:
        from validate_controlled_corpus import validate_behavior
    routines = generate_sources()
    compilers, unavailable = compiler_inventory()
    samples, builds, failures = [], [], []
    BUILDS.mkdir(parents=True, exist_ok=True)
    for compiler in compilers:
        for optimization in compiler["optimizations"]:
            for group in ROUTINES:
                source = SOURCE / f"{group}.c"
                build_id = f"{group}-{compiler['compiler']}-{optimization}"
                directory = BUILDS / build_id
                directory.mkdir(parents=True, exist_ok=True)
                output = directory / f"{build_id}.exe"

                def flags_for_output(target):
                    if compiler["compiler"] == "msvc":
                        return ["/nologo", "/Od" if optimization == "O0" else "/O2", "/Brepro", "/W3", "/D_CRT_SECURE_NO_WARNINGS", str(source), f"/Fe{target}", "/link", "/INCREMENTAL:NO", "/OPT:NOICF", "ws2_32.lib", "advapi32.lib"]
                    flags = [f"-{optimization}", "-fno-ipa-icf", "-Wl,--no-insert-timestamp", str(source), "-o", str(target), "-lws2_32", "-ladvapi32"]
                    if compiler["compiler"] == "clang":
                        flags.remove("-fno-ipa-icf")
                    return flags

                try:
                    result = build_pe(compiler, build_id, optimization, output, flags_for_output, lambda rows: validate_behavior(group, rows))
                except BuildFailure as error:
                    failures.append(error.record)
                    print(f"BUILD FAILED {build_id}: {error}", flush=True)
                    continue
                (directory / "behavior.txt").write_text("\n".join(result["behavior"]) + "\n", encoding="utf-8")
                build_hash = digest(output)
                metadata = dict(
                    build_id=build_id,
                    compiler=compiler["compiler"],
                    compiler_version=compiler["version"],
                    optimization=optimization,
                    source_path=source.relative_to(ROOT).as_posix(),
                    source_hash=digest(source),
                    build_hash=build_hash,
                    artifact_group=group,
                    **result,
                )
                builds.append(metadata)
                samples.append(dict(sample_id=build_id, build_id=build_id, path=output.relative_to(ROOT).as_posix(), filename=output.name, sha256=build_hash, architecture=metadata["architecture"], origin="controlled_source", provenance="controlled_benign", compiler=compiler["compiler"]))
                print(f"BUILD PASS {build_id}: {metadata['architecture']} sha256={build_hash}", flush=True)
    benign = ROOT / "samples/benign_realworld"
    benign.mkdir(parents=True, exist_ok=True)
    for filename in ("whoami.exe", "hostname.exe", "where.exe", "findstr.exe", "ping.exe", "tracert.exe", "ipconfig.exe", "tasklist.exe"):
        original = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / filename
        if not original.is_file():
            continue
        target = benign / filename
        shutil.copy2(original, target)
        if digest(original) != digest(target):
            raise ValueError(f"copy hash mismatch: {filename}")
        samples.append(
            dict(sample_id=f"system32-{filename}", build_id=None, path=target.relative_to(ROOT).as_posix(), filename=filename, sha256=digest(target), architecture=pe_architecture(target), origin=f"${{SystemRoot}}/System32/{filename}", provenance="windows_system32_benign_validation_only", compiler="unknown")
        )
    if len(samples) - len(builds) < 5:
        raise ValueError("Fewer than five trusted System32 executables available")
    catalog = dict(schema_version="0.1.0", routines=routines, builds=builds, samples=samples, unavailable_compilers=unavailable, build_failures=failures, ground_truth_policy="source_contract_and_behavior_only; never OSGF similarity")
    save(DATA / "corpus.json", catalog)
    print(f"CORPUS PASS: {len(routines)} routines; {len(builds)} controlled builds; {len(samples) - len(builds)} benign real-world samples; unavailable={unavailable}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    build_corpus()
