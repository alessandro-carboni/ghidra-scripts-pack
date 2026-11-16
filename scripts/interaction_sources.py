"""Fixed benign source designs; selected for semantic-view coverage, never similarity."""

import hashlib

DESIGNS = {
    "file_metadata": {
        "split": "discovery_train",
        "helper": 'DWORD a; (void)p; (void)n; a=GetFileAttributesA("C:\\\\Windows\\\\System32\\\\kernel32.dll"); return a==INVALID_FILE_ATTRIBUTES?0u:(a&65535u);',
        "body": "return file_metadata_helper(p,n)+n;",
        "description": "File-attribute word plus input length; distinct from the existing boolean file-existence probe.",
    },
    "registry_summary": {
        "split": "validation",
        "helper": 'HKEY key; DWORD subkeys=0; LONG status; (void)p; (void)n; if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\\\Microsoft",0,KEY_READ,&key)!=ERROR_SUCCESS) return 0; status=RegQueryInfoKeyA(key,0,0,0,&subkeys,0,0,0,0,0,0,0); RegCloseKey(key); return status==ERROR_SUCCESS?subkeys:0u;',
        "body": "unsigned i,count=0; for(i=0;i<n;i++) if(p[i]>=65 && p[i]<=90) count++; return registry_summary_helper(p,n)^count;",
        "description": "Read-only registry subkey count XOR uppercase-byte count; distinct from the existing key-open status probe.",
    },
    "socket_kind": {
        "split": "held_out_test",
        "helper": "WSADATA w; SOCKET s; int kind=0,size=sizeof(kind); (void)p; (void)n; if(WSAStartup(MAKEWORD(2,2),&w)) return 0; "
        "s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); if(s!=INVALID_SOCKET) { if(getsockopt(s,SOL_SOCKET,SO_TYPE,(char*)&kind,&size)!=0) kind=0; closesocket(s); } WSACleanup(); return (unsigned)kind;",
        "body": "return socket_kind_helper(p,n)*(n+1u);",
        "description": "Unconnected UDP socket type times input length plus one; no bind/connect/send and distinct from the existing TCP creation-status probe.",
    },
}
FAMILIES = ("transparent_wrapper", "thunk", "linear_chain")


def source(group):
    design = DESIGNS[group]
    artifact = "interaction_" + group
    base, opposite = artifact, artifact + "_flipped"
    signature = "(const unsigned char *p,unsigned n)"
    lines = ["#include <winsock2.h>", "#include <windows.h>", "#include <winerror.h>", "#include <stdio.h>", "#define API __declspec(dllexport) __declspec(noinline)", f"API unsigned {group}_helper{signature} {{ {design['helper']} }}"]
    bodies = {base: design["body"]}
    # Same anchor/helper/API shape, different observable result; no score consulted.
    prefix, expression = design["body"].rsplit("return ", 1)
    bodies[opposite] = prefix + "return (" + expression.rstrip(";") + ")^1u;"
    for family in FAMILIES:
        target = base + "__" + family
        if family == "thunk":
            bodies[target] = f"unsigned (*target)(const unsigned char *,unsigned)={base}; return target(p,n);"
        elif family == "linear_chain":
            lines.append(f"API unsigned {target}_inner{signature};")
            bodies[target] = f"return {target}_inner(p,n);"
        else:
            bodies[target] = f"return {base}(p,n);"
    routines, transformations = [], []
    for name, body in bodies.items():
        lines.append(f"API unsigned {name}{signature} {{ {body} }}")
        family = name.split("__", 1)[1] if "__" in name else "original"
        routines.append(
            dict(
                routine_id=name,
                source_group_id=base if family != "original" else name,
                artifact_group=artifact,
                source_path=f"samples/controlled/source/{artifact}.c",
                contract="bytes_0_255_trailing_nul_and_stable_readonly_environment",
                body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                variant=family,
                provenance="controlled_interaction_source",
                description=design["description"],
            )
        )
        if family != "original":
            transformations.append(
                dict(
                    family=family,
                    version="0.1.0",
                    parameters=dict(max_length=255, environment="same_readonly_os_state"),
                    original_routine=base,
                    transformed_routine=name,
                    rationale="Fixed delegation invokes the original routine exactly once with identical arguments, return value, API effects and error handling; no additional OS operation.",
                    validation_status="automatically_grounded",
                    validation="passed",
                    transformation_level="source",
                    test_cases_per_build=16,
                )
            )
    lines.append(f"API unsigned {base}__linear_chain_inner{signature} {{ return {base}(p,n); }}")
    lines.append("int main(void) { unsigned i,j,n; unsigned char p[256]; for(i=0;i<16;i++) { n=i*7; for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[n]=0;")
    for name in bodies:
        lines.append(f'printf("{name} %u %u\\n",i,{name}(p,n));')
    lines.append("} return 0; }")
    return "\n".join(lines) + "\n", routines, transformations


def expected(group, values, observation):
    if group == "file_metadata":
        return observation + len(values)
    if group == "registry_summary":
        return observation ^ sum(65 <= byte <= 90 for byte in values)
    if group == "socket_kind":
        return observation * (len(values) + 1)
    raise ValueError("unknown interaction source group")


def validate_behavior(group, rows, observation):
    names = {r["routine_id"] for r in source(group)[1]}
    seen = set()
    for row in rows:
        name, case, value = row.split()
        case = int(case)
        if name not in names or not 0 <= case < 16 or (name, case) in seen:
            raise ValueError("unexpected/duplicate interaction behavior case")
        seen.add((name, case))
        values = [(j * 17 + case * 13) % 127 for j in range(case * 7)]
        reference = expected(group, values, observation)
        if name.endswith("_flipped"):
            reference ^= 1
        if int(value) != reference:
            raise ValueError("interaction independent oracle mismatch: " + row)
    if len(seen) != 80:
        raise ValueError("incomplete interaction behavior coverage")
