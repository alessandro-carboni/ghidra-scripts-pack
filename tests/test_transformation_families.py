import shutil
import subprocess

import pytest

from scripts.transformation_families import default_parameters, generate, source_bytes
from scripts.transformation_schema import FAMILIES

CONTRACT = dict(kind="pure_bytes", min_length=0, max_length=255, trailing_nul=True, result_bits=32, preconditions=["readable nonvolatile buffer; no concurrent mutation"])


@pytest.mark.parametrize("family", FAMILIES)
def test_parameters_determinism_source_mapping_and_obligations(family):
    params = default_parameters(family)
    result = generate(dict(routine_id="sum_array"), family, params, 7, CONTRACT)
    assert result == generate(dict(routine_id="sum_array"), family, params, 7, CONTRACT)
    assert result["source_mappings"][0]["mapping_kind"] == "one_to_many"
    assert result["transformation_level"] == "source" and len(result["proof_obligations"]) >= 2
    assert source_bytes(result).count(b"\r\n") == source_bytes(result).count(b"\n")
    assert result["source"] != generate(dict(routine_id="sum_array"), family, params, 8, CONTRACT)["source"]
    changed = dict(params, preservation_hint="allow_inline")
    assert result["source"] != generate(dict(routine_id="sum_array"), family, changed, 7, CONTRACT)["source"]
    for invalid in (dict(params, unexpected=True), dict(params, naming_policy="arbitrary code"), dict(params, preservation_hint="volatile")):
        with pytest.raises(ValueError):
            generate(dict(routine_id="sum_array"), family, invalid, 0, CONTRACT)


@pytest.mark.parametrize("family,key", [("transparent_wrapper", "wrapper_depth"), ("thunk", "thunk_depth"), ("function_splitting", "split_count"), ("harmless_strand", "number_of_strands")])
def test_bounded_counts(family, key):
    for bad in (-1, 0, 9, True):
        params = dict(default_parameters(family), **{key: bad})
        with pytest.raises(ValueError):
            generate(dict(routine_id="find_max"), family, params, 0, CONTRACT)
    params = dict(default_parameters(family), **{key: 8})
    assert generate(dict(routine_id="find_max"), family, params, 0, CONTRACT)["status"] == "generated"


@pytest.mark.parametrize("key,bad", [("operation_family", "dependent_accumulator_updates"), ("side_effects", "IO"), ("aliasing", "unknown"), ("order", ["left", "left"])])
def test_unsafe_reordering_rejected(key, bad):
    params = dict(default_parameters("instruction_reordering"), **{key: bad})
    with pytest.raises(ValueError):
        generate(dict(routine_id="sum_array"), "instruction_reordering", params, 0, CONTRACT)


def test_unsupported_routines_and_invalid_contract():
    for name in ("read_file", "invented", "search_string"):
        result = generate(dict(routine_id=name), "function_splitting", default_parameters("function_splitting"), 0, CONTRACT)
        assert result["status"] == "unsupported" and result["source"] is None and result["diagnostics"]
    with pytest.raises(ValueError):
        generate(dict(routine_id="sum_array"), "dead_branch", default_parameters("dead_branch"), 0, dict(CONTRACT, max_length=999))
    for key, value in (("guard_expression", "n > 0"), ("dead_branch_payload", "network_call")):
        with pytest.raises(ValueError):
            generate(dict(routine_id="sum_array"), "dead_branch", dict(default_parameters("dead_branch"), **{key: value}), 0, CONTRACT)


@pytest.mark.parametrize("family", FAMILIES)
def test_real_c_syntax_and_edge_behavior(family, tmp_path):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("GCC unavailable: real family edge integration not run")
    # Linux syntax compatibility for the portable pure source subset; Windows uses PE controls.
    for name in ("sum_array", "xor_buffer", "find_max"):
        params = default_parameters(family)
        result = generate(dict(routine_id=name), family, params, 5, CONTRACT)
        text = result["source"]
        if not compiler.lower().endswith(".exe"):
            text = text.replace("#define API __declspec(dllexport) __declspec(noinline)", "#define API __attribute__((noinline))")
        text += f"""
int main(void) {{
 unsigned char p[256]; unsigned i,n; for(i=0;i<256;i++) p[i]=(unsigned char)(i%251);
 for(n=0;n<=255;n++) {{
  unsigned oracle=0; for(i=0;i<n;i++) {{
   {"oracle+=p[i];" if name == "sum_array" else "oracle^=p[i];" if name == "xor_buffer" else "if(p[i]>oracle) oracle=p[i];"}
  }}
  if({result["original_function"]}(p,n)!=oracle || {result["transformed_function"]}(p,n)!=oracle) return 1;
 }} return 0;
}}
"""
        path = tmp_path / (name + ".c")
        path.write_bytes(text.replace("\n", "\r\n").encode())
        binary = tmp_path / (name + ".exe")
        subprocess.run([compiler, "-O0", str(path), "-o", str(binary)], check=True, capture_output=True, timeout=60)
        subprocess.run([str(binary)], check=True, capture_output=True, timeout=20)
