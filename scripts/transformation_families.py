"""Bounded pure source transformations; no compilation, scoring or inferred graph effects."""

try:
    from .controlled_corpus import ROUTINES
    from .transformation_schema import CONTRACT, FAMILIES, VERSION, check_schema, stable_id
except ImportError:
    from controlled_corpus import ROUTINES
    from transformation_schema import CONTRACT, FAMILIES, VERSION, check_schema, stable_id

PURE = {name: body for group, routines in ROUTINES.items() if group != "system_api" for name, body in routines.items()}
OPERATORS = {"sum_array": "sum", "find_max": "max", "count_matches": "sum", "count_digits": "sum", "count_letters": "sum", "copy_buffer": "sum", "xor_buffer": "xor"}


def default_parameters(family):
    common = dict(naming_policy="stable_hash", preservation_hint="noinline")
    parameters = {
        "transparent_wrapper": dict(wrapper_depth=1, delegation="direct"),
        "thunk": dict(thunk_depth=1, delegation="fixed_pointer"),
        "function_splitting": dict(split_count=2, partition_strategy="balanced_contiguous", combine_operator="routine_reduction", empty_input_policy="zero"),
        "dead_branch": dict(guard_expression="n > 255", unreachable_condition="contract_max_255", dead_branch_payload="constant_return", payload_value=123, insertion_point="entry"),
        "harmless_strand": dict(number_of_strands=1, pure_operation_family="unsigned_mix", insertion_point="before_delegate", data_dependency="input_length"),
        "instruction_reordering": dict(operation_family="independent_partition_reductions", order=["right", "left"], side_effects="none", aliasing="read_only_buffer"),
    }
    if family not in parameters:
        raise ValueError("unsupported transformation family")
    return dict(common, **parameters[family])


def validate_parameters(family, parameters):
    expected = default_parameters(family)
    if set(parameters) != set(expected):
        raise ValueError("missing/unknown transformation parameter")
    for key in expected:
        if type(parameters[key]) is not type(expected[key]):
            raise ValueError("invalid parameter type: " + key)
    if parameters["naming_policy"] != "stable_hash" or parameters["preservation_hint"] not in ("noinline", "allow_inline"):
        raise ValueError("unsafe naming/preservation policy")
    configurable = {"preservation_hint", "wrapper_depth", "thunk_depth", "split_count", "number_of_strands", "payload_value", "delegation", "order"}
    for key in expected.keys() - configurable:
        if parameters[key] != expected[key]:
            raise ValueError("unsupported/unsafe parameter: " + key)
    for key in ("wrapper_depth", "thunk_depth", "split_count", "number_of_strands"):
        if key in parameters and not (2 if key == "split_count" else 1) <= parameters[key] <= 8:
            raise ValueError("bounded depth/count exceeded")
    if "payload_value" in parameters and not 0 <= parameters["payload_value"] < 2**32:
        raise ValueError("payload must be unsigned 32-bit")
    if family == "thunk" and parameters["delegation"] not in ("direct", "fixed_pointer"):
        raise ValueError("only stable thunk targets allowed")
    if family == "transparent_wrapper" and parameters["delegation"] != "direct":
        raise ValueError("wrapper requires direct delegation")
    if family == "instruction_reordering" and parameters["order"] not in (["left", "right"], ["right", "left"]):
        raise ValueError("only independent partition permutations supported")


def generate(routine, family, parameters, deterministic_seed, contract):
    if family not in FAMILIES:
        raise ValueError("unknown family")
    check_schema(contract, CONTRACT)
    if type(deterministic_seed) is not int or not 0 <= deterministic_seed < 2**32:
        raise ValueError("seed must be unsigned 32-bit")
    validate_parameters(family, parameters)
    name = routine["routine_id"]
    if name not in PURE or contract["kind"] != "pure_bytes":
        return dict(status="unsupported", source=None, diagnostics=["Only recognized pure source routines are supported; environmental effects require a separate proof."], source_mappings=[], proof_obligations=[])
    if family in ("function_splitting", "instruction_reordering") and name not in OPERATORS:
        return dict(status="unsupported", source=None, diagnostics=["Routine has no proven associative partition reduction."], source_mappings=[], proof_obligations=[])
    token = stable_id("source", dict(routine=name, family=family, parameters=parameters, seed=deterministic_seed, generator_version=VERSION)).split(":")[1]
    original, target = "original_" + token, "transformed_" + token
    hint = " __declspec(noinline)" if parameters["preservation_hint"] == "noinline" else ""
    prefix, signature = "API unsigned ", "(const unsigned char *p,unsigned n)"
    lines = ["#include <stdio.h>", "#include <string.h>", "#define API __declspec(dllexport)" + hint, f"{prefix}{original}{signature} {{ {PURE[name]} }}"]
    generated = []
    obligations = ["Readable non-volatile input bytes, 0<=n<=255, trailing NUL; unsigned 32-bit result; no concurrent mutation or externally observable effects."]

    def function(symbol, body, sig=signature):
        lines.append(f"{prefix}{symbol}{sig} {{ {body} }}")
        generated.append(symbol)

    if family in ("transparent_wrapper", "thunk"):
        depth = parameters["wrapper_depth" if family == "transparent_wrapper" else "thunk_depth"]
        callee = original
        for index in range(depth):
            symbol = target if index == depth - 1 else target + f"_stage_{index}"
            body = f"return {callee}(p,n);"
            if family == "thunk" and parameters["delegation"] == "fixed_pointer":
                body = f"unsigned (*const fixed_target)(const unsigned char *,unsigned)={callee}; return fixed_target(p,n);"
            function(symbol, body)
            callee = symbol
        obligations.append("Every delegation invokes exactly one fixed target with identical arguments and returns its result; chain terminates at the original.")
    elif family == "function_splitting":
        count = parameters["split_count"]
        body = ["unsigned result=0;"]
        operator = OPERATORS[name]
        for index in range(count):
            helper = target + f"_partition_{index}"
            function(helper, f"unsigned start=n*{index}u/{count}u,end=n*{index + 1}u/{count}u; return {original}(p+start,end-start);")
            body.append(f"unsigned r{index}={helper}(p,n);")
        for index in range(count):
            body.append(f"result={'result+r' + str(index) if operator == 'sum' else 'result^r' + str(index) if operator == 'xor' else 'result>r' + str(index) + '?result:r' + str(index)};")
        body.append("return result;")
        function(target, " ".join(body))
        obligations.append(f"Balanced disjoint contiguous partitions cover each byte once; {operator} has identity zero on this unsigned-byte domain, including empty partitions; n*i<=2040.")
    elif family == "dead_branch":
        function(target, f"if(n>255u) return {parameters['payload_value']}u; return {original}(p,n);")
        obligations.append("n>255 is unreachable under the input contract; outside-contract behavior is unspecified and deliberately not claimed equivalent.")
    elif family == "harmless_strand":
        helpers = []
        for index in range(parameters["number_of_strands"]):
            helper = target + f"_strand_{index}"
            constant = ((deterministic_seed + index) % 251) + 1
            function(helper, f"return (n*{constant}u)^91u;", "(unsigned n)")
            helpers.append(f"(void){helper}(n);")
        function(target, " ".join(helpers) + f" return {original}(p,n);")
        obligations.append("Added helpers only compute total unsigned arithmetic on scalar n; no memory write, volatile, I/O, global state or result dependency.")
    else:
        expressions = {"left": f"a={original}(p,middle);", "right": f"b={original}(p+middle,n-middle);"}
        combine = {"sum": "a+b", "xor": "a^b", "max": "a>b?a:b"}[OPERATORS[name]]
        function(target, "unsigned middle=n/2,a,b; " + " ".join(expressions[part] for part in parameters["order"]) + f" return {combine};")
        obligations.append("Two independent pure sub-reductions read disjoint partitions and write separate local scalars; changing their evaluation order cannot change the associative combined result. This is source-level reordering, not machine instruction rewriting.")
    mapping = dict(original_elements=[name], generated_elements=[original, *generated], mapping_level="source", mapping_kind="one_to_many", status="expected", evidence="Deterministic generator declarations, not binary correspondence.")
    return dict(
        status="generated",
        source="\n".join(lines) + "\n",
        original_function=original,
        transformed_function=target,
        generated_functions=generated,
        source_mappings=[mapping],
        proof_obligations=obligations,
        transformation_level="source",
        expected_source_effects=[family, "parameters applied exactly"],
        expected_graph_effects=["unknown until real extraction; compiler may inline, merge or eliminate source effects"],
        diagnostics=[],
        generator_version=VERSION,
    )


def source_bytes(generated):
    if generated["status"] != "generated":
        raise ValueError("unsupported generation has no source artifact")
    return generated["source"].replace("\n", "\r\n").encode("utf-8")
