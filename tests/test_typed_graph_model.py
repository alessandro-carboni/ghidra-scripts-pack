import json
import unittest

from ghidra_scripts import export_report
from ghidra_scripts.typed_graph_model import (
    API_ID_PREFIX,
    VISIBILITY_ID_PREFIX,
    CONSTANT_ID_PREFIX,
    EDGE_ENDPOINT_TYPES,
    EDGE_TYPES,
    FUNCTION_ID_PREFIX,
    NODE_TYPES,
    SECTION_ID_PREFIX,
    STRING_CATEGORY_ID_PREFIX,
    STRING_ID_PREFIX,
    EdgeType,
    NodeType,
    TYPED_GRAPH_MODEL_VERSION,
    build_api_call_edge,
    build_api_id,
    build_api_node,
    build_call_visibility_indicator_node,
    build_constant_id,
    build_constant_node,
    build_constant_use_edge,
    build_function_call_edge,
    build_function_identity,
    build_function_node,
    build_function_section_edge,
    build_indirect_call_indicator_edge,
    build_section_node,
    build_stable_function_id,
    build_string_category_edge,
    build_string_category_id,
    build_string_category_node,
    build_string_id,
    build_string_node,
    build_string_reference_edge,
    build_typed_graph_model_contract,
    build_unresolved_function_call,
    normalize_entry_address,
    normalize_graph_address,
    parse_edge_type,
    parse_node_type,
    validate_edge_endpoints,
)


class FakeAddress:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class FakeSymbol:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class FakeBody:
    def __init__(self, size):
        self.size = size

    def getNumAddresses(self):
        return self.size


class FakeFunction:
    def __init__(
        self,
        entry,
        name,
        external=False,
        thunk=False,
        section=None,
        size=None,
        symbol_name=None,
        contained_addresses=None,
        thunk_target=None,
    ):
        self.entry = FakeAddress(entry)
        self.name = name
        self.external = external
        self.thunk = thunk
        self.section = section
        self.size = size
        self.symbol_name = symbol_name
        self.contained_addresses = set(contained_addresses or [])
        self.thunk_target = thunk_target
        self.body = None if size is None else FakeBody(size)

    def getEntryPoint(self):
        return self.entry

    def getName(self):
        return self.name

    def isExternal(self):
        return self.external

    def isThunk(self):
        return self.thunk

    def getThunkedFunction(self, _recursive):
        return self.thunk_target

    def getSymbol(self):
        if self.symbol_name is None:
            return None
        return FakeSymbol(self.symbol_name)

    def getBody(self):
        return self.body


class FakeMemoryBlock:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class FakeMemory:
    def __init__(self, functions):
        self.sections = {str(function.getEntryPoint()): function.section for function in functions}

    def getBlock(self, address):
        section = self.sections.get(str(address))
        if section is None:
            return None
        return FakeMemoryBlock(section)


class FakeFunctionManager:
    def __init__(self, functions):
        self.functions = functions

    def getFunctions(self, _forward):
        return iter(self.functions)

    def getFunctionAt(self, address):
        address_text = str(address)
        for function in self.functions:
            if str(function.getEntryPoint()) == address_text:
                return function
        return None

    def getFunctionContaining(self, address):
        address_text = str(address)
        for function in self.functions:
            if str(function.getEntryPoint()) == address_text:
                return function
            if address_text in function.contained_addresses:
                return function
        return None


class FakeFlowType:
    def __init__(self, call=False, computed=False):
        self.call = call
        self.computed = computed

    def isCall(self):
        return self.call

    def isComputed(self):
        return self.computed


class FakeReferenceType:
    def __init__(self, call=False):
        self.call = call

    def isCall(self):
        return self.call


class FakeReference:
    def __init__(self, target, call=False):
        self.target = None if target is None else FakeAddress(target)
        self.reference_type = FakeReferenceType(call=call)

    def getToAddress(self):
        return self.target

    def getReferenceType(self):
        return self.reference_type


class FakeScalar:
    def __init__(self, value, bit_length=32):
        self.value = value
        self.bit_length = bit_length

    def getUnsignedValue(self):
        return self.value

    def bitLength(self):
        return self.bit_length


class FakeInstruction:
    def __init__(
        self,
        address,
        call=False,
        computed=False,
        op_objects=None,
    ):
        self.address = FakeAddress(address)
        self.flow_type = FakeFlowType(call=call, computed=computed)
        self.op_objects = op_objects or []

    def getAddress(self):
        return self.address

    def getFlowType(self):
        return self.flow_type

    def getNumOperands(self):
        return len(self.op_objects)

    def getOpObjects(self, operand_index):
        return list(self.op_objects[operand_index])


class FakeDataType:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class FakeData:
    def __init__(self, address, raw_value, data_type="string"):
        self.address = FakeAddress(address)
        self.raw_value = raw_value
        self.data_type = FakeDataType(data_type)

    def getAddress(self):
        return self.address

    def getDefaultValueRepresentation(self):
        return self.raw_value

    def getDataType(self):
        return self.data_type


class FakeListing:
    def __init__(self, instruction_map=None, data_map=None):
        self.instruction_map = instruction_map or {}
        self.data_map = data_map or {}

    def getInstructions(self, body, _forward):
        return iter(self.instruction_map.get(body, []))

    def getDataContaining(self, address):
        return self.data_map.get(str(address))

    def getDataAt(self, address):
        return self.data_map.get(str(address))


class FakeReferenceManager:
    def __init__(self, reference_map=None):
        self.reference_map = reference_map or {}

    def getReferencesFrom(self, address):
        return list(self.reference_map.get(str(address), []))


class FakeProgram:
    def __init__(
        self,
        functions,
        instruction_map=None,
        reference_map=None,
        data_map=None,
    ):
        self.function_manager = FakeFunctionManager(functions)
        self.memory = FakeMemory(functions)
        self.listing = FakeListing(instruction_map, data_map)
        self.reference_manager = FakeReferenceManager(reference_map)

    def getFunctionManager(self):
        return self.function_manager

    def getMemory(self):
        return self.memory

    def getListing(self):
        return self.listing

    def getReferenceManager(self):
        return self.reference_manager


class CurrentProgramMixin:
    def run_with_program(self, program, callback):
        previous_program = getattr(export_report, "currentProgram", None)
        had_program = hasattr(export_report, "currentProgram")
        export_report.currentProgram = program

        try:
            return callback()
        finally:
            if had_program:
                export_report.currentProgram = previous_program
            else:
                delattr(export_report, "currentProgram")


class TypedGraphModelTests(CurrentProgramMixin, unittest.TestCase):
    def test_initial_node_vocabulary_is_exact(self):
        self.assertEqual(
            [node_type.value for node_type in NODE_TYPES],
            [
                "FUNCTION",
                "API",
                "STRING",
                "STRING_CATEGORY",
                "CONSTANT",
                "SECTION",
                "VISIBILITY_INDICATOR",
            ],
        )

    def test_initial_edge_vocabulary_is_exact(self):
        self.assertEqual(
            [edge_type.value for edge_type in EDGE_TYPES],
            [
                "calls_function",
                "calls_api",
                "references_string",
                "has_string_category",
                "uses_constant",
                "belongs_to_section",
                "contains_indirect_call",
            ],
        )

    def test_each_edge_has_a_formal_endpoint_contract(self):
        expected = {
            EdgeType.CALLS_FUNCTION: (
                NodeType.FUNCTION,
                NodeType.FUNCTION,
            ),
            EdgeType.CALLS_API: (
                NodeType.FUNCTION,
                NodeType.API,
            ),
            EdgeType.REFERENCES_STRING: (
                NodeType.FUNCTION,
                NodeType.STRING,
            ),
            EdgeType.HAS_STRING_CATEGORY: (
                NodeType.STRING,
                NodeType.STRING_CATEGORY,
            ),
            EdgeType.USES_CONSTANT: (
                NodeType.FUNCTION,
                NodeType.CONSTANT,
            ),
            EdgeType.BELONGS_TO_SECTION: (
                NodeType.FUNCTION,
                NodeType.SECTION,
            ),
            EdgeType.CONTAINS_INDIRECT_CALL: (
                NodeType.FUNCTION,
                NodeType.VISIBILITY_INDICATOR,
            ),
        }

        self.assertEqual(set(EDGE_ENDPOINT_TYPES), set(EDGE_TYPES))
        self.assertEqual(EDGE_ENDPOINT_TYPES, expected)

    def test_edge_endpoint_validation_accepts_enum_and_string_values(self):
        validate_edge_endpoints(
            EdgeType.CALLS_API,
            NodeType.FUNCTION,
            NodeType.API,
        )
        validate_edge_endpoints(
            "has_string_category",
            "STRING",
            "STRING_CATEGORY",
        )

    def test_edge_endpoint_validation_rejects_invalid_relationship(self):
        with self.assertRaises(ValueError):
            validate_edge_endpoints(
                "calls_api",
                "FUNCTION",
                "FUNCTION",
            )

    def test_unknown_node_and_edge_types_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_node_type("UNKNOWN")
        with self.assertRaises(ValueError):
            parse_edge_type("unknown_edge")

    def test_entry_address_normalization_is_deterministic(self):
        self.assertEqual(
            normalize_entry_address("  0040ABCD  "),
            "0040abcd",
        )
        self.assertEqual(
            normalize_entry_address("0x0040ABCD"),
            "0040abcd",
        )
        self.assertEqual(
            normalize_graph_address("  0x0040ABCD "),
            "0040abcd",
        )

    def test_stable_function_id_is_derived_from_entry_address(self):
        self.assertEqual(
            build_stable_function_id("00401000"),
            "fn:00401000",
        )
        self.assertEqual(
            build_stable_function_id("0x0040ABCD"),
            "fn:0040abcd",
        )

    def test_function_rename_does_not_change_stable_id(self):
        original = build_function_identity(
            "00401000",
            "FUN_00401000",
        )
        renamed = build_function_identity(
            "00401000",
            "decode_payload",
        )

        self.assertEqual(original["id"], renamed["id"])
        self.assertNotEqual(original["name"], renamed["name"])

    def test_same_name_at_different_entries_has_different_stable_ids(self):
        first = build_function_identity("00401000", "handler")
        second = build_function_identity("00402000", "handler")
        self.assertNotEqual(first["id"], second["id"])

    def test_function_identity_preserves_metadata_separately(self):
        identity = build_function_identity(
            "0040ABCD",
            "FUN_0040ABCD",
            "ProcessPayload",
        )
        self.assertEqual(
            identity,
            {
                "id": "fn:0040abcd",
                "name": "FUN_0040ABCD",
                "entry": "0040abcd",
                "symbol_name": "ProcessPayload",
            },
        )

    def test_function_identity_allows_missing_symbol_name(self):
        identity = build_function_identity(
            "00401000",
            "FUN_00401000",
        )
        self.assertIsNone(identity["symbol_name"])

    def test_invalid_function_entry_addresses_are_rejected(self):
        for value in (None, "", "   ", "fn:00401000"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    build_stable_function_id(value)

    def test_function_node_contains_required_step_2_3_fields(self):
        node = build_function_node(
            entry_address="00401000",
            ghidra_name="FUN_00401000",
            symbol_name="DecodePayload",
            external=False,
            thunk=False,
            section=".text",
            size=128,
        )
        self.assertEqual(
            node,
            {
                "id": "fn:00401000",
                "type": "FUNCTION",
                "address": "00401000",
                "name": "FUN_00401000",
                "symbol_name": "DecodePayload",
                "external": False,
                "internal": True,
                "thunk": False,
                "section": ".text",
                "size": 128,
            },
        )

    def test_function_node_rejects_invalid_flags_and_size(self):
        with self.assertRaises(ValueError):
            build_function_node(
                "00401000",
                "FUN_00401000",
                external="false",
                thunk=False,
            )
        with self.assertRaises(ValueError):
            build_function_node(
                "00401000",
                "FUN_00401000",
                external=False,
                thunk=0,
            )
        for invalid_size in (-1, 12.5, True):
            with self.subTest(size=invalid_size):
                with self.assertRaises(ValueError):
                    build_function_node(
                        "00401000",
                        "FUN_00401000",
                        external=False,
                        thunk=False,
                        size=invalid_size,
                    )

    def test_exporter_function_nodes_are_internal_only_after_step_2_5(self):
        external = FakeFunction(
            "EXTERNAL:00000001",
            "CreateFileW",
            external=True,
            thunk=True,
        )
        import_thunk = FakeFunction(
            "00403000",
            "thunk_CreateFileW",
            thunk=True,
            section=".text",
            size=8,
            thunk_target=external,
        )
        functions = [
            FakeFunction(
                "00402000",
                "second",
                section=".text",
                size=64,
            ),
            FakeFunction(
                "00401000",
                "first",
                section=".text",
                size=32,
                symbol_name="FirstSymbol",
            ),
            import_thunk,
            external,
        ]
        program = FakeProgram(functions)

        nodes = self.run_with_program(
            program,
            export_report.get_typed_function_nodes,
        )

        self.assertEqual(
            [node["id"] for node in nodes],
            ["fn:00401000", "fn:00402000"],
        )
        self.assertTrue(all(node["internal"] for node in nodes))
        self.assertTrue(all(not node["external"] for node in nodes))

    def test_function_call_edge_aggregates_unique_callsites(self):
        edge = build_function_call_edge(
            caller_id="fn:00401000",
            callee_id="fn:00402000",
            callsites=["00401020", "00401010", "00401020"],
            indirect=False,
        )
        self.assertEqual(edge["source"], "fn:00401000")
        self.assertEqual(edge["target"], "fn:00402000")
        self.assertEqual(edge["caller"], "fn:00401000")
        self.assertEqual(edge["callee"], "fn:00402000")
        self.assertEqual(edge["callsite"], "00401010")
        self.assertEqual(edge["callsites"], ["00401010", "00401020"])
        self.assertTrue(edge["direct"])
        self.assertFalse(edge["indirect"])
        self.assertFalse(edge["unresolved"])
        self.assertEqual(edge["occurrences"], 2)

    def test_unresolved_call_record_has_no_fake_callee(self):
        call = build_unresolved_function_call(
            caller_id="fn:00401000",
            callsite="00401030",
            indirect=True,
        )
        self.assertEqual(call["caller"], "fn:00401000")
        self.assertIsNone(call["callee"])
        self.assertFalse(call["direct"])
        self.assertTrue(call["indirect"])
        self.assertTrue(call["unresolved"])
        self.assertEqual(call["occurrences"], 1)

    def test_exporter_builds_direct_and_indirect_function_edges(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        callee = FakeFunction("00402000", "callee", size=16, section=".text")
        direct = FakeInstruction("00401010", call=True)
        indirect = FakeInstruction("00401020", call=True, computed=True)
        program = FakeProgram(
            [caller, callee],
            instruction_map={
                caller.body: [direct, indirect],
                callee.body: [],
            },
            reference_map={
                "00401010": [FakeReference("00402000", call=True)],
                "00401020": [FakeReference("00402000", call=True)],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        edges = [edge for edge in graph["edges"] if edge["type"] == "calls_function"]

        self.assertEqual(len(edges), 2)
        self.assertEqual(edges[0]["caller"], "fn:00401000")
        self.assertEqual(edges[0]["callee"], "fn:00402000")
        self.assertTrue(edges[0]["direct"])
        self.assertTrue(edges[1]["indirect"])
        self.assertEqual(graph["unresolved_calls"], [])

    def test_exporter_aggregates_repeated_function_calls(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        callee = FakeFunction("00402000", "callee", size=16, section=".text")
        first = FakeInstruction("00401010", call=True)
        second = FakeInstruction("00401020", call=True)
        program = FakeProgram(
            [caller, callee],
            instruction_map={caller.body: [second, first], callee.body: []},
            reference_map={
                "00401010": [FakeReference("00402000", call=True)],
                "00401020": [FakeReference("00402000", call=True)],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        edges = [edge for edge in graph["edges"] if edge["type"] == "calls_function"]

        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["callsites"], ["00401010", "00401020"])
        self.assertEqual(edges[0]["occurrences"], 2)

    def test_exporter_resolves_function_reference_inside_body(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        callee = FakeFunction(
            "00402000",
            "callee",
            size=16,
            section=".text",
            contained_addresses=["00402008"],
        )
        instruction = FakeInstruction("00401010", call=True)
        program = FakeProgram(
            [caller, callee],
            instruction_map={caller.body: [instruction], callee.body: []},
            reference_map={
                "00401010": [FakeReference("00402008", call=True)],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        edges = [edge for edge in graph["edges"] if edge["type"] == "calls_function"]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["callee"], "fn:00402000")

    def test_exporter_keeps_unresolved_call_separate(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        instruction = FakeInstruction("00401010", call=True, computed=True)
        program = FakeProgram(
            [caller],
            instruction_map={caller.body: [instruction]},
            reference_map={"00401010": []},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )

        call_edges = [edge for edge in graph["edges"] if edge["type"] in ("calls_function", "calls_api")]
        visibility_edges = [edge for edge in graph["edges"] if edge["type"] == "contains_indirect_call"]

        self.assertEqual(call_edges, [])
        self.assertEqual(len(visibility_edges), 1)
        self.assertEqual(len(graph["unresolved_calls"]), 1)
        self.assertTrue(graph["unresolved_calls"][0]["indirect"])
        self.assertIsNone(graph["unresolved_calls"][0]["callee"])
        self.assertEqual(
            graph["unresolved_calls"][0]["indicator"],
            "unresolved_call",
        )

    def test_api_id_and_node_preserve_normalized_and_original_names(self):
        self.assertEqual(build_api_id("CreateFile"), "api:createfile")
        node = build_api_node(
            "CreateFile",
            ["CreateFileW", "CreateFileA", "CreateFileW"],
        )
        self.assertEqual(node["id"], "api:createfile")
        self.assertEqual(node["normalized_name"], "CreateFile")
        self.assertEqual(
            node["original_names"],
            ["CreateFileA", "CreateFileW"],
        )

    def test_api_call_edge_contains_generic_and_domain_endpoints(self):
        edge = build_api_call_edge(
            caller_id="fn:00401000",
            api_id="api:createfile",
            callsites=["00401020", "00401010"],
            original_names=["CreateFileW"],
        )
        self.assertEqual(edge["source"], "fn:00401000")
        self.assertEqual(edge["target"], "api:createfile")
        self.assertEqual(edge["caller"], "fn:00401000")
        self.assertEqual(edge["api"], "api:createfile")
        self.assertEqual(edge["api_original_names"], ["CreateFileW"])
        self.assertEqual(edge["occurrences"], 2)

    def test_exporter_separates_direct_external_api_from_functions(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        external = FakeFunction(
            "EXTERNAL:00000001",
            "CreateFileW",
            external=True,
        )
        instruction = FakeInstruction("00401010", call=True)
        program = FakeProgram(
            [caller, external],
            instruction_map={caller.body: [instruction]},
            reference_map={
                "00401010": [FakeReference("EXTERNAL:00000001", call=True)],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        function_nodes = [node for node in graph["nodes"] if node["type"] == "FUNCTION"]
        api_nodes = [node for node in graph["nodes"] if node["type"] == "API"]
        api_edges = [edge for edge in graph["edges"] if edge["type"] == "calls_api"]

        self.assertEqual([node["id"] for node in function_nodes], ["fn:00401000"])
        self.assertEqual([node["id"] for node in api_nodes], ["api:createfile"])
        self.assertEqual(api_nodes[0]["original_names"], ["CreateFileW"])
        self.assertEqual(len(api_edges), 1)
        self.assertEqual(api_edges[0]["api"], "api:createfile")
        self.assertEqual(graph["unresolved_calls"], [])

    def test_exporter_resolves_import_thunk_to_api(self):
        external = FakeFunction(
            "EXTERNAL:00000001",
            "CreateFileW",
            external=True,
        )
        import_thunk = FakeFunction(
            "00403000",
            "thunk_CreateFileW",
            thunk=True,
            size=8,
            section=".text",
            thunk_target=external,
        )
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        instruction = FakeInstruction("00401010", call=True)
        program = FakeProgram(
            [caller, import_thunk, external],
            instruction_map={caller.body: [instruction], import_thunk.body: []},
            reference_map={
                "00401010": [FakeReference("00403000", call=True)],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        function_ids = [node["id"] for node in graph["nodes"] if node["type"] == "FUNCTION"]
        api_edges = [edge for edge in graph["edges"] if edge["type"] == "calls_api"]

        self.assertEqual(function_ids, ["fn:00401000"])
        self.assertEqual(len(api_edges), 1)
        self.assertEqual(api_edges[0]["api"], "api:createfile")

    def test_exporter_collapses_api_variants_but_preserves_original_names(self):
        caller = FakeFunction("00401000", "caller", size=64, section=".text")
        api_w = FakeFunction("EXTERNAL:1", "CreateFileW", external=True)
        api_a = FakeFunction("EXTERNAL:2", "CreateFileA", external=True)
        first = FakeInstruction("00401010", call=True)
        second = FakeInstruction("00401020", call=True)
        program = FakeProgram(
            [caller, api_w, api_a],
            instruction_map={caller.body: [first, second]},
            reference_map={
                "00401010": [FakeReference("EXTERNAL:1", call=True)],
                "00401020": [FakeReference("EXTERNAL:2", call=True)],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        api_nodes = [node for node in graph["nodes"] if node["type"] == "API"]
        api_edges = [edge for edge in graph["edges"] if edge["type"] == "calls_api"]

        self.assertEqual(len(api_nodes), 1)
        self.assertEqual(api_nodes[0]["id"], "api:createfile")
        self.assertEqual(
            api_nodes[0]["original_names"],
            ["CreateFileA", "CreateFileW"],
        )
        self.assertEqual(len(api_edges), 1)
        self.assertEqual(api_edges[0]["occurrences"], 2)
        self.assertEqual(
            api_edges[0]["api_original_names"],
            ["CreateFileA", "CreateFileW"],
        )

    def test_string_id_and_node_keep_raw_value_address_and_reference_count(self):
        self.assertEqual(build_string_id("00405000"), "str:00405000")
        node = build_string_node(
            address="00405000",
            value="https://example.test",
            raw_value='"https://example.test"',
            category=None,
            reference_count=3,
        )
        self.assertEqual(node["id"], "str:00405000")
        self.assertEqual(node["value"], "https://example.test")
        self.assertEqual(node["raw_value"], '"https://example.test"')
        self.assertIsNone(node["category"])
        self.assertEqual(node["reference_count"], 3)

    def test_string_reference_edge_keeps_sites_and_total_reference_count(self):
        edge = build_string_reference_edge(
            function_id="fn:00401000",
            string_id="str:00405000",
            reference_sites=["00401010", "00401020"],
            reference_count=3,
        )
        self.assertEqual(edge["source"], "fn:00401000")
        self.assertEqual(edge["target"], "str:00405000")
        self.assertEqual(edge["function"], "fn:00401000")
        self.assertEqual(edge["string"], "str:00405000")
        self.assertEqual(edge["reference_sites"], ["00401010", "00401020"])
        self.assertEqual(edge["reference_count"], 3)

    def test_exporter_collects_referenced_string_evidence_without_legacy_cap(self):
        caller = FakeFunction("00401000", "caller", size=64, section=".text")
        first = FakeInstruction("00401010")
        second = FakeInstruction("00401020")
        string_data = FakeData(
            "00405000",
            '"https://example.test/path"',
            data_type="TerminatedCString",
        )
        program = FakeProgram(
            [caller],
            instruction_map={caller.body: [first, second]},
            reference_map={
                "00401010": [FakeReference("00405000")],
                "00401020": [FakeReference("00405003")],
            },
            data_map={
                "00405000": string_data,
                "00405003": string_data,
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        string_nodes = [node for node in graph["nodes"] if node["type"] == "STRING"]
        string_edges = [edge for edge in graph["edges"] if edge["type"] == "references_string"]

        self.assertEqual(len(string_nodes), 1)
        self.assertEqual(string_nodes[0]["address"], "00405000")
        self.assertEqual(
            string_nodes[0]["value"],
            "https://example.test/path",
        )
        self.assertEqual(
            string_nodes[0]["raw_value"],
            '"https://example.test/path"',
        )
        self.assertEqual(string_nodes[0]["category"], "url")
        self.assertEqual(string_nodes[0]["categories"], ["url"])
        self.assertEqual(string_nodes[0]["reference_count"], 2)
        self.assertEqual(len(string_edges), 1)
        self.assertEqual(string_edges[0]["reference_count"], 2)
        self.assertEqual(
            string_edges[0]["reference_sites"],
            ["00401010", "00401020"],
        )

    def test_non_string_data_is_not_emitted_as_string_evidence(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        instruction = FakeInstruction("00401010")
        non_string = FakeData("00405000", "0x1234", data_type="DWORD")
        program = FakeProgram(
            [caller],
            instruction_map={caller.body: [instruction]},
            reference_map={"00401010": [FakeReference("00405000")]},
            data_map={"00405000": non_string},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        self.assertFalse(any(node["type"] == "STRING" for node in graph["nodes"]))

    def test_seeded_graph_is_deterministic(self):
        caller = FakeFunction("00401000", "caller", size=64, section=".text")
        callee = FakeFunction("00402000", "callee", size=16, section=".text")
        external = FakeFunction("EXTERNAL:1", "CreateFileW", external=True)
        call_internal = FakeInstruction("00401020", call=True)
        call_api = FakeInstruction("00401010", call=True)
        data_ref = FakeInstruction("00401030")
        string_data = FakeData("00405000", '"hello world"')
        program = FakeProgram(
            [external, callee, caller],
            instruction_map={
                caller.body: [data_ref, call_internal, call_api],
                callee.body: [],
            },
            reference_map={
                "00401010": [FakeReference("EXTERNAL:1", call=True)],
                "00401020": [FakeReference("00402000", call=True)],
                "00401030": [FakeReference("00405000")],
            },
            data_map={"00405000": string_data},
        )

        first = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        second = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        self.assertEqual(first, second)

    def test_seeded_script_marker_is_opt_in(self):
        self.assertFalse(export_report.parse_seeded_script_arg(["reports", "rules"]))
        self.assertTrue(export_report.parse_seeded_script_arg(["reports", "rules", "seeded=true"]))
        self.assertTrue(export_report.parse_seeded_script_arg(["reports", "rules", "SEEDED=TRUE"]))

    def test_contract_is_json_serializable_and_versioned_through_step_2_12(self):
        contract = build_typed_graph_model_contract()

        self.assertEqual(contract["model_version"], "0.12.0")
        self.assertEqual(TYPED_GRAPH_MODEL_VERSION, "0.12.0")
        self.assertEqual(contract["function_identity"]["id_prefix"], FUNCTION_ID_PREFIX)
        self.assertEqual(contract["api_node"]["id_prefix"], API_ID_PREFIX)
        self.assertEqual(contract["string_node"]["id_prefix"], STRING_ID_PREFIX)
        self.assertEqual(
            contract["string_category_node"]["id_prefix"],
            STRING_CATEGORY_ID_PREFIX,
        )
        self.assertEqual(
            contract["constant_node"]["id_prefix"],
            CONSTANT_ID_PREFIX,
        )
        self.assertEqual(
            contract["section_node"]["id_prefix"],
            SECTION_ID_PREFIX,
        )
        self.assertEqual(
            contract["function_call_edge"]["aggregation"],
            "caller+callee+call_kind",
        )
        self.assertEqual(
            contract["api_call_edge"]["aggregation"],
            "caller+api+call_kind",
        )
        self.assertEqual(
            contract["string_reference_edge"]["aggregation"],
            "function+string",
        )

        serialized = json.dumps(contract, sort_keys=True)
        self.assertIn('"calls_function"', serialized)
        self.assertIn('"calls_api"', serialized)
        self.assertIn('"references_string"', serialized)
        self.assertIn('"original_names"', serialized)
        self.assertIn('"raw_value"', serialized)
        self.assertIn('"has_string_category"', serialized)
        self.assertIn('"uses_constant"', serialized)
        self.assertIn('"belongs_to_section"', serialized)

    def test_string_categories_are_deterministic_and_preserve_multi_category(self):
        cases = {
            "https://example.test/a": ["url"],
            "connect 192.168.1.10": ["ip_address"],
            r"HKEY_CURRENT_USER\Software\Demo": ["registry_path"],
            "cmd.exe /c whoami": ["shell_command"],
            "powershell -enc AAAA": ["shell_command", "powershell"],
            r"C:\Windows\Temp\dropper.exe": ["file_path"],
            "User-Agent: Mozilla/5.0": ["user_agent"],
            "x64dbg.exe": ["debugger_name"],
            "VMware Virtual Platform": ["vm_indicator"],
        }

        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(
                    export_report.categorize_typed_string(value),
                    expected,
                )

    def test_string_category_node_and_edge_use_typed_endpoints(self):
        category_id = build_string_category_id("url")
        node = build_string_category_node("url")
        edge = build_string_category_edge(
            "str:00405000",
            category_id,
        )

        self.assertEqual(category_id, "strcat:url")
        self.assertEqual(node["type"], "STRING_CATEGORY")
        self.assertEqual(edge["type"], "has_string_category")
        self.assertEqual(edge["source"], "str:00405000")
        self.assertEqual(edge["target"], "strcat:url")

    def test_exporter_emits_string_category_nodes_and_edges(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        instruction = FakeInstruction("00401010")
        string_data = FakeData(
            "00405000",
            '"powershell https://example.test/payload.ps1"',
        )
        program = FakeProgram(
            [caller],
            instruction_map={caller.body: [instruction]},
            reference_map={
                "00401010": [FakeReference("00405000")],
            },
            data_map={"00405000": string_data},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )

        string_node = next(node for node in graph["nodes"] if node["type"] == "STRING")
        category_nodes = [node for node in graph["nodes"] if node["type"] == "STRING_CATEGORY"]
        category_edges = [edge for edge in graph["edges"] if edge["type"] == "has_string_category"]

        self.assertEqual(
            string_node["categories"],
            ["url", "shell_command", "powershell"],
        )
        self.assertEqual(
            [node["id"] for node in category_nodes],
            [
                "strcat:powershell",
                "strcat:shell_command",
                "strcat:url",
            ],
        )
        self.assertEqual(len(category_edges), 3)
        self.assertEqual(
            string_node["value"],
            "powershell https://example.test/payload.ps1",
        )

    def test_constant_decoders_cover_step_2_8_categories(self):
        self.assertEqual(
            export_report._classify_constant_for_api(
                "VirtualAllocEx",
                0x40,
            ),
            [
                {
                    "category": "memory_protection",
                    "symbolic_names": ["PAGE_EXECUTE_READWRITE"],
                }
            ],
        )

        allocation = export_report._classify_constant_for_api(
            "VirtualAllocEx",
            0x3000,
        )
        self.assertEqual(
            allocation,
            [
                {
                    "category": "allocation_flags",
                    "symbolic_names": ["MEM_COMMIT", "MEM_RESERVE"],
                }
            ],
        )

        self.assertEqual(
            export_report._classify_constant_for_api(
                "OpenProcess",
                0x1FFFFF,
            ),
            [
                {
                    "category": "process_rights",
                    "symbolic_names": ["PROCESS_ALL_ACCESS"],
                }
            ],
        )

        self.assertEqual(
            export_report._classify_constant_for_api(
                "RegOpenKeyEx",
                0x20019,
            ),
            [
                {
                    "category": "registry_flags",
                    "symbolic_names": ["KEY_READ"],
                }
            ],
        )

    def test_constant_node_and_edge_preserve_semantics_and_context(self):
        constant_id = build_constant_id(
            "memory_protection",
            0x40,
        )
        node = build_constant_node(
            category="memory_protection",
            value=0x40,
            symbolic_names=["PAGE_EXECUTE_READWRITE"],
            bit_lengths=[32],
        )
        edge = build_constant_use_edge(
            function_id="fn:00401000",
            constant_id=constant_id,
            use_sites=["00401008"],
            occurrences=1,
            context_apis=["VirtualAllocEx"],
        )

        self.assertEqual(
            constant_id,
            "const:memory_protection:0x40",
        )
        self.assertEqual(node["value"], 0x40)
        self.assertEqual(node["value_hex"], "0x40")
        self.assertEqual(
            node["symbolic_names"],
            ["PAGE_EXECUTE_READWRITE"],
        )
        self.assertEqual(edge["type"], "uses_constant")
        self.assertEqual(edge["source"], "fn:00401000")
        self.assertEqual(edge["target"], constant_id)
        self.assertEqual(
            edge["context_apis"],
            ["VirtualAllocEx"],
        )

    def test_exporter_collects_constants_from_api_setup_window(self):
        caller = FakeFunction("00401000", "caller", size=64, section=".text")
        external = FakeFunction(
            "EXTERNAL:1",
            "VirtualAllocEx",
            external=True,
        )

        alloc_flags = FakeInstruction(
            "00401008",
            op_objects=[[FakeScalar(0x3000)]],
        )
        protection = FakeInstruction(
            "0040100c",
            op_objects=[[FakeScalar(0x40)]],
        )
        call = FakeInstruction(
            "00401010",
            call=True,
        )

        program = FakeProgram(
            [caller, external],
            instruction_map={
                caller.body: [
                    alloc_flags,
                    protection,
                    call,
                ]
            },
            reference_map={
                "00401010": [
                    FakeReference(
                        "EXTERNAL:1",
                        call=True,
                    )
                ]
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )

        constants = [node for node in graph["nodes"] if node["type"] == "CONSTANT"]
        edges = [edge for edge in graph["edges"] if edge["type"] == "uses_constant"]

        self.assertEqual(
            [node["id"] for node in constants],
            [
                "const:allocation_flags:0x3000",
                "const:memory_protection:0x40",
            ],
        )
        self.assertEqual(len(edges), 2)
        self.assertTrue(all(edge["context_apis"] == ["VirtualAllocEx"] for edge in edges))

    def test_unrelated_scalar_is_not_emitted_as_constant(self):
        caller = FakeFunction("00401000", "caller", size=32, section=".text")
        instruction = FakeInstruction(
            "00401010",
            op_objects=[[FakeScalar(0x40)]],
        )
        program = FakeProgram(
            [caller],
            instruction_map={caller.body: [instruction]},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )

        self.assertFalse(any(node["type"] == "CONSTANT" for node in graph["nodes"]))

    def test_section_node_preserves_permissions_entropy_and_size(self):
        node = build_section_node(
            name=".text",
            start="00401000",
            end="00401fff",
            size=4096,
            read=True,
            write=False,
            execute=True,
            initialized=True,
            entropy=6.25,
            entropy_class="normal",
            entropy_sampled_bytes=4096,
            suspicious=False,
            reasons=[],
        )

        self.assertEqual(
            node["id"],
            "sec:00401000",
        )
        self.assertEqual(
            node["permissions"],
            "r-x",
        )
        self.assertTrue(node["read"])
        self.assertFalse(node["write"])
        self.assertTrue(node["execute"])
        self.assertEqual(node["entropy"], 6.25)
        self.assertEqual(node["size"], 4096)

    def test_function_section_edge_uses_typed_endpoints(self):
        edge = build_function_section_edge(
            "fn:00401010",
            "sec:00401000",
        )

        self.assertEqual(
            edge,
            {
                "type": "belongs_to_section",
                "source": "fn:00401010",
                "target": "sec:00401000",
                "function": "fn:00401010",
                "section": "sec:00401000",
            },
        )

    def test_exporter_links_functions_to_shared_section_node(self):
        first = FakeFunction(
            "00401010",
            "first",
            size=16,
            section=".text",
        )
        second = FakeFunction(
            "00401030",
            "second",
            size=16,
            section=".text",
        )
        program = FakeProgram(
            [second, first],
            instruction_map={
                first.body: [],
                second.body: [],
            },
        )

        section_info = [
            {
                "name": ".text",
                "start": "00401000",
                "end": "00401fff",
                "size": 4096,
                "read": True,
                "write": False,
                "execute": True,
                "initialized": True,
                "entropy": 6.5,
                "entropy_class": "normal",
                "entropy_sampled_bytes": 4096,
                "suspicious": False,
                "reasons": [],
            }
        ]

        graph = self.run_with_program(
            program,
            lambda: export_report.build_seeded_typed_graph(section_info=section_info),
        )

        section_nodes = [node for node in graph["nodes"] if node["type"] == "SECTION"]
        section_edges = [edge for edge in graph["edges"] if edge["type"] == "belongs_to_section"]

        self.assertEqual(len(section_nodes), 1)
        self.assertEqual(
            section_nodes[0]["id"],
            "sec:00401000",
        )
        self.assertEqual(len(section_edges), 2)
        self.assertEqual(
            [edge["source"] for edge in section_edges],
            ["fn:00401010", "fn:00401030"],
        )

    def test_call_visibility_indicator_preserves_indirect_unresolved_and_dispatch(self):
        node = build_call_visibility_indicator_node(
            function_id="fn:00401000",
            indirect_callsites=["00401020", "00401010"],
            resolved_indirect_callsites=["00401010"],
            unresolved_indirect_callsites=["00401020"],
            dynamic_dispatch_callsites=["00401010"],
            dynamic_dispatch_targets=[
                "fn:00402000",
                "api:createfile",
            ],
        )

        self.assertEqual(
            node["id"],
            "vis:call_visibility:fn:00401000",
        )
        self.assertEqual(node["type"], "VISIBILITY_INDICATOR")
        self.assertEqual(
            node["signals"],
            [
                "indirect_call",
                "unresolved_call",
                "dynamic_dispatch",
            ],
        )
        self.assertEqual(node["indirect_call_count"], 2)
        self.assertEqual(node["resolved_indirect_call_count"], 1)
        self.assertEqual(node["unresolved_indirect_call_count"], 1)
        self.assertEqual(node["dynamic_dispatch_count"], 1)
        self.assertEqual(
            node["dynamic_dispatch_recognition"],
            "computed_call_with_multiple_resolved_targets",
        )

        edge = build_indirect_call_indicator_edge(
            "fn:00401000",
            node["id"],
        )
        self.assertEqual(edge["type"], "contains_indirect_call")
        self.assertEqual(edge["source"], "fn:00401000")
        self.assertEqual(edge["target"], node["id"])

    def test_unresolved_call_is_explicit_indicator(self):
        call = build_unresolved_function_call(
            caller_id="fn:00401000",
            callsite="00401030",
            indirect=False,
        )

        self.assertEqual(call["indicator"], "unresolved_call")
        self.assertEqual(
            call["reason"],
            "no_resolved_function_or_api_target",
        )
        self.assertTrue(call["direct"])
        self.assertFalse(call["indirect"])
        self.assertTrue(call["unresolved"])

    def test_exporter_builds_visibility_indicator_for_indirect_calls(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=32,
            section=".text",
        )
        callee = FakeFunction(
            "00402000",
            "callee",
            size=16,
            section=".text",
        )
        indirect = FakeInstruction(
            "00401010",
            call=True,
            computed=True,
        )
        unresolved = FakeInstruction(
            "00401020",
            call=True,
            computed=True,
        )
        program = FakeProgram(
            [caller, callee],
            instruction_map={
                caller.body: [indirect, unresolved],
                callee.body: [],
            },
            reference_map={
                "00401010": [FakeReference("00402000", call=True)],
                "00401020": [],
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        visibility_nodes = [node for node in graph["nodes"] if node["type"] == "VISIBILITY_INDICATOR"]
        visibility_edges = [edge for edge in graph["edges"] if edge["type"] == "contains_indirect_call"]

        self.assertEqual(len(visibility_nodes), 1)
        self.assertEqual(len(visibility_edges), 1)
        self.assertEqual(
            visibility_nodes[0]["signals"],
            ["indirect_call", "unresolved_call"],
        )
        self.assertEqual(
            visibility_nodes[0]["indirect_callsites"],
            ["00401010", "00401020"],
        )
        self.assertEqual(
            visibility_nodes[0]["unresolved_indirect_callsites"],
            ["00401020"],
        )

    def test_dynamic_dispatch_requires_multiple_resolved_targets(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=32,
            section=".text",
        )
        first = FakeFunction(
            "00402000",
            "first",
            size=16,
            section=".text",
        )
        second = FakeFunction(
            "00403000",
            "second",
            size=16,
            section=".text",
        )
        indirect = FakeInstruction(
            "00401010",
            call=True,
            computed=True,
        )
        program = FakeProgram(
            [caller, first, second],
            instruction_map={
                caller.body: [indirect],
                first.body: [],
                second.body: [],
            },
            reference_map={
                "00401010": [
                    FakeReference("00402000", call=True),
                    FakeReference("00403000", call=True),
                ]
            },
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        visibility = next(node for node in graph["nodes"] if node["type"] == "VISIBILITY_INDICATOR")

        self.assertIn("dynamic_dispatch", visibility["signals"])
        self.assertEqual(visibility["dynamic_dispatch_count"], 1)
        self.assertEqual(
            visibility["dynamic_dispatch_callsites"],
            ["00401010"],
        )
        self.assertEqual(
            visibility["dynamic_dispatch_targets"],
            ["fn:00402000", "fn:00403000"],
        )

    def test_single_target_indirect_call_is_not_dynamic_dispatch(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=32,
            section=".text",
        )
        callee = FakeFunction(
            "00402000",
            "callee",
            size=16,
            section=".text",
        )
        indirect = FakeInstruction(
            "00401010",
            call=True,
            computed=True,
        )
        program = FakeProgram(
            [caller, callee],
            instruction_map={
                caller.body: [indirect],
                callee.body: [],
            },
            reference_map={"00401010": [FakeReference("00402000", call=True)]},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        visibility = next(node for node in graph["nodes"] if node["type"] == "VISIBILITY_INDICATOR")

        self.assertEqual(visibility["signals"], ["indirect_call"])
        self.assertEqual(visibility["dynamic_dispatch_count"], 0)
        self.assertIsNone(visibility["dynamic_dispatch_recognition"])

    def test_final_typed_graph_metadata_declares_complete_nonlegacy_graph(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=16,
            section=".text",
        )
        program = FakeProgram(
            [caller],
            instruction_map={caller.body: []},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        metadata = graph["metadata"]

        self.assertEqual(
            graph["model_version"],
            "0.12.0",
        )
        self.assertEqual(
            metadata["scope"],
            "complete_seeded_evidence_graph",
        )
        self.assertEqual(
            metadata["callgraph_source"],
            "ghidra_instruction_references",
        )
        self.assertFalse(metadata["legacy_callgraph_used"])
        self.assertFalse(metadata["legacy_callgraph_limits_applied"])
        self.assertFalse(metadata["truncated"])
        self.assertEqual(metadata["node_count"], len(graph["nodes"]))
        self.assertEqual(metadata["edge_count"], len(graph["edges"]))

    def test_final_graph_has_unique_nodes_and_valid_typed_edges(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=32,
            section=".text",
        )
        callee = FakeFunction(
            "00402000",
            "callee",
            size=16,
            section=".text",
        )
        call = FakeInstruction("00401010", call=True)
        program = FakeProgram(
            [caller, callee],
            instruction_map={
                caller.body: [call],
                callee.body: [],
            },
            reference_map={"00401010": [FakeReference("00402000", call=True)]},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        node_by_id = {node["id"]: node for node in graph["nodes"]}

        self.assertEqual(len(node_by_id), len(graph["nodes"]))

        for edge in graph["edges"]:
            self.assertIn(edge["source"], node_by_id)
            self.assertIn(edge["target"], node_by_id)
            validate_edge_endpoints(
                edge["type"],
                node_by_id[edge["source"]]["type"],
                node_by_id[edge["target"]]["type"],
            )

    def test_callsite_matches_instruction_that_emitted_call(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=32,
            section=".text",
        )
        callee = FakeFunction(
            "00402000",
            "callee",
            size=16,
            section=".text",
        )
        call = FakeInstruction("0040102a", call=True)
        program = FakeProgram(
            [caller, callee],
            instruction_map={
                caller.body: [call],
                callee.body: [],
            },
            reference_map={"0040102a": [FakeReference("00402000", call=True)]},
        )

        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        edge = next(edge for edge in graph["edges"] if edge["type"] == "calls_function")

        self.assertEqual(edge["callsite"], "0040102a")
        self.assertEqual(edge["callsites"], ["0040102a"])

    def test_complete_graph_is_not_limited_by_legacy_node_or_edge_caps(self):
        function_count = 300
        functions = [
            FakeFunction(
                "{:08x}".format(0x401000 + index * 0x10),
                "f{}".format(index),
                size=8,
                section=".text",
            )
            for index in range(function_count)
        ]

        instruction_map = {}
        reference_map = {}
        for index, function in enumerate(functions):
            instructions = []
            for offset in (1, 2, 3):
                call_address = "{:08x}".format(0x700000 + index * 0x10 + offset)
                instruction = FakeInstruction(call_address, call=True)
                instructions.append(instruction)
                target = functions[(index + offset) % function_count]
                reference_map[call_address] = [
                    FakeReference(
                        str(target.getEntryPoint()),
                        call=True,
                    )
                ]
            instruction_map[function.body] = instructions

        program = FakeProgram(
            functions,
            instruction_map=instruction_map,
            reference_map=reference_map,
        )
        graph = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )

        function_nodes = [node for node in graph["nodes"] if node["type"] == "FUNCTION"]
        call_edges = [edge for edge in graph["edges"] if edge["type"] == "calls_function"]

        self.assertEqual(len(function_nodes), 300)
        self.assertEqual(len(call_edges), 900)
        self.assertGreater(len(function_nodes), 250)
        self.assertGreater(len(call_edges), 800)
        self.assertFalse(graph["metadata"]["truncated"])
        self.assertFalse(graph["metadata"]["legacy_callgraph_limits_applied"])

    def test_seeded_graph_final_output_is_deterministic(self):
        caller = FakeFunction(
            "00401000",
            "caller",
            size=32,
            section=".text",
        )
        callee = FakeFunction(
            "00402000",
            "callee",
            size=16,
            section=".text",
        )
        call = FakeInstruction(
            "00401010",
            call=True,
            computed=True,
        )
        program = FakeProgram(
            [caller, callee],
            instruction_map={
                caller.body: [call],
                callee.body: [],
            },
            reference_map={"00401010": [FakeReference("00402000", call=True)]},
        )

        first = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )
        second = self.run_with_program(
            program,
            export_report.build_seeded_typed_graph,
        )

        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_legacy_report_attachment_omits_typed_graph_when_seeded_disabled(self):
        report = {"sample": {"name": "legacy.exe"}}
        typed_graph = {
            "model_version": "0.12.0",
            "nodes": [],
            "edges": [],
            "unresolved_calls": [],
        }

        returned = export_report.attach_seeded_typed_graph(
            report,
            False,
            typed_graph,
        )

        self.assertIs(returned, report)
        self.assertNotIn("typed_graph", report)

    def test_seeded_report_attachment_adds_complete_typed_graph(self):
        report = {"sample": {"name": "seeded.exe"}}
        typed_graph = {
            "model_version": "0.12.0",
            "metadata": {
                "scope": "complete_seeded_evidence_graph",
            },
            "nodes": [],
            "edges": [],
            "unresolved_calls": [],
        }

        export_report.attach_seeded_typed_graph(
            report,
            True,
            typed_graph,
        )

        self.assertIs(report["typed_graph"], typed_graph)

    def test_final_contract_covers_visibility_and_complete_graph_metadata(self):
        contract = build_typed_graph_model_contract()

        self.assertEqual(contract["model_version"], "0.12.0")
        self.assertEqual(
            contract["visibility_indicator_node"]["id_prefix"],
            VISIBILITY_ID_PREFIX,
        )
        self.assertEqual(
            contract["indirect_call_indicator_edge"]["type"],
            "contains_indirect_call",
        )
        self.assertEqual(
            contract["graph_contract"]["scope"],
            "complete_seeded_evidence_graph",
        )
        self.assertFalse(contract["graph_contract"]["legacy_callgraph_used"])
        self.assertFalse(contract["graph_contract"]["legacy_callgraph_limits_applied"])


if __name__ == "__main__":
    unittest.main()
