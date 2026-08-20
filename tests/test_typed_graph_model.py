import json
import unittest

from ghidra_scripts import export_report
from ghidra_scripts.typed_graph_model import (
    EDGE_ENDPOINT_TYPES,
    EDGE_TYPES,
    FUNCTION_ID_PREFIX,
    NODE_TYPES,
    EdgeType,
    NodeType,
    TYPED_GRAPH_MODEL_VERSION,
    build_function_identity,
    build_function_node,
    build_stable_function_id,
    build_typed_graph_model_contract,
    normalize_entry_address,
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
    ):
        self.entry = FakeAddress(entry)
        self.name = name
        self.external = external
        self.thunk = thunk
        self.section = section
        self.size = size
        self.symbol_name = symbol_name

    def getEntryPoint(self):
        return self.entry

    def getName(self):
        return self.name

    def isExternal(self):
        return self.external

    def isThunk(self):
        return self.thunk

    def getSymbol(self):
        if self.symbol_name is None:
            return None
        return FakeSymbol(self.symbol_name)

    def getBody(self):
        if self.size is None:
            return None
        return FakeBody(self.size)


class FakeMemoryBlock:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class FakeMemory:
    def __init__(self, functions):
        self.sections = {
            str(function.getEntryPoint()): function.section
            for function in functions
        }

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


class FakeProgram:
    def __init__(self, functions):
        self.function_manager = FakeFunctionManager(functions)
        self.memory = FakeMemory(functions)

    def getFunctionManager(self):
        return self.function_manager

    def getMemory(self):
        return self.memory


class TypedGraphModelTests(unittest.TestCase):
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
        self.assertEqual(
            set(EDGE_ENDPOINT_TYPES),
            set(EDGE_TYPES),
        )

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

        self.assertEqual(
            EDGE_ENDPOINT_TYPES,
            expected,
        )

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

        self.assertEqual(
            original["id"],
            renamed["id"],
        )

        self.assertNotEqual(
            original["name"],
            renamed["name"],
        )

    def test_same_name_at_different_entries_has_different_stable_ids(self):
        first = build_function_identity(
            "00401000",
            "handler",
        )

        second = build_function_identity(
            "00402000",
            "handler",
        )

        self.assertNotEqual(
            first["id"],
            second["id"],
        )

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

        self.assertIsNone(
            identity["symbol_name"]
        )

    def test_invalid_function_entry_addresses_are_rejected(self):
        for value in (
            None,
            "",
            "   ",
            "fn:00401000",
        ):
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

    def test_external_function_node_is_classified_explicitly(self):
        node = build_function_node(
            entry_address="EXTERNAL:00000001",
            ghidra_name="CreateFileW",
            external=True,
            thunk=True,
        )

        self.assertTrue(node["external"])
        self.assertFalse(node["internal"])
        self.assertTrue(node["thunk"])
        self.assertIsNone(node["section"])
        self.assertIsNone(node["size"])

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

    def test_exporter_collects_all_function_nodes_deterministically(self):
        functions = [
            FakeFunction(
                "00402000",
                "second",
                section=".text",
                size=64,
                symbol_name="SecondSymbol",
            ),
            FakeFunction(
                "00401000",
                "first",
                section=".text",
                size=32,
                symbol_name="FirstSymbol",
            ),
            FakeFunction(
                "EXTERNAL:00000001",
                "CreateFileW",
                external=True,
                thunk=True,
            ),
        ]

        previous_program = getattr(export_report, "currentProgram", None)
        had_program = hasattr(export_report, "currentProgram")
        export_report.currentProgram = FakeProgram(functions)

        try:
            nodes = export_report.get_typed_function_nodes()
        finally:
            if had_program:
                export_report.currentProgram = previous_program
            else:
                delattr(export_report, "currentProgram")

        self.assertEqual(
            [node["id"] for node in nodes],
            [
                "fn:00401000",
                "fn:00402000",
                "fn:external:00000001",
            ],
        )
        self.assertEqual(nodes[0]["section"], ".text")
        self.assertEqual(nodes[0]["size"], 32)
        self.assertEqual(nodes[0]["symbol_name"], "FirstSymbol")
        self.assertTrue(nodes[2]["external"])
        self.assertFalse(nodes[2]["internal"])

    def test_seeded_script_marker_is_opt_in(self):
        self.assertFalse(
            export_report.parse_seeded_script_arg(
                ["reports", "rules"]
            )
        )
        self.assertTrue(
            export_report.parse_seeded_script_arg(
                ["reports", "rules", "seeded=true"]
            )
        )
        self.assertTrue(
            export_report.parse_seeded_script_arg(
                ["reports", "rules", "SEEDED=TRUE"]
            )
        )

    def test_contract_is_json_serializable_and_versioned(self):
        contract = build_typed_graph_model_contract()

        self.assertEqual(
            contract["model_version"],
            TYPED_GRAPH_MODEL_VERSION,
        )

        self.assertEqual(
            contract["function_identity"],
            {
                "primary_key": "id",
                "id_prefix": FUNCTION_ID_PREFIX,
                "id_source": "entry_address",
                "fields": [
                    "id",
                    "name",
                    "entry",
                    "symbol_name",
                ],
            },
        )

        self.assertEqual(
            contract["function_node"]["type"],
            "FUNCTION",
        )
        self.assertEqual(
            contract["function_node"]["address_semantics"],
            "entry_address",
        )

        serialized = json.dumps(
            contract,
            sort_keys=True,
        )

        self.assertIn(
            '"FUNCTION"',
            serialized,
        )

        self.assertIn(
            '"calls_function"',
            serialized,
        )

        self.assertIn(
            '"entry_address"',
            serialized,
        )


if __name__ == "__main__":
    unittest.main()