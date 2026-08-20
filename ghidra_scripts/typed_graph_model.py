"""Formal contract for the Seeded Typed Evidence Graph.

This module intentionally contains no Ghidra API calls. Step 2.1 establishes
the graph vocabulary and endpoint invariants, Step 2.2 adds stable function
identities, and Step 2.3 defines the first concrete typed node shape.
"""

from enum import Enum


TYPED_GRAPH_MODEL_VERSION = "0.3.0"
FUNCTION_ID_PREFIX = "fn:"


class NodeType(str, Enum):
    """Node kinds allowed in the initial typed evidence graph."""

    FUNCTION = "FUNCTION"
    API = "API"
    STRING = "STRING"
    STRING_CATEGORY = "STRING_CATEGORY"
    CONSTANT = "CONSTANT"
    SECTION = "SECTION"
    VISIBILITY_INDICATOR = "VISIBILITY_INDICATOR"


class EdgeType(str, Enum):
    """Relationship kinds allowed in the initial typed evidence graph."""

    CALLS_FUNCTION = "calls_function"
    CALLS_API = "calls_api"
    REFERENCES_STRING = "references_string"
    HAS_STRING_CATEGORY = "has_string_category"
    USES_CONSTANT = "uses_constant"
    BELONGS_TO_SECTION = "belongs_to_section"
    CONTAINS_INDIRECT_CALL = "contains_indirect_call"


NODE_TYPES = tuple(NodeType)
EDGE_TYPES = tuple(EdgeType)


# Each edge kind has an explicit source/target type contract.
#
# Keeping these relationships centralized prevents later extraction steps
# from silently producing structurally invalid graph edges.
EDGE_ENDPOINT_TYPES = {
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


def parse_node_type(value):
    """Return a NodeType for value or raise ValueError for unknown values."""

    return NodeType(value)


def parse_edge_type(value):
    """Return an EdgeType for value or raise ValueError for unknown values."""

    return EdgeType(value)


def validate_edge_endpoints(edge_type, source_type, target_type):
    """Validate the source/target node kinds for an edge kind.

    The function accepts enum members or their serialized string values.

    A ValueError is raised when the relationship does not belong to the
    Typed Evidence Graph model.
    """

    parsed_edge_type = parse_edge_type(edge_type)
    parsed_source_type = parse_node_type(source_type)
    parsed_target_type = parse_node_type(target_type)

    expected_source, expected_target = EDGE_ENDPOINT_TYPES[parsed_edge_type]

    if parsed_source_type != expected_source or parsed_target_type != expected_target:
        raise ValueError(
            "invalid endpoints for {}: expected {} -> {}, got {} -> {}".format(
                parsed_edge_type.value,
                expected_source.value,
                expected_target.value,
                parsed_source_type.value,
                parsed_target_type.value,
            )
        )


def normalize_entry_address(entry_address):
    """Return the canonical text used by stable function identities.

    Ghidra entry addresses are currently exported through ``str(address)``.
    The stable identity contract preserves that address text while removing
    surrounding whitespace and normalizing hexadecimal letter case.
    """

    if entry_address is None:
        raise ValueError("function entry address cannot be None")

    address_text = str(entry_address).strip()

    if not address_text:
        raise ValueError("function entry address cannot be empty")

    if address_text.lower().startswith(FUNCTION_ID_PREFIX):
        raise ValueError("function entry address must not include the function ID prefix")

    if address_text.lower().startswith("0x"):
        address_text = address_text[2:]

    if not address_text:
        raise ValueError("function entry address cannot be empty")

    return address_text.lower()


def build_stable_function_id(entry_address):
    """Build the stable function ID from its canonical entry address."""

    return FUNCTION_ID_PREFIX + normalize_entry_address(entry_address)


def build_function_identity(
    entry_address,
    ghidra_name,
    symbol_name=None,
):
    """Build the metadata contract for a FUNCTION node identity.

    The stable ID is derived only from the entry address. Ghidra names and
    optional symbol names remain descriptive metadata and never participate
    in identity generation.
    """

    normalized_entry = normalize_entry_address(entry_address)

    if ghidra_name is None:
        raise ValueError("Ghidra function name cannot be None")

    ghidra_name_text = str(ghidra_name)
    symbol_name_text = None if symbol_name is None else str(symbol_name)

    return {
        "id": FUNCTION_ID_PREFIX + normalized_entry,
        "name": ghidra_name_text,
        "entry": normalized_entry,
        "symbol_name": symbol_name_text,
    }


def build_function_node(
    entry_address,
    ghidra_name,
    external,
    thunk,
    section=None,
    size=None,
    symbol_name=None,
):
    """Build a concrete typed FUNCTION node.

    ``address`` is the canonical function entry address. ``external`` and
    ``internal`` are deliberately both serialized so downstream consumers do
    not need to infer the classification. Section and size may be ``None``
    when Ghidra cannot provide them, which is common for external functions.
    """

    identity = build_function_identity(
        entry_address,
        ghidra_name,
        symbol_name=symbol_name,
    )

    if not isinstance(external, bool):
        raise ValueError("function external flag must be a boolean")

    if not isinstance(thunk, bool):
        raise ValueError("function thunk flag must be a boolean")

    if section is None:
        section_name = None
    else:
        section_name = str(section).strip()
        if not section_name:
            section_name = None

    if size is not None:
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError("function size must be an integer or None")
        if size < 0:
            raise ValueError("function size cannot be negative")

    return {
        "id": identity["id"],
        "type": NodeType.FUNCTION.value,
        "address": identity["entry"],
        "name": identity["name"],
        "symbol_name": identity["symbol_name"],
        "external": external,
        "internal": not external,
        "thunk": thunk,
        "section": section_name,
        "size": size,
    }


def build_typed_graph_model_contract():
    """Return the serializable graph vocabulary and identity invariants."""

    return {
        "model_version": TYPED_GRAPH_MODEL_VERSION,
        "node_types": [node_type.value for node_type in NODE_TYPES],
        "edge_types": [edge_type.value for edge_type in EDGE_TYPES],
        "edge_endpoints": {
            edge_type.value: {
                "source": source_type.value,
                "target": target_type.value,
            }
            for edge_type, (
                source_type,
                target_type,
            ) in EDGE_ENDPOINT_TYPES.items()
        },
        "function_identity": {
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
        "function_node": {
            "type": NodeType.FUNCTION.value,
            "primary_key": "id",
            "address_semantics": "entry_address",
            "fields": [
                "id",
                "type",
                "address",
                "name",
                "symbol_name",
                "external",
                "internal",
                "thunk",
                "section",
                "size",
            ],
            "nullable_fields": [
                "symbol_name",
                "section",
                "size",
            ],
        },
    }
