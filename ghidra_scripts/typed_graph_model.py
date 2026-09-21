"""Formal contract for the Seeded Typed Evidence Graph.

This module intentionally contains no Ghidra API calls. Steps 2.1-2.9 define
the typed evidence vocabulary and populate FUNCTION, API, STRING,
STRING_CATEGORY, CONSTANT, and SECTION evidence. Steps 2.10-2.12 finalize
indirect-call visibility evidence and the complete Step 2 graph contract.
"""

from enum import Enum



TYPED_GRAPH_MODEL_VERSION = "0.12.0"
FUNCTION_ID_PREFIX = "fn:"
API_ID_PREFIX = "api:"
STRING_ID_PREFIX = "str:"
STRING_CATEGORY_ID_PREFIX = "strcat:"
CONSTANT_ID_PREFIX = "const:"
SECTION_ID_PREFIX = "sec:"
VISIBILITY_ID_PREFIX = "vis:"


class NodeType(str, Enum):
    """Node kinds allowed in the typed evidence graph."""

    FUNCTION = "FUNCTION"
    API = "API"
    STRING = "STRING"
    STRING_CATEGORY = "STRING_CATEGORY"
    CONSTANT = "CONSTANT"
    SECTION = "SECTION"
    VISIBILITY_INDICATOR = "VISIBILITY_INDICATOR"


class EdgeType(str, Enum):
    """Relationship kinds allowed in the typed evidence graph."""

    CALLS_FUNCTION = "calls_function"
    CALLS_API = "calls_api"
    REFERENCES_STRING = "references_string"
    HAS_STRING_CATEGORY = "has_string_category"
    USES_CONSTANT = "uses_constant"
    BELONGS_TO_SECTION = "belongs_to_section"
    CONTAINS_INDIRECT_CALL = "contains_indirect_call"


NODE_TYPES = tuple(NodeType)
EDGE_TYPES = tuple(EdgeType)


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
    """Validate the source/target node kinds for an edge kind."""

    parsed_edge_type = parse_edge_type(edge_type)
    parsed_source_type = parse_node_type(source_type)
    parsed_target_type = parse_node_type(target_type)

    expected_source, expected_target = EDGE_ENDPOINT_TYPES[parsed_edge_type]

    if (
        parsed_source_type != expected_source
        or parsed_target_type != expected_target
    ):
        raise ValueError(
            "invalid endpoints for {}: expected {} -> {}, got {} -> {}".format(
                parsed_edge_type.value,
                expected_source.value,
                expected_target.value,
                parsed_source_type.value,
                parsed_target_type.value,
            )
        )


def _normalize_nonempty_text(value, field_name):
    if value is None:
        raise ValueError("{} cannot be None".format(field_name))

    text = str(value).strip()
    if not text:
        raise ValueError("{} cannot be empty".format(field_name))

    return text


def normalize_entry_address(entry_address):
    """Return the canonical text used by stable function identities."""

    address_text = _normalize_nonempty_text(
        entry_address,
        "function entry address",
    )

    if address_text.lower().startswith(FUNCTION_ID_PREFIX):
        raise ValueError(
            "function entry address must not include the function ID prefix"
        )

    if address_text.lower().startswith("0x"):
        address_text = address_text[2:]

    if not address_text:
        raise ValueError("function entry address cannot be empty")

    return address_text.lower()


def normalize_graph_address(address):
    """Canonicalize a generic graph address without assigning a node type."""

    address_text = _normalize_nonempty_text(address, "graph address")

    if address_text.lower().startswith("0x"):
        address_text = address_text[2:]

    if not address_text:
        raise ValueError("graph address cannot be empty")

    return address_text.lower()


def build_stable_function_id(entry_address):
    """Build the stable FUNCTION ID from its canonical entry address."""

    return FUNCTION_ID_PREFIX + normalize_entry_address(entry_address)


def validate_stable_function_id(function_id):
    """Validate and return a canonical stable FUNCTION ID."""

    function_id_text = _normalize_nonempty_text(
        function_id,
        "function id",
    ).lower()

    if not function_id_text.startswith(FUNCTION_ID_PREFIX):
        raise ValueError("function id must start with 'fn:'")

    address_text = function_id_text[len(FUNCTION_ID_PREFIX) :]
    if not address_text:
        raise ValueError("function id must contain an address")

    return FUNCTION_ID_PREFIX + normalize_entry_address(address_text)


def build_function_identity(
    entry_address,
    ghidra_name,
    symbol_name=None,
):
    """Build the metadata contract for a FUNCTION node identity."""

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
    """Build a concrete typed FUNCTION node."""

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


def _normalize_api_name(api_name):
    return _normalize_nonempty_text(api_name, "API name")


def build_api_id(normalized_name):
    """Build a deterministic API node ID from the normalized API name."""

    return API_ID_PREFIX + _normalize_api_name(normalized_name).lower()


def validate_api_id(api_id):
    """Validate and canonicalize an API node ID."""

    api_id_text = _normalize_nonempty_text(api_id, "API id")
    if not api_id_text.lower().startswith(API_ID_PREFIX):
        raise ValueError("API id must start with 'api:'")

    name = api_id_text[len(API_ID_PREFIX) :]
    if not name:
        raise ValueError("API id must contain a name")

    return API_ID_PREFIX + name.lower()


def build_api_node(normalized_name, original_names):
    """Build a typed API node while preserving all observed raw variants."""

    normalized = _normalize_api_name(normalized_name)
    originals = sorted(
        set(_normalize_api_name(name) for name in original_names)
    )

    if not originals:
        raise ValueError("API node requires at least one original name")

    return {
        "id": build_api_id(normalized),
        "type": NodeType.API.value,
        "name": normalized,
        "normalized_name": normalized,
        "original_names": originals,
    }


def build_string_id(address):
    """Build a stable STRING node ID from the defined-data address."""

    return STRING_ID_PREFIX + normalize_graph_address(address)


def validate_string_id(string_id):
    """Validate and canonicalize a STRING node ID."""

    string_id_text = _normalize_nonempty_text(string_id, "string id")
    if not string_id_text.lower().startswith(STRING_ID_PREFIX):
        raise ValueError("string id must start with 'str:'")

    address = string_id_text[len(STRING_ID_PREFIX) :]
    if not address:
        raise ValueError("string id must contain an address")

    return STRING_ID_PREFIX + normalize_graph_address(address)


def _normalize_string_categories(category=None, categories=None):
    values = []

    if categories is not None:
        for item in categories:
            text = _normalize_nonempty_text(item, "string category").lower()
            if text not in values:
                values.append(text)

    if category is not None:
        text = _normalize_nonempty_text(category, "string category").lower()
        if text not in values:
            values.insert(0, text)

    return values


def build_string_node(
    address,
    value,
    raw_value,
    reference_count,
    category=None,
    categories=None,
):
    """Build a referenced STRING evidence node.

    ``value`` and ``raw_value`` always preserve the original string evidence.
    Step 2.7 adds deterministic semantic categories without replacing either
    original representation.
    """

    normalized_address = normalize_graph_address(address)

    if value is None:
        raise ValueError("string value cannot be None")
    if raw_value is None:
        raise ValueError("string raw value cannot be None")

    if (
        isinstance(reference_count, bool)
        or not isinstance(reference_count, int)
        or reference_count < 0
    ):
        raise ValueError("string reference_count must be a non-negative integer")

    normalized_categories = _normalize_string_categories(
        category=category,
        categories=categories,
    )

    primary_category = (
        normalized_categories[0]
        if normalized_categories
        else None
    )

    return {
        "id": STRING_ID_PREFIX + normalized_address,
        "type": NodeType.STRING.value,
        "address": normalized_address,
        "value": str(value),
        "raw_value": str(raw_value),
        "category": primary_category,
        "categories": normalized_categories,
        "reference_count": reference_count,
    }


def build_string_category_id(category):
    """Build the deterministic ID for a STRING_CATEGORY node."""

    normalized = _normalize_nonempty_text(
        category,
        "string category",
    ).lower()

    return STRING_CATEGORY_ID_PREFIX + normalized


def validate_string_category_id(category_id):
    """Validate and canonicalize a STRING_CATEGORY ID."""

    text = _normalize_nonempty_text(
        category_id,
        "string category id",
    ).lower()

    if not text.startswith(STRING_CATEGORY_ID_PREFIX):
        raise ValueError("string category id must start with 'strcat:'")

    category = text[len(STRING_CATEGORY_ID_PREFIX) :]
    if not category:
        raise ValueError("string category id must contain a category")

    return STRING_CATEGORY_ID_PREFIX + category


def build_string_category_node(category):
    """Build a typed STRING_CATEGORY node."""

    normalized = _normalize_nonempty_text(
        category,
        "string category",
    ).lower()

    return {
        "id": build_string_category_id(normalized),
        "type": NodeType.STRING_CATEGORY.value,
        "name": normalized,
        "category": normalized,
    }


def build_string_category_edge(string_id, category_id):
    """Build STRING -> STRING_CATEGORY evidence."""

    string = validate_string_id(string_id)
    category = validate_string_category_id(category_id)

    return {
        "type": EdgeType.HAS_STRING_CATEGORY.value,
        "source": string,
        "target": category,
        "string": string,
        "category": category,
    }


def _normalize_callsites(callsites):
    if callsites is None:
        raise ValueError("callsites cannot be None")

    normalized = sorted(
        set(normalize_graph_address(callsite) for callsite in callsites)
    )

    if not normalized:
        raise ValueError("at least one callsite is required")

    return normalized


def build_function_call_edge(
    caller_id,
    callee_id,
    callsites,
    indirect=False,
):
    """Build an aggregated resolved FUNCTION -> FUNCTION call edge."""

    if not isinstance(indirect, bool):
        raise ValueError("indirect flag must be a boolean")

    caller = validate_stable_function_id(caller_id)
    callee = validate_stable_function_id(callee_id)
    normalized_callsites = _normalize_callsites(callsites)

    return {
        "type": EdgeType.CALLS_FUNCTION.value,
        "source": caller,
        "target": callee,
        "caller": caller,
        "callee": callee,
        "callsite": normalized_callsites[0],
        "callsites": normalized_callsites,
        "direct": not indirect,
        "indirect": indirect,
        "unresolved": False,
        "occurrences": len(normalized_callsites),
    }


def build_api_call_edge(
    caller_id,
    api_id,
    callsites,
    original_names,
    indirect=False,
):
    """Build an aggregated FUNCTION -> API call edge."""

    if not isinstance(indirect, bool):
        raise ValueError("indirect flag must be a boolean")

    caller = validate_stable_function_id(caller_id)
    api = validate_api_id(api_id)
    normalized_callsites = _normalize_callsites(callsites)
    originals = sorted(
        set(_normalize_api_name(name) for name in original_names)
    )

    if not originals:
        raise ValueError("API call edge requires at least one original API name")

    return {
        "type": EdgeType.CALLS_API.value,
        "source": caller,
        "target": api,
        "caller": caller,
        "api": api,
        "api_original_names": originals,
        "callsite": normalized_callsites[0],
        "callsites": normalized_callsites,
        "direct": not indirect,
        "indirect": indirect,
        "unresolved": False,
        "occurrences": len(normalized_callsites),
    }


def build_string_reference_edge(
    function_id,
    string_id,
    reference_sites,
    reference_count,
):
    """Build an aggregated FUNCTION -> STRING evidence edge."""

    function = validate_stable_function_id(function_id)
    string = validate_string_id(string_id)
    sites = _normalize_callsites(reference_sites)

    if (
        isinstance(reference_count, bool)
        or not isinstance(reference_count, int)
        or reference_count <= 0
    ):
        raise ValueError("string reference_count must be a positive integer")

    if reference_count < len(sites):
        raise ValueError(
            "string reference_count cannot be smaller than unique reference sites"
        )

    return {
        "type": EdgeType.REFERENCES_STRING.value,
        "source": function,
        "target": string,
        "function": function,
        "string": string,
        "reference_sites": sites,
        "reference_count": reference_count,
    }


def _normalize_constant_category(category):
    normalized = _normalize_nonempty_text(
        category,
        "constant category",
    ).lower()

    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789_" for ch in normalized):
        raise ValueError(
            "constant category must contain only lowercase letters, digits, and underscores"
        )

    return normalized


def _validate_constant_value(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("constant value must be an integer")

    if value < 0:
        raise ValueError("constant value must be non-negative")

    return value


def build_constant_id(category, value):
    """Build a deterministic semantic CONSTANT ID."""

    normalized_category = _normalize_constant_category(category)
    normalized_value = _validate_constant_value(value)

    return "{}{}:0x{:x}".format(
        CONSTANT_ID_PREFIX,
        normalized_category,
        normalized_value,
    )


def validate_constant_id(constant_id):
    """Validate a CONSTANT ID."""

    text = _normalize_nonempty_text(
        constant_id,
        "constant id",
    ).lower()

    if not text.startswith(CONSTANT_ID_PREFIX):
        raise ValueError("constant id must start with 'const:'")

    remainder = text[len(CONSTANT_ID_PREFIX) :]
    parts = remainder.split(":", 1)

    if len(parts) != 2:
        raise ValueError("constant id must contain category and hexadecimal value")

    _normalize_constant_category(parts[0])

    value_text = parts[1]
    if not value_text.startswith("0x"):
        raise ValueError("constant id value must be hexadecimal")

    try:
        value = int(value_text, 16)
    except ValueError as exc:
        raise ValueError("constant id contains invalid hexadecimal value") from exc

    return build_constant_id(parts[0], value)


def build_constant_node(
    category,
    value,
    symbolic_names,
    bit_lengths=None,
):
    """Build a relevant semantic CONSTANT node."""

    normalized_category = _normalize_constant_category(category)
    normalized_value = _validate_constant_value(value)

    names = sorted(
        set(
            _normalize_nonempty_text(name, "constant symbolic name")
            for name in symbolic_names
        )
    )

    if not names:
        raise ValueError("constant node requires at least one symbolic name")

    lengths = []
    for bit_length in bit_lengths or []:
        if isinstance(bit_length, bool) or not isinstance(bit_length, int):
            raise ValueError("constant bit length must be an integer")
        if bit_length < 0 or bit_length > 64:
            raise ValueError("constant bit length must be between 0 and 64")
        if bit_length not in lengths:
            lengths.append(bit_length)

    lengths.sort()

    return {
        "id": build_constant_id(
            normalized_category,
            normalized_value,
        ),
        "type": NodeType.CONSTANT.value,
        "category": normalized_category,
        "value": normalized_value,
        "value_hex": "0x{:x}".format(normalized_value),
        "symbolic_names": names,
        "bit_lengths": lengths,
    }


def build_constant_use_edge(
    function_id,
    constant_id,
    use_sites,
    occurrences,
    context_apis,
):
    """Build FUNCTION -> CONSTANT evidence."""

    function = validate_stable_function_id(function_id)
    constant = validate_constant_id(constant_id)
    sites = _normalize_callsites(use_sites)

    if (
        isinstance(occurrences, bool)
        or not isinstance(occurrences, int)
        or occurrences <= 0
    ):
        raise ValueError("constant occurrences must be a positive integer")

    if occurrences < len(sites):
        raise ValueError(
            "constant occurrences cannot be smaller than unique use sites"
        )

    apis = sorted(
        set(
            _normalize_nonempty_text(api, "constant context API")
            for api in context_apis
        )
    )

    if not apis:
        raise ValueError("constant use edge requires at least one context API")

    return {
        "type": EdgeType.USES_CONSTANT.value,
        "source": function,
        "target": constant,
        "function": function,
        "constant": constant,
        "use_sites": sites,
        "occurrences": occurrences,
        "context_apis": apis,
    }


def build_section_id(start_address):
    """Build a stable SECTION node ID from the section start address."""

    return SECTION_ID_PREFIX + normalize_graph_address(start_address)


def validate_section_id(section_id):
    """Validate and canonicalize a SECTION ID."""

    text = _normalize_nonempty_text(
        section_id,
        "section id",
    ).lower()

    if not text.startswith(SECTION_ID_PREFIX):
        raise ValueError("section id must start with 'sec:'")

    address = text[len(SECTION_ID_PREFIX) :]
    if not address:
        raise ValueError("section id must contain a start address")

    return SECTION_ID_PREFIX + normalize_graph_address(address)


def build_section_node(
    name,
    start,
    end,
    size,
    read,
    write,
    execute,
    initialized,
    entropy=None,
    entropy_class="unknown",
    entropy_sampled_bytes=0,
    suspicious=False,
    reasons=None,
):
    """Build a typed SECTION node from Ghidra memory-block facts."""

    section_name = _normalize_nonempty_text(name, "section name")
    normalized_start = normalize_graph_address(start)
    normalized_end = normalize_graph_address(end)

    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("section size must be a non-negative integer")

    for field_name, value in (
        ("read", read),
        ("write", write),
        ("execute", execute),
        ("initialized", initialized),
        ("suspicious", suspicious),
    ):
        if not isinstance(value, bool):
            raise ValueError("section {} flag must be boolean".format(field_name))

    if entropy is not None:
        if isinstance(entropy, bool) or not isinstance(entropy, (int, float)):
            raise ValueError("section entropy must be numeric or None")
        entropy = float(entropy)

    if (
        isinstance(entropy_sampled_bytes, bool)
        or not isinstance(entropy_sampled_bytes, int)
        or entropy_sampled_bytes < 0
    ):
        raise ValueError(
            "section entropy_sampled_bytes must be a non-negative integer"
        )

    entropy_class_text = (
        "unknown"
        if entropy_class is None
        else str(entropy_class).strip() or "unknown"
    )

    reason_values = sorted(
        set(str(reason) for reason in (reasons or []) if str(reason).strip())
    )

    permissions = "{}{}{}".format(
        "r" if read else "-",
        "w" if write else "-",
        "x" if execute else "-",
    )

    return {
        "id": build_section_id(normalized_start),
        "type": NodeType.SECTION.value,
        "name": section_name,
        "start": normalized_start,
        "end": normalized_end,
        "size": size,
        "permissions": permissions,
        "read": read,
        "write": write,
        "execute": execute,
        "initialized": initialized,
        "entropy": entropy,
        "entropy_class": entropy_class_text,
        "entropy_sampled_bytes": entropy_sampled_bytes,
        "suspicious": suspicious,
        "reasons": reason_values,
    }


def build_function_section_edge(function_id, section_id):
    """Build FUNCTION -> SECTION membership."""

    function = validate_stable_function_id(function_id)
    section = validate_section_id(section_id)

    return {
        "type": EdgeType.BELONGS_TO_SECTION.value,
        "source": function,
        "target": section,
        "function": function,
        "section": section,
    }


def build_call_visibility_indicator_id(function_id):
    """Build a stable visibility-indicator ID for one FUNCTION."""

    function = validate_stable_function_id(function_id)
    return VISIBILITY_ID_PREFIX + "call_visibility:" + function


def validate_call_visibility_indicator_id(indicator_id):
    """Validate the Step 2.10 call-visibility indicator ID."""

    text = _normalize_nonempty_text(
        indicator_id,
        "visibility indicator id",
    ).lower()

    prefix = VISIBILITY_ID_PREFIX + "call_visibility:"
    if not text.startswith(prefix):
        raise ValueError(
            "call visibility indicator id must start with 'vis:call_visibility:'"
        )

    function_id = text[len(prefix) :]
    return prefix + validate_stable_function_id(function_id)


def build_call_visibility_indicator_node(
    function_id,
    indirect_callsites,
    resolved_indirect_callsites=None,
    unresolved_indirect_callsites=None,
    dynamic_dispatch_callsites=None,
    dynamic_dispatch_targets=None,
):
    """Build aggregated indirect-call visibility evidence for a FUNCTION.

    Dynamic dispatch is deliberately conservative in Step 2.10: the exporter
    sets it only when one computed callsite has multiple resolved call targets.
    """

    function = validate_stable_function_id(function_id)
    indirect_sites = _normalize_callsites(indirect_callsites)

    resolved_sites = []
    if resolved_indirect_callsites:
        resolved_sites = sorted(
            set(
                normalize_graph_address(callsite)
                for callsite in resolved_indirect_callsites
            )
        )

    unresolved_sites = []
    if unresolved_indirect_callsites:
        unresolved_sites = sorted(
            set(
                normalize_graph_address(callsite)
                for callsite in unresolved_indirect_callsites
            )
        )

    dispatch_sites = []
    if dynamic_dispatch_callsites:
        dispatch_sites = sorted(
            set(
                normalize_graph_address(callsite)
                for callsite in dynamic_dispatch_callsites
            )
        )

    targets = sorted(
        set(
            _normalize_nonempty_text(target, "dynamic dispatch target").lower()
            for target in (dynamic_dispatch_targets or [])
        )
    )

    signals = ["indirect_call"]
    if unresolved_sites:
        signals.append("unresolved_call")
    if dispatch_sites:
        signals.append("dynamic_dispatch")

    return {
        "id": build_call_visibility_indicator_id(function),
        "type": NodeType.VISIBILITY_INDICATOR.value,
        "indicator": "call_visibility",
        "function": function,
        "signals": signals,
        "indirect_callsites": indirect_sites,
        "indirect_call_count": len(indirect_sites),
        "resolved_indirect_callsites": resolved_sites,
        "resolved_indirect_call_count": len(resolved_sites),
        "unresolved_indirect_callsites": unresolved_sites,
        "unresolved_indirect_call_count": len(unresolved_sites),
        "dynamic_dispatch_callsites": dispatch_sites,
        "dynamic_dispatch_count": len(dispatch_sites),
        "dynamic_dispatch_targets": targets,
        "dynamic_dispatch_recognition": (
            "computed_call_with_multiple_resolved_targets"
            if dispatch_sites
            else None
        ),
    }


def build_indirect_call_indicator_edge(function_id, indicator_id):
    """Build FUNCTION -> VISIBILITY_INDICATOR indirect-call evidence."""

    function = validate_stable_function_id(function_id)
    indicator = validate_call_visibility_indicator_id(indicator_id)

    expected_indicator = build_call_visibility_indicator_id(function)
    if indicator != expected_indicator:
        raise ValueError(
            "call visibility indicator must belong to the source function"
        )

    return {
        "type": EdgeType.CONTAINS_INDIRECT_CALL.value,
        "source": function,
        "target": indicator,
        "function": function,
        "indicator": indicator,
    }


def build_unresolved_function_call(
    caller_id,
    callsite,
    indirect=False,
):
    """Build evidence for a call instruction without a resolved target."""

    if not isinstance(indirect, bool):
        raise ValueError("indirect flag must be a boolean")

    caller = validate_stable_function_id(caller_id)
    normalized_callsite = normalize_graph_address(callsite)

    return {
        "indicator": "unresolved_call",
        "reason": "no_resolved_function_or_api_target",
        "caller": caller,
        "callee": None,
        "callsite": normalized_callsite,
        "direct": not indirect,
        "indirect": indirect,
        "unresolved": True,
        "occurrences": 1,
    }


def build_typed_graph_model_contract():
    """Return the serializable graph vocabulary and current node/edge shapes."""

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
        "api_node": {
            "type": NodeType.API.value,
            "primary_key": "id",
            "id_prefix": API_ID_PREFIX,
            "fields": [
                "id",
                "type",
                "name",
                "normalized_name",
                "original_names",
            ],
        },
        "string_node": {
            "type": NodeType.STRING.value,
            "primary_key": "id",
            "id_prefix": STRING_ID_PREFIX,
            "fields": [
                "id",
                "type",
                "address",
                "value",
                "raw_value",
                "category",
                "categories",
                "reference_count",
            ],
            "nullable_fields": ["category"],
        },
        "string_category_node": {
            "type": NodeType.STRING_CATEGORY.value,
            "primary_key": "id",
            "id_prefix": STRING_CATEGORY_ID_PREFIX,
        },
        "constant_node": {
            "type": NodeType.CONSTANT.value,
            "primary_key": "id",
            "id_prefix": CONSTANT_ID_PREFIX,
            "id_semantics": "category+unsigned_value",
        },
        "section_node": {
            "type": NodeType.SECTION.value,
            "primary_key": "id",
            "id_prefix": SECTION_ID_PREFIX,
            "id_semantics": "start_address",
        },
        "visibility_indicator_node": {
            "type": NodeType.VISIBILITY_INDICATOR.value,
            "primary_key": "id",
            "id_prefix": VISIBILITY_ID_PREFIX,
            "indicator": "call_visibility",
            "signals": [
                "indirect_call",
                "unresolved_call",
                "dynamic_dispatch",
            ],
            "dynamic_dispatch_recognition": (
                "computed_call_with_multiple_resolved_targets"
            ),
        },
        "function_call_edge": {
            "type": EdgeType.CALLS_FUNCTION.value,
            "source_type": NodeType.FUNCTION.value,
            "target_type": NodeType.FUNCTION.value,
            "aggregation": "caller+callee+call_kind",
        },
        "api_call_edge": {
            "type": EdgeType.CALLS_API.value,
            "source_type": NodeType.FUNCTION.value,
            "target_type": NodeType.API.value,
            "aggregation": "caller+api+call_kind",
        },
        "string_reference_edge": {
            "type": EdgeType.REFERENCES_STRING.value,
            "source_type": NodeType.FUNCTION.value,
            "target_type": NodeType.STRING.value,
            "aggregation": "function+string",
        },
        "string_category_edge": {
            "type": EdgeType.HAS_STRING_CATEGORY.value,
            "source_type": NodeType.STRING.value,
            "target_type": NodeType.STRING_CATEGORY.value,
            "aggregation": "string+category",
        },
        "constant_use_edge": {
            "type": EdgeType.USES_CONSTANT.value,
            "source_type": NodeType.FUNCTION.value,
            "target_type": NodeType.CONSTANT.value,
            "aggregation": "function+constant",
        },
        "function_section_edge": {
            "type": EdgeType.BELONGS_TO_SECTION.value,
            "source_type": NodeType.FUNCTION.value,
            "target_type": NodeType.SECTION.value,
            "aggregation": "function+section",
        },
        "indirect_call_indicator_edge": {
            "type": EdgeType.CONTAINS_INDIRECT_CALL.value,
            "source_type": NodeType.FUNCTION.value,
            "target_type": NodeType.VISIBILITY_INDICATOR.value,
            "aggregation": "function+call_visibility",
        },
        "unresolved_function_call": {
            "edge": False,
            "indicator": "unresolved_call",
            "reason": "no_resolved_function_or_api_target",
        },
        "graph_contract": {
            "scope": "complete_seeded_evidence_graph",
            "callgraph_source": "ghidra_instruction_references",
            "legacy_callgraph_used": False,
            "legacy_callgraph_limits_applied": False,
            "truncated": False,
        },
    }
