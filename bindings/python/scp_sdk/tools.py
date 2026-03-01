"""Tool-related dataclasses for the SCP Python SDK.

Contains :class:`ToolDefinition` and :class:`TestVector`, the two types
needed for tool registration and verification within SCP contexts.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 3 and
``.docs/standards/python.md`` for conventions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scp_sdk.identity import Identity


@dataclass
class TestVector:
    """A single test vector for tool verification.

    Test vectors define expected input/output pairs that a tool
    implementation must satisfy.  They are used during tool registration
    to verify that the implementation matches its declared behaviour.
    """

    #: Input data to feed the tool (JSON-compatible dict).
    input: dict[str, Any]

    #: Expected output from the tool (JSON-compatible dict).
    expected_output: dict[str, Any]

    #: Human-readable description of what this vector tests.
    description: str = ""


@dataclass
class ToolDefinition:
    """Definition of a tool registered in an SCP context.

    Mirrors ADR-014 acceptance criterion 3.  The ``operator`` field
    accepts either an ``Identity`` object (from ``scp_sdk.identity``,
    defined in a separate story) or a plain DID string.

    Example::

        tool = ToolDefinition(
            name="recipe_search",
            description="Search recipes by ingredients",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            output_schema={"type": "object", "properties": {"results": {"type": "array"}}},
            operator="did:dht:z6MkOperator",
        )
    """

    #: Unique tool name within the context.
    name: str

    #: Human-readable description of the tool's purpose.
    description: str

    #: JSON Schema describing the tool's input.
    input_schema: dict[str, Any]

    #: JSON Schema describing the tool's output.
    output_schema: dict[str, Any]

    #: DID string or :class:`~scp_sdk.identity.Identity` object of the
    #: tool operator.
    operator: Identity | str | None

    #: Optional test vectors for verification.
    test_vectors: list[TestVector] | None = None

    #: Optional implementation hash for integrity verification.
    implementation_hash: bytes | None = None


__all__ = [
    "TestVector",
    "ToolDefinition",
]
