"""Tool-related dataclasses and cross-context/session wrappers for the SCP Python SDK.

Contains :class:`ToolDefinition` and :class:`TestVector`, the two types
needed for tool registration and verification within SCP contexts, plus
module-level async functions for cross-context tool invocation and
stateful tool sessions:

- :func:`invoke_cross_context` -- Invoke a tool across context boundaries.
- :func:`session_create` -- Create a stateful tool session.
- :func:`session_invoke` -- Invoke a tool within an active session.
- :func:`session_close` -- Close a stateful tool session.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 3,
``.docs/standards/python.md`` for conventions, and spec section 6.2 /
6.2.1 for cross-context invocation and stateful sessions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import BRIDGE_ERROR_MAP, ContextError

if TYPE_CHECKING:
    from scp_sdk.identity import Identity
    from scp_sdk.scp import SCP

try:
    import _scp_core  # type: ignore[import-not-found]
except ImportError:
    _scp_core = None  # type: ignore[assignment]


def _resolve_bridge(scp: SCP) -> Any:
    """Return the effective bridge object for tool operations.

    Tests patch ``scp_sdk.tools._scp_core`` with a ``MagicMock`` whose
    ``tool_*`` attributes stand in for the live bridge. In production
    those attributes do not exist on the real ``_scp_core`` module
    (Phase 4 PR 4 consolidated them onto :class:`SCP`), so we fall
    through to ``scp._native`` and dispatch on the SCP instance.
    """
    mod = _scp_core
    if mod is not None and hasattr(mod, "_mock_name"):
        return mod
    return scp._native


def _translate_bridge_error(exc: Exception) -> Exception:
    """Translate a ``_scp_core`` bridge exception to an SDK exception.

    Uses :data:`~scp_sdk.errors.BRIDGE_ERROR_MAP` to look up the SDK type
    by the bridge exception's class name.  Falls back to
    :class:`~scp_sdk.errors.ContextError` for unmapped types.
    """
    sdk_cls = BRIDGE_ERROR_MAP.get(type(exc).__name__, ContextError)
    return sdk_cls(str(exc))


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
class ToolCost:
    """Per-invocation cost metadata for a tool (spec section 5.4.1).

    All monetary values are in the smallest currency unit (e.g., cents
    for USD, satoshis for BTC).
    """

    #: Cost per invocation in the smallest currency unit.
    amount: int

    #: ISO 4217 or protocol-defined currency code.
    currency: str

    #: DID of the payment recipient.  May differ from the tool operator.
    payee: str

    #: Optional pricing formula identifier for dynamic pricing (spec section 19.4).
    cost_formula: str | None = None


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

    #: Optional per-invocation cost metadata (spec section 5.4.1).
    cost: ToolCost | None = None


# ---------------------------------------------------------------------------
# Cross-context tool invocation (spec section 6.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SagaResult:
    """The committed terminal of a §6.2.4 cross-context tool-invocation saga.

    Returned by :meth:`scp_sdk.SCP.tool_invoke_cross_context_saga` only on a
    ``Committed`` terminal — every non-committed terminal raises a typed saga
    exception (:class:`~scp_sdk.errors.SagaAbortedError`,
    :class:`~scp_sdk.errors.SagaNeedsRepairError`, or
    :class:`~scp_sdk.errors.SagaBusyError`) instead.

    The fields are a faithful pass-through of the bridge result: ``receipt``
    and ``output`` are surfaced exactly as the bridge returns them (``None``
    when absent — never synthesized). See spec §6.2.4 and ADR-049 §3a.
    """

    #: The durable saga identifier (supervisor-minted, never a caller input).
    saga_id: str

    #: The target's signed ``CrossContextToolReceipt`` bytes (JCS), or ``None``.
    receipt: bytes | None = None

    #: The captured tool output bytes (the receipt's canonical ``output_jcs``),
    #: or ``None``.
    output: bytes | None = None


# ---------------------------------------------------------------------------
# Stateful tool sessions (spec section 6.2.1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Bidirectional consent protocol (spec section 6.2.0.1)
# ---------------------------------------------------------------------------


__all__ = [
    "SagaResult",
    "TestVector",
    "ToolCost",
    "ToolDefinition",
]
