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

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import BRIDGE_ERROR_MAP, ContextError, ValidationError

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


async def invoke_cross_context(
    scp: SCP,
    source_context_id: str,
    target_context_id: str,
    tool_id: str,
    input: dict[str, Any],
    invoker_did: str,
    ucan_token: str,
    chain_depth: int = 0,
    proof_tokens: list[str] | None = None,
) -> dict[str, Any]:
    """Invoke a tool across context boundaries.

    The source context initiates the call and the target context
    contains the tool.  Both contexts must have approved the interface
    before calls are permitted.  Rate limits and chain depth are
    enforced per spec section 6.2.

    Args:
        source_context_id: The ID of the calling context.
        target_context_id: The ID of the context containing the tool.
        tool_id: The ID of the tool to invoke.
        input: Input data as a JSON-compatible dict matching the tool's
            input schema.
        invoker_did: The DID of the participant invoking the tool.
        ucan_token: JWT-encoded UCAN token authorizing the invocation.
            Must contain ``tool_invoke:{tool_id}`` or ``tool_invoke:*``
            capability.  Validated against the target context's ceiling.
        chain_depth: Current cross-context chain depth (0 for first hop).
            Must be in the range 0-255 (u8 on the bridge side).
        proof_tokens: Optional list of encoded parent UCAN token strings
            for delegation chain verification.

    Returns:
        The tool's output as a JSON-compatible dict.

    Raises:
        ContextError: If either context is not connected, the tool is
            not found, chain depth is exceeded, or the interface is not
            approved.
        UcanPermissionError: If the UCAN token is invalid, expired,
            revoked, or lacks the required tool invocation capability.
        ValidationError: If input validation fails (schema mismatch,
            invalid parameters).
    """
    if (
        isinstance(chain_depth, bool)
        or not isinstance(chain_depth, int)
        or chain_depth < 0
        or chain_depth > 255
    ):
        raise ValidationError(
            f"chain_depth must be an integer in range 0-255, got {chain_depth!r}",
            code="SCP-VALID-7002",
        )

    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        result = await asyncio.to_thread(
            instance.tool_invoke_cross_context,
            source_context_id,
            target_context_id,
            tool_id,
            input,
            invoker_did,
            ucan_token,
            chain_depth,
            proof_tokens,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc
    return result


# ---------------------------------------------------------------------------
# Stateful tool sessions (spec section 6.2.1)
# ---------------------------------------------------------------------------


async def session_create(
    scp: SCP,
    context_id: str,
    tool_id: str,
    source_context_id: str,
    ttl_seconds: int | None = None,
) -> str:
    """Create a stateful tool session.

    Sessions enable multi-turn workflows with state preservation across
    invocations.  Each session is subject to per-caller caps (default: 1000
    concurrent sessions per caller, per spec §6.2.1 and ADR-043).

    Sessions without a TTL persist for the lifetime of the context
    (spec section 6.2.1).

    Args:
        context_id: The context containing the tool.
        tool_id: The tool to create a session for.
        source_context_id: The calling context (session cap tracked per
            caller).
        ttl_seconds: Optional time-to-live for the session, in seconds.
            Must be a non-negative integer (u64 on the bridge side) or
            ``None`` for a session that persists for the lifetime of the
            context.

    Returns:
        The session ID (UUID string).

    Raises:
        ContextError: If the context is not connected, the tool is not
            found, or the per-caller session cap is exceeded.
        ValidationError: If input validation fails (invalid parameters).
    """
    if ttl_seconds is not None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 0:
            raise ValidationError(
                f"ttl_seconds must be a non-negative integer, got {ttl_seconds!r}",
                code="SCP-VALID-7002",
            )

    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        return await asyncio.to_thread(
            instance.tool_session_create,
            context_id,
            tool_id,
            source_context_id,
            ttl_seconds,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc


async def session_invoke(
    scp: SCP,
    context_id: str,
    session_id: str,
    input: dict[str, Any],
    invoker_did: str,
    ucan_token: str,
    proof_tokens: list[str] | None = None,
) -> dict[str, Any]:
    """Invoke a tool within an active session.

    Each call is individually governed: the invoker must hold
    ``ToolInvoke`` capability and present a valid UCAN token.  Session
    state is carried forward across invocations.  The session's call
    count is incremented on each successful invocation.

    Args:
        context_id: The context containing the tool session.
        session_id: The session to invoke within.
        input: Input data as a JSON-compatible dict matching the tool's
            input schema.
        invoker_did: The DID of the invoker (capability checked per
            call).
        ucan_token: JWT-encoded UCAN token authorizing the invocation.
            Must contain ``tool_invoke:{tool_id}`` or ``tool_invoke:*``
            capability.
        proof_tokens: Optional list of encoded parent UCAN token strings
            for delegation chain verification.

    Returns:
        The tool's output as a JSON-compatible dict.

    Raises:
        ContextError: If the session is not found, has expired, or the
            invoker lacks capability.
        UcanPermissionError: If the UCAN token is invalid, expired,
            revoked, or lacks the required tool invocation capability.
        ValidationError: If input validation fails (schema mismatch,
            invalid parameters).
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        result = await asyncio.to_thread(
            instance.tool_session_invoke,
            context_id,
            session_id,
            input,
            invoker_did,
            ucan_token,
            proof_tokens,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc
    return result


async def session_close(scp: SCP, context_id: str, session_id: str) -> None:
    """Close a stateful tool session.

    Removes the session from the store, releasing the caller's session
    slot.  After closing, any further invocations with this session ID
    will fail.

    Args:
        context_id: The context containing the tool session.
        session_id: The session to close.

    Raises:
        ContextError: If the context is not connected or the session is
            not found.
        ValidationError: If input validation fails (invalid parameters).
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        await asyncio.to_thread(
            instance.tool_session_close,
            context_id,
            session_id,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc


# ---------------------------------------------------------------------------
# Bidirectional consent protocol (spec section 6.2.0.1)
# ---------------------------------------------------------------------------


async def interface_expose(
    scp: SCP,
    context_id: str,
    tool_id: str,
    target_context_id: str,
    rate_limit_json: str | None = None,
) -> dict[str, Any]:
    """Expose a tool interface for cross-context sharing (step 1).

    The caller (admin of the source context) proposes sharing a specific
    tool with a target context.  The returned interface has
    ``approved_by_source = True`` and ``approved_by_target = False``.
    The target context must call :func:`interface_accept` to complete
    the handshake.

    Args:
        context_id: The source context ID.
        tool_id: The ID of the tool to expose.
        target_context_id: The target context to expose the tool to.
        rate_limit_json: Optional per-interface rate limit as a JSON
            string with ``max_calls`` and ``window_seconds`` fields.

    Returns:
        The ``ToolInterface`` as a JSON-compatible dict.

    Raises:
        ContextError: If the caller is not an admin or the tool is
            not found.
        ValidationError: If ``rate_limit_json`` is malformed.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        result_json = await asyncio.to_thread(
            instance.tool_interface_expose,
            context_id,
            tool_id,
            target_context_id,
            rate_limit_json,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc

    import json

    return json.loads(result_json)


async def interface_accept(
    scp: SCP,
    context_id: str,
    interface_json: str,
) -> dict[str, Any]:
    """Accept a cross-context tool interface (step 4).

    Sets ``approved_by_target = True`` on the interface.  Both
    ``approved_by_source`` and ``approved_by_target`` must be ``True``
    before calls are permitted.

    Args:
        context_id: The target context ID (the one accepting).
        interface_json: The ``ToolInterface`` JSON string to accept
            (as received from the source context's
            :func:`interface_expose` call).

    Returns:
        The updated ``ToolInterface`` as a JSON-compatible dict.

    Raises:
        ContextError: If the caller is not an admin or the interface's
            target context does not match ``context_id``.
        ValidationError: If ``interface_json`` is malformed.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        result_json = await asyncio.to_thread(
            instance.tool_interface_accept,
            context_id,
            interface_json,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc

    import json

    return json.loads(result_json)


async def interface_revoke(
    scp: SCP,
    context_id: str,
    interface_id_hex: str,
) -> dict[str, Any]:
    """Revoke a cross-context tool interface (step 5).

    Either context may revoke unilaterally.  Returns an
    ``InterfaceRevoked`` event for recording in the revoking context's
    event log.

    Args:
        context_id: The revoking context ID.
        interface_id_hex: The 32-byte interface/offer ID as a hex
            string (64 hex characters).

    Returns:
        The ``InterfaceRevoked`` event as a JSON-compatible dict.

    Raises:
        ValidationError: If ``interface_id_hex`` is not valid hex or
            not 32 bytes.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    instance = _resolve_bridge(scp)
    try:
        result_json = await asyncio.to_thread(
            instance.tool_interface_revoke,
            context_id,
            interface_id_hex,
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc

    import json

    return json.loads(result_json)


__all__ = [
    "TestVector",
    "ToolCost",
    "ToolDefinition",
    "interface_accept",
    "interface_expose",
    "interface_revoke",
    "invoke_cross_context",
    "session_close",
    "session_create",
    "session_invoke",
]
