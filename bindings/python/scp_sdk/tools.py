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

from scp_sdk.errors import ContextError

if TYPE_CHECKING:
    from scp_sdk.identity import Identity

try:
    import _scp_core  # type: ignore[import-not-found]
except ImportError:
    _scp_core = None  # type: ignore[assignment]


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


# ---------------------------------------------------------------------------
# Cross-context tool invocation (spec section 6.2)
# ---------------------------------------------------------------------------


async def invoke_cross_context(
    source_context: str,
    target_context: str,
    tool_id: str,
    input: dict[str, Any],
    invoker_did: str,
    ucan_token: str,
    chain_depth: int = 0,
    proof_tokens: list[str] | None = None,
) -> dict[str, Any]:
    """Invoke a tool across context boundaries.

    The source context exposes the tool and the target context accepts
    the interface.  Both contexts must have approved the interface before
    calls are permitted.  Rate limits and chain depth are enforced per
    spec section 6.2.

    Args:
        source_context: The ID of the calling context.
        target_context: The ID of the context containing the tool.
        tool_id: The ID of the tool to invoke.
        input: Input data as a JSON-compatible dict matching the tool's
            input schema.
        invoker_did: The DID of the participant invoking the tool.
        ucan_token: JWT-encoded UCAN token authorizing the invocation.
            Must contain ``tool_invoke:{tool_id}`` or ``tool_invoke:*``
            capability.  Validated against the target context's ceiling.
        chain_depth: Current cross-context chain depth (0 for first hop).
        proof_tokens: Optional list of encoded parent UCAN token strings
            for delegation chain verification.

    Returns:
        The tool's output as a JSON-compatible dict.

    Raises:
        ContextError: If either context is not connected, the tool is
            not found, chain depth is exceeded, or the interface is not
            approved.
        UcanError: If the UCAN token is invalid, expired, revoked, or
            lacks the required tool invocation capability.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    result = await asyncio.to_thread(
        _scp_core.tool_invoke_cross_context,
        source_context,
        target_context,
        tool_id,
        input,
        invoker_did,
        ucan_token,
        chain_depth,
        proof_tokens,
    )
    return result


# ---------------------------------------------------------------------------
# Stateful tool sessions (spec section 6.2.1)
# ---------------------------------------------------------------------------


async def session_create(
    context: str,
    tool_id: str,
    source_context_id: str,
    ttl_seconds: int,
) -> str:
    """Create a stateful tool session.

    Sessions enable multi-turn workflows with state preservation across
    invocations.  Each session has a TTL and is subject to per-caller
    caps (default: 5 concurrent sessions per caller, per spec section
    6.2.1).

    Args:
        context: The context containing the tool.
        tool_id: The tool to create a session for.
        source_context_id: The calling context (session cap tracked per
            caller).
        ttl_seconds: Time-to-live for the session, in seconds.

    Returns:
        The session ID (UUID string).

    Raises:
        ContextError: If the context is not connected, the tool is not
            found, or the per-caller session cap is exceeded.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    return await asyncio.to_thread(
        _scp_core.tool_session_create,
        context,
        tool_id,
        source_context_id,
        ttl_seconds,
    )


async def session_invoke(
    context: str,
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
        context: The context containing the tool session.
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
        UcanError: If the UCAN token is invalid, expired, revoked, or
            lacks the required tool invocation capability.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    result = await asyncio.to_thread(
        _scp_core.tool_session_invoke,
        context,
        session_id,
        input,
        invoker_did,
        ucan_token,
        proof_tokens,
    )
    return result


async def session_close(context: str, session_id: str) -> None:
    """Close a stateful tool session.

    Removes the session from the store, releasing the caller's session
    slot.  After closing, any further invocations with this session ID
    will fail.

    Args:
        context: The context containing the tool session.
        session_id: The session to close.

    Raises:
        ContextError: If the context is not connected or the session is
            not found.
    """
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )

    await asyncio.to_thread(
        _scp_core.tool_session_close,
        context,
        session_id,
    )


__all__ = [
    "TestVector",
    "ToolDefinition",
    "invoke_cross_context",
    "session_close",
    "session_create",
    "session_invoke",
]
