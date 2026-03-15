"""SCP Context class with async context manager support.

Wraps the ``_scp_core`` PyO3 bridge functions for context lifecycle,
messaging, and tool invocation.  Resource lifecycle is managed via
``async with`` -- the context manager ensures cleanup (leave context
if still active) on ``__aexit__``.

``receive()`` returns an :class:`AsyncIterator[Message]
<collections.abc.AsyncIterator>` backed by a bounded receive buffer
(default 1,000 events, oldest-drop overflow, ``BufferOverflow`` warning
event emitted on overflow).

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 2 and
``.docs/standards/sdk-common.md`` §Receive stream buffer tests for the
canonical design.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ContextError
from scp_sdk.types import (
    Capability,
    CeilingPolicy,
    ContextMode,
    MemberRole,
    MemoryScope,
    Message,
    PromotionPolicy,
)

if TYPE_CHECKING:
    from scp_sdk.identity import Identity

logger = logging.getLogger("scp_sdk")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default receive buffer capacity (events).
_DEFAULT_BUFFER_SIZE: int = 1_000

#: Minimum configurable buffer size.
_MIN_BUFFER_SIZE: int = 100

#: Maximum configurable buffer size.
_MAX_BUFFER_SIZE: int = 10_000


# ---------------------------------------------------------------------------
# Membership dataclass
# ---------------------------------------------------------------------------


@dataclass
class Membership:
    """Represents a participant's membership in a context.

    Returned by :meth:`Context.join`.
    """

    #: DID of the member.
    did: str

    #: Role assigned to the member within the context.
    role: str

    #: Identifier of the context the member joined.
    context_id: str


# ---------------------------------------------------------------------------
# _ReceiveIterator -- AsyncIterator with buffer semantics
# ---------------------------------------------------------------------------


class _ReceiveIterator(AsyncIterator[Message]):
    """Async iterator over incoming messages from an SCP context.

    Wraps the bridge-level ``PyMessageReceiver`` which returns
    ``asyncio.Future`` objects from ``__anext__``.  Each await yields
    control back to the asyncio event loop so other coroutines can
    make progress while waiting for messages.

    Oldest-drop overflow semantics are handled at the Rust bridge
    level (see ``deliver_message`` in ``runtime.rs``).

    Buffer size defaults to :data:`_DEFAULT_BUFFER_SIZE` (1,000) and is
    configurable via :meth:`Context.create` or :meth:`Context.configure`.
    """

    def __init__(self, bridge_receiver: Any, buffer_size: int) -> None:
        self._receiver = bridge_receiver
        self._buffer: deque[Message] = deque(maxlen=buffer_size)
        self._buffer_size = buffer_size
        self._closed = False

    def __aiter__(self) -> _ReceiveIterator:
        return self

    async def __anext__(self) -> Message:
        if self._closed:
            raise StopAsyncIteration

        # Return buffered messages first.
        if self._buffer:
            return self._buffer.popleft()

        # Await the bridge receiver's __anext__, which returns an
        # asyncio.Future that resolves when a message arrives on the
        # tokio channel.  This yields control to the asyncio event loop
        # so other coroutines can make progress while waiting (fixes #138).
        raw = await self._receiver.__anext__()

        if raw is None:
            # Channel closed (sender dropped) -- stop iteration.
            self._closed = True
            raise StopAsyncIteration

        return Message(
            sender_did=raw.sender_did,
            content=raw.payload,
            timestamp=raw.timestamp,
            sequence=0,
            context_id=raw.context_id,
        )

    def close(self) -> None:
        """Mark the iterator as closed; subsequent iteration will stop."""
        self._closed = True


# ---------------------------------------------------------------------------
# Context class
# ---------------------------------------------------------------------------


class Context:
    """An SCP context with async context manager support.

    Wraps the ``_scp_core`` bridge functions for context lifecycle,
    messaging, and tool invocation.  Use :meth:`create` to construct
    instances.

    Attributes:
        context_id: Unique identifier for this context.
        state: Lifecycle state (``'creating'``, ``'active'``,
            ``'closing'``, ``'closed'``, ``'expired'``).
    """

    def __init__(self, handle: Any, creator_did: str, buffer_size: int) -> None:
        self._handle = handle
        self._creator_did = creator_did
        self._buffer_size = buffer_size

    # -- Properties ---------------------------------------------------------

    @property
    def context_id(self) -> str:
        """Unique identifier for this context."""
        return self._handle.context_id

    @property
    def state(self) -> str:
        """Current lifecycle state of the context."""
        return self._handle.state

    # -- Factory ------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        creator: Identity,
        ceiling: list[Capability | str],
        tools: list[Any] | None = None,
        roles: dict[str, list[str]] | None = None,
        ttl: float | None = None,
        memory_scope: MemoryScope | str = MemoryScope.FULL,
        governance: str = "single_admin",
        mode: ContextMode | str = ContextMode.ENCRYPTED,
        ceiling_policy: CeilingPolicy | str = CeilingPolicy.IMMUTABLE,
        promotion_policy: PromotionPolicy | str = PromotionPolicy.NO_PROMOTION,
        template_id: str | None = None,
        economic_policy: str | None = None,
        buffer_size: int = _DEFAULT_BUFFER_SIZE,
    ) -> Context:
        """Create a new SCP context.

        Args:
            creator: The identity creating the context.
            ceiling: Capability ceiling -- maximum capabilities any
                participant can hold.  Accepts :class:`Capability` enum
                members, raw strings, or a mix of both.
            tools: Optional list of tool definitions to register.
            roles: Optional mapping of role names to capability lists.
            ttl: Optional time-to-live in seconds.
            memory_scope: Memory scope.  Accepts a :class:`MemoryScope`
                enum member or a raw string (``'ephemeral'``,
                ``'summary'``, ``'full'``).  Defaults to
                :attr:`MemoryScope.FULL`.
            governance: Governance model.  Defaults to
                ``'single_admin'``.
            mode: Context mode (spec section 5.1).  Accepts a
                :class:`ContextMode` enum member or a raw string
                (``'encrypted'``, ``'broadcast'``).  Defaults to
                :attr:`ContextMode.ENCRYPTED`.
            ceiling_policy: Ceiling mutability policy (spec section 5.3).
                Accepts a :class:`CeilingPolicy` enum member or a raw
                string (``'immutable'``, ``'governed'``).  Defaults to
                :attr:`CeilingPolicy.IMMUTABLE`.
            promotion_policy: Promotion policy (spec section 5.10).
                Accepts a :class:`PromotionPolicy` enum member or a raw
                string (``'no_promotion'``, ``'promotable'``).  Defaults
                to :attr:`PromotionPolicy.NO_PROMOTION`.
            template_id: Optional well-known template identifier
                (spec section 5.14).  When present, all other fields
                must match the template definition.
            economic_policy: Optional economic policy as a JSON string
                (spec section 19).  ``None`` means free context.
            buffer_size: Receive buffer capacity.  Defaults to 1,000.
                Must be between 100 and 10,000.

        Returns:
            A new :class:`Context` in the ``'active'`` state.

        Raises:
            ContextError: If context creation fails.
            ValidationError: If parameters are invalid.
        """
        _validate_buffer_size(buffer_size)

        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        ceiling_strs = [c.value if isinstance(c, Capability) else c for c in ceiling]
        scope_str = memory_scope.value if isinstance(memory_scope, MemoryScope) else memory_scope
        mode_str = mode.value if isinstance(mode, ContextMode) else mode
        ceiling_policy_str = (
            ceiling_policy.value if isinstance(ceiling_policy, CeilingPolicy) else ceiling_policy
        )
        promotion_policy_str = (
            promotion_policy.value
            if isinstance(promotion_policy, PromotionPolicy)
            else promotion_policy
        )

        params: dict[str, Any] = {
            "ceiling": ceiling_strs,
            "roles": roles or {},
            "tools": [t.name for t in tools] if tools else [],
            "ttl": ttl,
            "memory_scope": scope_str,
            "governance": governance,
            "mode": mode_str,
            "ceiling_policy": ceiling_policy_str,
            "promotion_policy": promotion_policy_str,
            "template_id": template_id,
            "economic_policy": economic_policy,
        }

        handle = _scp_core.py_context_create(creator.did, params)
        return cls(handle=handle, creator_did=creator.did, buffer_size=buffer_size)

    # -- Lifecycle ----------------------------------------------------------

    async def join(self, identity: Identity) -> Membership:
        """Join this context with the given identity.

        Args:
            identity: The identity joining the context.

        Returns:
            A :class:`Membership` representing the new participant.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        _scp_core.py_context_join(self._handle, identity.did)
        return Membership(
            did=identity.did,
            role="member",
            context_id=self.context_id,
        )

    async def leave(self, identity: Identity) -> None:
        """Leave this context with the given identity.

        Args:
            identity: The identity leaving the context.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        _scp_core.py_context_leave(self._handle, identity.did)

    async def close(self, identity: Identity) -> None:
        """Close this context.

        Requires admin role or ``ContextClose`` capability.

        Args:
            identity: The identity initiating the close.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        _scp_core.py_context_close(self._handle, identity.did)

    # -- Messaging ----------------------------------------------------------

    async def send(
        self,
        message: str | bytes,
        identity: Identity | None = None,
    ) -> None:
        """Send a message to this context.

        Args:
            message: The message payload (text or binary).
            identity: The sending identity.  Defaults to the context
                creator if not specified.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        sender_did = identity.did if identity is not None else self._creator_did
        _scp_core.py_context_send(self._handle, sender_did, message)

    async def receive(self) -> AsyncIterator[Message]:
        """Return an async iterator of incoming messages.

        The iterator is backed by a bounded buffer (default 1,000
        events).  When the consumer falls behind, the oldest
        unconsumed event is dropped and a ``BufferOverflow`` warning
        is emitted.

        Returns:
            An :class:`AsyncIterator[Message]
            <collections.abc.AsyncIterator>`.

        Raises:
            ContextError: If the context is not active.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        bridge_receiver = _scp_core.py_context_receive(self._handle)
        return _ReceiveIterator(bridge_receiver, self._buffer_size)

    # -- Tool invocation ----------------------------------------------------

    async def invoke(
        self,
        tool: str,
        input: dict[str, Any],
        ucan_token: str,
        identity: Identity | None = None,
        proof_tokens: list[str] | None = None,
    ) -> dict[str, Any]:
        """Invoke a tool registered in this context.

        Requires a valid UCAN token authorizing the invocation.  The
        token must contain a ``tool_invoke:{tool_id}`` or
        ``tool_invoke:*`` capability scoped to this context.  See
        spec section 6.2, section 8, and ADR-016 for UCAN enforcement.

        .. versionchanged:: 0.2.0
            ``ucan_token`` is now a required positional parameter
            (previously tool invocation did not require UCAN
            authorization).  This is a **breaking change** -- callers
            that previously used ``Context.invoke(tool, input)`` or
            ``Context.invoke(tool, input, identity=...)`` must now
            pass the UCAN token as the third positional argument:
            ``Context.invoke(tool, input, ucan_token)``.
            ``proof_tokens`` was also added as an optional keyword
            argument for delegation chain resolution.

        Args:
            tool: The tool identifier.
            input: Input data as a JSON-compatible dict.
            ucan_token: JWT-encoded UCAN token authorizing the
                invocation.  Validated using the full 11-step ADR-016
                pipeline.
            identity: The invoking identity.  Defaults to the context
                creator if not specified.
            proof_tokens: Optional list of additional UCAN proof
                tokens for delegation chain resolution.

        Returns:
            The tool's output as a JSON-compatible dict.

        Raises:
            ContextError: If the context is not active or the tool is
                not found.
            ToolError: If tool execution fails.
            UcanError: If the UCAN token is invalid, expired, revoked,
                or lacks the required tool invocation capability.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        invoker_did = identity.did if identity is not None else self._creator_did
        result = _scp_core.tool_invoke(
            self.context_id,
            tool,
            input,
            invoker_did,
            ucan_token,
            proof_tokens,
        )
        return result

    # -- Membership queries -------------------------------------------------

    async def member_count(self) -> int | None:
        """Return the number of members in this context.

        Returns:
            The member count, or ``None`` if the context is not registered.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        result = _scp_core.py_context_member_count(self._handle)
        return int(result) if result is not None else None

    async def is_member(self, did: str) -> bool:
        """Check whether a DID is a member of this context.

        Args:
            did: The DID to check.

        Returns:
            ``True`` if the DID is a member.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return _scp_core.py_context_is_member(self._handle, did)

    async def member_dids(self) -> list[str]:
        """Return all member DIDs in this context.

        Returns:
            A list of DID strings.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return _scp_core.py_context_member_dids(self._handle)

    async def member_role(self, did: str) -> MemberRole | None:
        """Return the role of a member in this context.

        Args:
            did: The DID of the member.

        Returns:
            A :class:`MemberRole` enum member, or ``None`` if the
            member is not found.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        raw = _scp_core.py_context_member_role(self._handle, did)
        if raw is None:
            return None
        return MemberRole.from_bridge(raw)

    # -- Economic policy ----------------------------------------------------

    async def set_economic_policy(self, policy_json: str) -> None:
        """Set the economic policy for this context (spec section 19).

        Validates the JSON against the ``EconomicPolicy`` schema before
        storing.

        Args:
            policy_json: The economic policy as a JSON string.

        Raises:
            ContextError: If the bridge is unavailable.
            ValidationError: If the JSON is invalid or does not conform
                to the ``EconomicPolicy`` schema.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        _scp_core.py_set_economic_policy(self._handle, policy_json)

    async def get_economic_policy(self) -> str | None:
        """Return the economic policy for this context as a JSON string.

        Returns:
            The economic policy JSON, or ``None`` if no policy is set.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return _scp_core.py_get_economic_policy(self._handle)

    # -- Broadcast operations -----------------------------------------------

    async def broadcast_subscribe(self, subscriber_did: str) -> None:
        """Subscribe a DID to this broadcast context.

        For open broadcast contexts, any DID can subscribe. For gated
        contexts, a valid ``messages:read`` UCAN is required.

        Args:
            subscriber_did: The DID subscribing to broadcasts.

        Raises:
            ContextError: If the context is not active or not broadcast.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        _scp_core.py_broadcast_subscribe(self._handle, subscriber_did)

    async def broadcast_unsubscribe(
        self,
        subscriber_did: str,
        *,
        rotate_keys: bool = False,
    ) -> None:
        """Unsubscribe a DID from this broadcast context.

        Args:
            subscriber_did: The DID to unsubscribe.
            rotate_keys: When ``True``, all authors rotate their
                broadcast keys after unsubscription.

        Raises:
            ContextError: If the context is not active or not broadcast.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        _scp_core.py_broadcast_unsubscribe(self._handle, subscriber_did, rotate_keys)

    async def broadcast_publish(
        self,
        payload: bytes,
        identity: Identity | None = None,
    ) -> None:
        """Publish a message to this broadcast context.

        The payload is encrypted with the author's broadcast key.

        Args:
            payload: The raw message payload.
            identity: The publishing identity. Defaults to the context
                creator if not specified.

        Raises:
            ContextError: If the context is not active or not broadcast.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        author_did = identity.did if identity is not None else self._creator_did
        _scp_core.py_broadcast_publish(self._handle, author_did, payload)

    async def broadcast_block_subscriber(
        self,
        subscriber_did: str,
        blocker_did: str | None = None,
    ) -> None:
        """Block a subscriber's read access in this broadcast context.

        Args:
            subscriber_did: The DID of the subscriber to block.
            blocker_did: The DID of the blocker. Defaults to the
                context creator if not specified.

        Raises:
            ContextError: If the operation fails.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        blocker = blocker_did if blocker_did is not None else self._creator_did
        _scp_core.py_broadcast_block_subscriber(self._handle, subscriber_did, blocker)

    async def broadcast_unblock_subscriber(
        self,
        subscriber_did: str,
        unblocker_did: str | None = None,
    ) -> None:
        """Unblock a previously blocked subscriber in this broadcast context.

        Forward-only restoration (section 9.16.8): the unblocked subscriber
        can request the current key on next pull but cannot decrypt content
        from the block period.

        Args:
            subscriber_did: The DID of the subscriber to unblock.
            unblocker_did: The DID of the author performing the unblock.
                Defaults to the context creator if not specified.

        Raises:
            ContextError: If the operation fails.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        unblocker = unblocker_did if unblocker_did is not None else self._creator_did
        _scp_core.py_broadcast_unblock_subscriber(self._handle, subscriber_did, unblocker)

    async def broadcast_handle_key_request(
        self,
        author_did: str,
        requester_did: str,
    ) -> str:
        """Handle a broadcast key request from a subscriber.

        Args:
            author_did: The DID of the author handling the request.
            requester_did: The DID of the requester.

        Returns:
            A string describing the key request decision.

        Raises:
            ContextError: If the operation fails.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return _scp_core.py_broadcast_handle_key_request(self._handle, author_did, requester_did)

    async def broadcast_subscriber_count(self) -> int | None:
        """Return the number of broadcast subscribers for this context.

        Returns:
            The subscriber count, or ``None`` if the context is not
            a broadcast context.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        result = _scp_core.py_broadcast_subscriber_count(self._handle)
        return int(result) if result is not None else None

    async def broadcast_is_subscriber(self, did: str) -> bool:
        """Check whether a DID is a broadcast subscriber.

        Args:
            did: The DID to check.

        Returns:
            ``True`` if the DID is a subscriber.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return _scp_core.py_broadcast_is_subscriber(self._handle, did)

    async def broadcast_admission(self) -> str | None:
        """Return the broadcast admission policy for this context.

        Returns:
            The policy as a string (``'Open'`` or ``'Gated'``), or
            ``None`` if not a broadcast context.

        Raises:
            ContextError: If the bridge is unavailable.
        """
        try:
            import _scp_core
        except ImportError as exc:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                code="SCP-CTX-2001",
            ) from exc

        return _scp_core.py_broadcast_admission(self._handle)

    # -- Configuration ------------------------------------------------------

    def configure(self, *, buffer_size: int | None = None) -> None:
        """Update runtime configuration for this context.

        Args:
            buffer_size: New receive buffer capacity (100--10,000).

        Raises:
            ValueError: If *buffer_size* is out of bounds.
        """
        if buffer_size is not None:
            _validate_buffer_size(buffer_size)
            self._buffer_size = buffer_size

    # -- Async context manager ----------------------------------------------

    async def __aenter__(self) -> Context:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Cleanup: leave context if still active, then destroy local state.

        When the context is in the ``'active'`` state, this method
        performs *participant departure* (sends a ``MemberLeft`` event)
        followed by local crypto-state destruction.  If the context has
        already been left or closed, only local cleanup runs.

        For *admin-level* context closure (which terminates the context
        for all participants and destroys the MLS group), call
        :meth:`close` explicitly before exiting the ``async with``
        block.

        Errors during cleanup are logged but never raised -- callers
        must not be penalized for disposing resources.  After this
        method returns, all local state (sender keys, MLS epoch state,
        transport handles) is released regardless of whether the remote
        leave operation succeeded.
        """
        try:
            if self.state == "active":
                try:
                    import _scp_core

                    _scp_core.py_context_leave(self._handle, self._creator_did)
                except Exception:
                    logger.debug(
                        "cleanup: failed to leave context %s",
                        self.context_id,
                        exc_info=True,
                    )
        finally:
            self._destroy_local_state()

    # -- Local cleanup -------------------------------------------------------

    def _destroy_local_state(self) -> None:
        """Release local crypto state (sender keys, MLS epoch, handles).

        Called unconditionally at the end of ``__aexit__`` to satisfy
        the resource lifecycle invariant: after dispose returns, all
        local state is released regardless of remote operation outcomes.

        Errors during destruction are logged but never raised.
        """
        try:
            import _scp_core

            if hasattr(_scp_core, "py_context_destroy_local"):
                _scp_core.py_context_destroy_local(self._handle)
        except Exception:
            logger.debug(
                "cleanup: failed to destroy local state for context %s",
                self.context_id,
                exc_info=True,
            )

    # -- Finalizer (GC safety for long-running processes) -------------------

    def __del__(self) -> None:
        """Release registry resources if the context was not properly closed.

        Called by the garbage collector when the ``Context`` object is
        reclaimed.  This is a last-resort cleanup for processes that do
        not use ``async with`` or forget to call :meth:`close`.

        Errors are silently suppressed -- ``__del__`` must never raise.
        """
        try:
            # Capture handle in a local variable to avoid TOCTOU race:
            # _handle could become None between the check and the use.
            handle = getattr(self, "_handle", None)
            if handle is None:
                return

            creator_did = getattr(self, "_creator_did", None)
            if creator_did is None:
                return

            # Check state via the handle directly (not self.state which
            # re-reads self._handle, re-introducing the race).
            try:
                state = handle.state
            except Exception:
                return

            if state == "active":
                try:
                    import _scp_core

                    _scp_core.py_context_close(handle, creator_did)
                except Exception:
                    # Best-effort: context may already be closed, or
                    # interpreter may be shutting down.
                    pass
        except Exception:
            pass

    # -- Representation -----------------------------------------------------

    def __repr__(self) -> str:
        return f"Context(context_id={self.context_id!r}, state={self.state!r})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_buffer_size(size: int) -> None:
    """Raise :class:`ValueError` if *size* is outside the valid range."""
    if not (_MIN_BUFFER_SIZE <= size <= _MAX_BUFFER_SIZE):
        msg = f"buffer_size must be between {_MIN_BUFFER_SIZE} and {_MAX_BUFFER_SIZE}, got {size}"
        raise ValueError(msg)


@dataclass(frozen=True)
class ScopedHandle:
    """Capability-restricted context handle (spec section 8.4.2).

    Wraps a context with a whitelist of allowed capabilities. All protocol
    operations must check the whitelist before proceeding. An app cannot
    access protocol operations beyond its declared capabilities.

    Once created, a ``ScopedHandle`` cannot gain additional capabilities
    (no escalation guarantee, spec 8.4.2 rule 4).
    """

    context: Context
    granted_capabilities: tuple[str, ...]
    app_did: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "granted_capabilities", tuple(self.granted_capabilities))

    def has_capability(self, capability: str) -> bool:
        """Check whether a given capability is allowed."""
        import _scp_core

        return _scp_core.py_check_scoped_capability(self.granted_capabilities, capability)

    def check_capability(self, capability: str) -> None:
        """Raise :class:`ContextError` if the capability is not granted."""
        if not self.has_capability(capability):
            msg = f"capability denied: {capability} not granted to app {self.app_did}"
            raise ContextError(msg)


def validate_capability_declaration(
    declaration_json: str,
    ceiling_capabilities: list[str],
    role_capabilities: list[str],
) -> dict[str, Any]:
    """Validate a capability declaration against a context ceiling and role.

    Returns a dict with ``valid`` (bool), ``granted_capabilities`` (list of str),
    ``error`` (str or None), and ``app_did`` (str).

    See spec sections 8.4.1 and 8.4.2.
    """
    import json

    import _scp_core

    result_json = _scp_core.py_validate_capability_declaration(
        declaration_json, ceiling_capabilities, role_capabilities
    )
    return json.loads(result_json)


def evaluate_invitation(
    params_json: str,
    inviter_did: str,
    identity_did: str,
    *,
    policy_json: str | None = None,
    spending_json: str | None = None,
    trusted_dids: list[str] | None = None,
) -> str:
    """Evaluate a context invitation through the sequential pipeline.

    Runs the 4-step evaluation pipeline:

    1. **Template check** -- validates params match the claimed template.
    2. **Economic policy check** -- verifies spending capability for paid
       contexts.
    3. **Auto-accept check** -- evaluates trust, TTL cap, and rate limit
       against a matching auto-accept policy.
    4. **Agent prompt** -- falls through if no auto-accept matches.

    Args:
        params_json: JSON-serialized ``ContextParams`` from the invitation.
        inviter_did: DID string of the identity sending the invitation.
        identity_did: DID string of the local identity receiving the
            invitation. Used to key the rate limit tracker.
        policy_json: Optional JSON-serialized ``AutoAcceptPolicy``. If
            ``None``, the pipeline always falls through to prompt-agent.
        spending_json: Optional JSON-serialized ``SpendingContext``.
            Required when the context has an economic policy requiring
            payment.
        trusted_dids: Optional list of DID strings representing identities
            trusted by the local identity (e.g., shared-context peers).

    Returns:
        ``"auto_accept"`` if the pipeline decided to auto-accept,
        ``"prompt_agent"`` if the agent should be prompted.

    Raises:
        ScpError: If input validation or pipeline evaluation fails.

    Example::

        decision = evaluate_invitation(
            params_json=invitation.params_json,
            inviter_did="did:dht:z6MkBob...",
            identity_did="did:dht:z6MkAlice...",
            policy_json=my_policy_json,
            trusted_dids=["did:dht:z6MkBob..."],
        )
        if decision == "auto_accept":
            await context.join(invitation)

    See ``.docs/standards/sdk-common.md`` "Invitation evaluation" and
    ``.docs/specs/19-economic-governance.md`` sections 19.3, 19.14.
    """
    import json

    import _scp_core

    trusted_dids_json = json.dumps(trusted_dids) if trusted_dids else None
    return _scp_core.evaluate_invitation(
        params_json,
        inviter_did,
        identity_did,
        policy_json,
        spending_json,
        trusted_dids_json,
    )


__all__ = [
    "Context",
    "Membership",
    "ScopedHandle",
    "evaluate_invitation",
    "validate_capability_declaration",
]
