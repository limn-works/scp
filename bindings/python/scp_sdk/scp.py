"""SDK-level :class:`SCP` entry point for the Python SDK.

See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate")
for the design rationale. The :class:`SCP` class is the only public way
to build against the SCP protocol from Python — each :class:`SCP`
instance owns an independent ``BridgeInstance`` (registries, transport,
context manager), so tests, multi-identity apps, and per-tenant services
can hold distinct instances without sharing state.

The free-function façade that used to delegate to a process-global
default instance was removed in Phase 4 PR 4 (#1549). Every SDK
function now requires an explicit :class:`SCP` argument.

Example usage::

    from scp_sdk import SCP

    # Construct a fresh instance with in-memory state.
    with SCP() as scp:
        # scp.instance_id is a monotonic u64 unique per process.
        ...

    # Explicit in-memory storage config.
    scp = SCP(storage={"type": "in_memory"})
    scp.shutdown(timeout=5.0)

    # SQLCipher-encrypted on-disk storage (Phase 4 PR 3, #1549).
    scp = SCP(storage={
        "type": "sqlite",
        "path": "/var/lib/my-app",
        "key": b"\\x00" * 32,
    })

    # `resume` is async — it awaits transport reconnect (#1678).
    scp.suspend()
    await scp.resume()
"""

from __future__ import annotations

import asyncio
import math
from types import TracebackType
from typing import Any

from scp_sdk.errors import ScpError

__all__ = ["SCP"]


def _native_cls() -> Any:
    """Return the PyO3-native ``SCP`` class from the ``_scp_core`` extension.

    Raised at call time (not import time) so that pure-Python environments
    — where the native extension isn't available — can still ``import
    scp_sdk`` without an ImportError. The caller sees a meaningful
    :class:`ScpError` the first time they actually construct an instance.
    """
    try:
        import _scp_core  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc
    cls = getattr(_scp_core, "SCP", None)
    if cls is None:
        raise ScpError(
            "_scp_core does not export the SCP class — rebuild the native "
            "extension with `maturin develop --release` from the Phase 4 "
            "PR 1 codebase.",
            code="SCP-UNKNOWN-0001",
        )
    return cls


class SCP:
    """Caller-owned SCP instance — the sole public SDK entry point.

    Each :class:`SCP` wraps an independent native ``BridgeInstance`` (with
    its own registries, transport state, and context manager). The wrapper
    exposes lifecycle controls (:meth:`suspend`, :meth:`resume`,
    :meth:`shutdown`) plus the monotonic :attr:`instance_id` used by the
    FFI handle-affinity check.

    Phase 4 PR 4 (#1549, ADR-048) removed the process-global default
    instance and the free-function façade that delegated to it. Every
    caller now owns an explicit :class:`SCP` — pass it positionally to
    :meth:`Identity.create`, :meth:`Context.create`, and every other
    SDK entry point.

    :class:`SCP` is a context manager: ``with SCP() as scp: ...`` calls
    :meth:`shutdown` with a 5-second timeout on exit.
    """

    # The native PyO3 SCP handle. `frozen=True` on the Rust side guarantees
    # we never mutate it from Python; all state mutation is through the
    # interior atomics/mutexes on `PyBridgeInstance`.
    _native: Any

    def __init__(
        self,
        *,
        storage: dict[str, Any] | None = None,
    ) -> None:
        """Construct a fresh :class:`SCP` instance.

        :param storage: Optional storage configuration dict. Accepted shapes:

            * ``{"type": "in_memory"}`` — ephemeral encrypted in-memory
              storage (the default when ``storage`` is ``None``).
            * ``{"type": "sqlite", "path": str, "key": bytes}`` —
              SQLCipher-encrypted on-disk storage at ``{path}/scp.db``.
              ``key`` is the raw encryption key material (32 bytes
              recommended) and is zeroized on the Rust side once the
              database is opened. Landed in Phase 4 PR 3 (#1549).

            When ``None``, defaults to in-memory storage.
        :raises ValidationError: If ``storage`` contains an unknown
            ``type`` or is missing required fields for the selected
            variant.

        .. note::

           A standalone ``persistence`` parameter (injecting a custom
           :class:`ContextPersistence` impl across the FFI boundary)
           remains unexposed at the SDK surface. The SQLite storage
           variant above automatically constructs a real
           :class:`ContextPersistence` internally — opt in via the
           ``storage`` dict. A Python-accessible custom persistence
           trait is deferred; no tracking issue is open because SQLite
           covers the documented use cases.
        """
        cls = _native_cls()
        if storage is not None:
            self._native = cls.with_storage(storage)
        else:
            self._native = cls()

    @property
    def instance_id(self) -> int:
        """Monotonic u64 identifier for this bridge instance.

        Unique per process. Used by the FFI handle-affinity check — every
        handle minted by this instance stores this id, and FFI entry
        points reject handles whose id does not match the receiving
        instance's id.
        """
        return int(self._native.instance_id)

    def suspend(self) -> None:
        """Suspend the bridge for mobile/desktop backgrounding.

        Disconnects the transport (clears the relay connection) and marks
        the instance as suspended. Context state is preserved;
        transport-dependent operations will fail until :meth:`resume` is
        called.

        :raises TransportError: If transport cleanup fails
            (code ``SCP-TRANS-5001``).
        """
        # Lazy import avoids circular dep (errors -> scp -> errors).
        from scp_sdk.errors import TransportError

        try:
            self._native.suspend()
        except Exception as exc:  # PyO3 raises ScpTransportError
            raise TransportError(
                f"suspend failed: {exc}",
                code="SCP-TRANS-5001",
            ) from exc

    async def resume(self) -> None:
        """Resume a suspended bridge instance.

        Clears the suspended flag and — as of Phase 4 PR 3 (#1678) —
        automatically reconnects the transport to every relay URL the
        instance was subscribed to at suspend time. Callers no longer
        need to re-invoke :func:`scp_sdk.connect_relay` manually; the
        FFI layer replays the pending-URL list internally.

        This is an ``async`` coroutine because the underlying PyO3
        ``resume`` performs async work (transport reconnect, persisted
        context restoration) behind a blocking ``block_on`` at the FFI
        boundary. We wrap the blocking call in :func:`asyncio.to_thread`
        so the Python event loop remains responsive while the reconnect
        round-trips complete. Matches the async ``resume`` surface on
        the NAPI and UniFFI bridges (see #1549 PR 3 — commit
        ``refactor(ffi): make resume() async across bridge core + scp
        handles``).

        :raises ContextError: If the instance has been permanently shut
            down (code ``SCP-CTX-2000``).
        """
        # Lazy import avoids circular dep (errors -> scp -> errors).
        from scp_sdk.errors import ContextError

        try:
            await asyncio.to_thread(self._native.resume)
        except Exception as exc:  # PyO3 raises ScpContextError
            raise ContextError(
                f"resume failed: {exc}",
                code="SCP-CTX-2000",
            ) from exc

    def shutdown(self, timeout: float = 5.0) -> None:
        """Shut down this instance with a graceful deadline.

        Drains in-flight tasks within ``timeout`` seconds, aborts any
        stragglers, then runs typed-field cleanup. A second call is a
        no-op (the underlying :class:`ShutdownError::AlreadyShutDown` is
        swallowed at the SDK surface).

        ``timeout`` is clamped defensively: ``NaN`` and negative values
        map to ``0`` (abort immediately); ``math.inf`` or values that
        would overflow ``u64`` milliseconds map to ``0xFFFFFFFF_FFFFFFFF``
        (effectively unbounded). Finite in-range values are rounded to
        the nearest millisecond (``round()`` rather than ``int()``
        truncation — we were dropping up to 0.999 ms of caller budget
        per call before the round 2 review).

        :param timeout: Maximum seconds to wait for in-flight tasks
            (float — fractional seconds are preserved to millisecond
            resolution before crossing the FFI boundary).
        :raises ContextError: If the tokio runtime is unavailable.
        """
        # u64::MAX milliseconds — matches the Rust-side PyO3 bridge type.
        u64_max = 0xFFFFFFFF_FFFFFFFF
        # Order matters: isinf(+) must be caught BEFORE !isfinite, otherwise
        # math.inf collapses to the NaN/negative abort branch. NaN is not
        # orderable, so explicitly testing isfinite()==False is the only
        # reliable way to trap it.
        if math.isinf(timeout) and timeout > 0:
            millis = u64_max
        elif not math.isfinite(timeout) or timeout <= 0:
            # NaN, negative, negative-infinity, or zero → immediate abort.
            millis = 0
        elif timeout * 1000 > u64_max:
            millis = u64_max
        else:
            millis = round(timeout * 1000)
        self._native.shutdown(millis)

    def __enter__(self) -> SCP:
        """Enter the context-manager scope — returns ``self``."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Shut down on scope exit using the default 5-second timeout."""
        self.shutdown()

    # ------------------------------------------------------------------
    # Operation methods — 159 bridge delegators (PyO3 → asyncio.to_thread)
    # ------------------------------------------------------------------
    #
    # Every method below delegates to the same-named attribute on
    # ``self._native`` (the PyO3 ``_scp_core.SCP`` handle). PyO3 methods
    # are synchronous — they perform ``py.allow_threads(|| rt.block_on(..))``
    # internally — so each wrapper offloads to a worker thread via
    # :func:`asyncio.to_thread` to keep the asyncio event loop responsive.
    #
    # Grouped by domain under ``# region`` banners. Added in Phase 4 PR 5
    # (#1549) — the SDK surface collapse that replaced the module-level
    # free-function façade with method calls on :class:`SCP`.

    # region Identity

    async def create_identity_link_attestation(
        self,
        did: str,
        platform: str,
        handle: str,
        proof: str,
        verification_method: str,
        platform_id: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.create_identity_link_attestation``."""
        return await asyncio.to_thread(
            self._native.create_identity_link_attestation,
            did,
            platform,
            handle,
            proof,
            verification_method,
            platform_id,
        )

    async def identity_add_agent_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_add_agent_key``."""
        return await asyncio.to_thread(self._native.identity_add_agent_key, identity)

    async def identity_attest_device(self, identity_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_attest_device``."""
        return await asyncio.to_thread(self._native.identity_attest_device, identity_did)

    async def identity_create(self, custody: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_create``."""
        return await asyncio.to_thread(self._native.identity_create, custody)

    async def identity_create_with_agent_key(self, custody: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_create_with_agent_key``."""
        return await asyncio.to_thread(self._native.identity_create_with_agent_key, custody)

    async def identity_execute_custody_migration(
        self, did: str, target: str, context_ids: list[str]
    ) -> Any:
        """Delegate to ``_scp_core.SCP.identity_execute_custody_migration``."""
        return await asyncio.to_thread(
            self._native.identity_execute_custody_migration, did, target, context_ids
        )

    async def identity_execute_recovery(self, did: str, tier: str, context_ids: list[str]) -> Any:
        """Delegate to ``_scp_core.SCP.identity_execute_recovery``."""
        return await asyncio.to_thread(
            self._native.identity_execute_recovery, did, tier, context_ids
        )

    async def identity_link_attestations(self, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_link_attestations``."""
        return await asyncio.to_thread(self._native.identity_link_attestations, did)

    async def identity_load(self, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_load``."""
        return await asyncio.to_thread(self._native.identity_load, did)

    async def identity_migrate(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_migrate``."""
        return await asyncio.to_thread(self._native.identity_migrate, identity)

    async def identity_remove_agent_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_remove_agent_key``."""
        return await asyncio.to_thread(self._native.identity_remove_agent_key, identity)

    async def identity_resolve(self, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_resolve``."""
        return await asyncio.to_thread(self._native.identity_resolve, did)

    async def identity_rotate_agent_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_rotate_agent_key``."""
        return await asyncio.to_thread(self._native.identity_rotate_agent_key, identity)

    async def identity_rotate_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_rotate_key``."""
        return await asyncio.to_thread(self._native.identity_rotate_key, identity)

    async def identity_verify_device_attestation(self, did: str, token_base64: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_verify_device_attestation``."""
        return await asyncio.to_thread(
            self._native.identity_verify_device_attestation, did, token_base64
        )

    async def init_storage(self, storage_type: str) -> Any:
        """Delegate to ``_scp_core.SCP.init_storage``."""
        return await asyncio.to_thread(self._native.init_storage, storage_type)

    async def remove_identity_link_attestation(self, did: str, attestation_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.remove_identity_link_attestation``."""
        return await asyncio.to_thread(
            self._native.remove_identity_link_attestation, did, attestation_id
        )

    async def verify_identity_link_attestation(
        self, attestation_json: str, issuer_public_key_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.py_verify_identity_link_attestation``."""
        return await asyncio.to_thread(
            self._native.py_verify_identity_link_attestation,
            attestation_json,
            issuer_public_key_hex,
        )

    # endregion Identity

    # region Context

    async def access_key_generate(self, context_id: str, member_did: str, caller_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.access_key_generate``."""
        return await asyncio.to_thread(
            self._native.access_key_generate, context_id, member_did, caller_did
        )

    async def access_key_restore(self, context_id: str, member_did: str, caller_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.access_key_restore``."""
        return await asyncio.to_thread(
            self._native.access_key_restore, context_id, member_did, caller_did
        )

    async def access_key_revoke(self, context_id: str, member_did: str, caller_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.access_key_revoke``."""
        return await asyncio.to_thread(
            self._native.access_key_revoke, context_id, member_did, caller_did
        )

    async def context_close(self, handle: Any, identity_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_close``."""
        return await asyncio.to_thread(self._native.context_close, handle, identity_did)

    async def context_create(self, identity_did: str, params: dict[str, Any]) -> Any:
        """Delegate to ``_scp_core.SCP.context_create``."""
        return await asyncio.to_thread(self._native.context_create, identity_did, params)

    async def context_drain_events(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_drain_events``."""
        return await asyncio.to_thread(self._native.context_drain_events, handle)

    async def context_export(self, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_export``."""
        return await asyncio.to_thread(self._native.context_export, context_id)

    async def context_handle_ttl_expiry(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_handle_ttl_expiry``."""
        return await asyncio.to_thread(self._native.context_handle_ttl_expiry, handle)

    async def context_import(self, data: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_import``."""
        return await asyncio.to_thread(self._native.context_import, data)

    async def context_is_member(self, handle: Any, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_is_member``."""
        return await asyncio.to_thread(self._native.context_is_member, handle, did)

    async def context_join(
        self, handle: Any, identity_did: str, spending_ucan_jwt: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.context_join``."""
        return await asyncio.to_thread(
            self._native.context_join, handle, identity_did, spending_ucan_jwt
        )

    async def context_leave(self, handle: Any, identity_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_leave``."""
        return await asyncio.to_thread(self._native.context_leave, handle, identity_did)

    async def context_member_count(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_member_count``."""
        return await asyncio.to_thread(self._native.context_member_count, handle)

    async def context_member_dids(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_member_dids``."""
        return await asyncio.to_thread(self._native.context_member_dids, handle)

    async def context_member_role(self, handle: Any, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_member_role``."""
        return await asyncio.to_thread(self._native.context_member_role, handle, did)

    async def context_propose_ttl_extension(
        self, handle: Any, member_did: str, proposed_seconds: int
    ) -> Any:
        """Delegate to ``_scp_core.SCP.context_propose_ttl_extension``."""
        return await asyncio.to_thread(
            self._native.context_propose_ttl_extension, handle, member_did, proposed_seconds
        )

    async def context_receive(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_receive``."""
        return await asyncio.to_thread(self._native.context_receive, handle)

    async def context_reset_ttl_timer(self, handle: Any, new_seconds: int) -> Any:
        """Delegate to ``_scp_core.SCP.context_reset_ttl_timer``."""
        return await asyncio.to_thread(self._native.context_reset_ttl_timer, handle, new_seconds)

    async def context_send(
        self,
        handle: Any,
        identity_did: str,
        payload: bytes | str,
        spending_ucan_jwt: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.context_send``."""
        return await asyncio.to_thread(
            self._native.context_send, handle, identity_did, payload, spending_ucan_jwt
        )

    async def get_economic_policy(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.get_economic_policy``."""
        return await asyncio.to_thread(self._native.get_economic_policy, handle)

    async def restore_all_contexts(self) -> Any:
        """Delegate to ``_scp_core.SCP.restore_all_contexts``."""
        return await asyncio.to_thread(self._native.restore_all_contexts)

    async def restore_context(self, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.restore_context``."""
        return await asyncio.to_thread(self._native.restore_context, context_id)

    async def set_economic_policy(self, handle: Any, policy_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.set_economic_policy``."""
        return await asyncio.to_thread(self._native.set_economic_policy, handle, policy_json)

    # endregion Context

    # region UCAN

    async def ucan_delegate(
        self,
        context_id: str,
        delegator_did: str,
        delegatee_did: str,
        parent_token: str,
        capabilities: list[str],
    ) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_delegate``."""
        return await asyncio.to_thread(
            self._native.ucan_delegate,
            context_id,
            delegator_did,
            delegatee_did,
            parent_token,
            capabilities,
        )

    async def ucan_mint(
        self,
        context_id: str,
        member_did: str,
        capabilities: list[str],
        proofs: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_mint``."""
        return await asyncio.to_thread(
            self._native.ucan_mint, context_id, member_did, capabilities, proofs
        )

    async def ucan_revoke(self, context_id: str, token: str, revoker_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_revoke``."""
        return await asyncio.to_thread(self._native.ucan_revoke, context_id, token, revoker_did)

    async def ucan_validate(
        self,
        context_id: str,
        token: str,
        capability: str,
        presenting_agent_did: str | None = None,
        proof_tokens: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_validate``."""
        return await asyncio.to_thread(
            self._native.ucan_validate,
            context_id,
            token,
            capability,
            presenting_agent_did,
            proof_tokens,
        )

    # endregion UCAN

    # region Broadcast

    async def broadcast_admission(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_admission``."""
        return await asyncio.to_thread(self._native.broadcast_admission, handle)

    async def broadcast_block_subscriber(
        self, handle: Any, subscriber_did: str, blocker_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_block_subscriber``."""
        return await asyncio.to_thread(
            self._native.broadcast_block_subscriber, handle, subscriber_did, blocker_did
        )

    async def broadcast_handle_key_request(
        self, handle: Any, author_did: str, requester_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_handle_key_request``."""
        return await asyncio.to_thread(
            self._native.broadcast_handle_key_request, handle, author_did, requester_did
        )

    async def broadcast_is_subscriber(self, handle: Any, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_is_subscriber``."""
        return await asyncio.to_thread(self._native.broadcast_is_subscriber, handle, did)

    async def broadcast_publish(self, handle: Any, author_did: str, payload: bytes) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_publish``."""
        return await asyncio.to_thread(self._native.broadcast_publish, handle, author_did, payload)

    async def broadcast_publish_asset(
        self,
        handle: Any,
        author_did: str,
        path: str,
        content_type: str,
        body: bytes,
        deploy_id: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_publish_asset``."""
        return await asyncio.to_thread(
            self._native.broadcast_publish_asset,
            handle,
            author_did,
            path,
            content_type,
            body,
            deploy_id,
        )

    async def broadcast_publish_assets(
        self,
        handle: Any,
        author_did: str,
        assets: list[tuple[str, str, bytes]],
        deploy_id: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_publish_assets``."""
        return await asyncio.to_thread(
            self._native.broadcast_publish_assets, handle, author_did, assets, deploy_id
        )

    async def broadcast_subscribe(self, handle: Any, subscriber_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_subscribe``."""
        return await asyncio.to_thread(self._native.broadcast_subscribe, handle, subscriber_did)

    async def broadcast_subscriber_count(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_subscriber_count``."""
        return await asyncio.to_thread(self._native.broadcast_subscriber_count, handle)

    async def broadcast_unblock_subscriber(
        self, handle: Any, subscriber_did: str, unblocker_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_unblock_subscriber``."""
        return await asyncio.to_thread(
            self._native.broadcast_unblock_subscriber, handle, subscriber_did, unblocker_did
        )

    async def broadcast_unsubscribe(
        self, handle: Any, subscriber_did: str, rotate_keys: bool = False
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_unsubscribe``."""
        return await asyncio.to_thread(
            self._native.broadcast_unsubscribe, handle, subscriber_did, rotate_keys
        )

    # endregion Broadcast

    # region Governance

    async def add_checkpoint_cosignature(
        self, handle: Any, checkpoint_json: str, signer_did: str, signature_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.add_checkpoint_cosignature``."""
        return await asyncio.to_thread(
            self._native.add_checkpoint_cosignature,
            handle,
            checkpoint_json,
            signer_did,
            signature_hex,
        )

    async def apply_pending_ceiling_modification(self, handle: Any, current_timestamp: int) -> Any:
        """Delegate to ``_scp_core.SCP.apply_pending_ceiling_modification``."""
        return await asyncio.to_thread(
            self._native.apply_pending_ceiling_modification, handle, current_timestamp
        )

    async def create_governance_checkpoint(
        self,
        handle: Any,
        checkpoint_seq: int,
        merkle_root_hex: str,
        event_count: int,
        last_event_hash_hex: str,
        state_snapshot_hash_hex: str,
        creator_did: str,
        creator_signature_hex: str,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.create_governance_checkpoint``."""
        return await asyncio.to_thread(
            self._native.create_governance_checkpoint,
            handle,
            checkpoint_seq,
            merkle_root_hex,
            event_count,
            last_event_hash_hex,
            state_snapshot_hash_hex,
            creator_did,
            creator_signature_hex,
        )

    async def evaluate_invitation(
        self,
        params_json: str,
        inviter_did: str,
        identity_did: str,
        policy_json: str | None = None,
        spending_json: str | None = None,
        trusted_dids_json: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.evaluate_invitation``."""
        return await asyncio.to_thread(
            self._native.evaluate_invitation,
            params_json,
            inviter_did,
            identity_did,
            policy_json,
            spending_json,
            trusted_dids_json,
        )

    async def finalize_close(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.finalize_close``."""
        return await asyncio.to_thread(self._native.finalize_close, handle)

    async def governance_approve(self, handle: Any, identity_did: str, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_approve``."""
        return await asyncio.to_thread(
            self._native.governance_approve, handle, identity_did, proposal_id_hex
        )

    async def governance_execute(self, handle: Any, proposal_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_execute``."""
        return await asyncio.to_thread(self._native.governance_execute, handle, proposal_json)

    async def governance_get_proposal(self, handle: Any, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_get_proposal``."""
        return await asyncio.to_thread(
            self._native.governance_get_proposal, handle, proposal_id_hex
        )

    async def governance_list_proposals(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.governance_list_proposals``."""
        return await asyncio.to_thread(self._native.governance_list_proposals, handle)

    async def governance_propose(self, handle: Any, identity_did: str, action_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_propose``."""
        return await asyncio.to_thread(
            self._native.governance_propose, handle, identity_did, action_json
        )

    async def governance_reject(self, handle: Any, identity_did: str, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_reject``."""
        return await asyncio.to_thread(
            self._native.governance_reject, handle, identity_did, proposal_id_hex
        )

    async def governance_withdraw(
        self, handle: Any, identity_did: str, proposal_id_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.governance_withdraw``."""
        return await asyncio.to_thread(
            self._native.governance_withdraw, handle, identity_did, proposal_id_hex
        )

    async def migration_state(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.migration_state``."""
        return await asyncio.to_thread(self._native.migration_state, handle)

    async def tombstone_migrated_context(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.tombstone_migrated_context``."""
        return await asyncio.to_thread(self._native.tombstone_migrated_context, handle)

    # endregion Governance

    # region MCP

    async def mcp_client_connect_sse(self, url: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_connect_sse``."""
        return await asyncio.to_thread(self._native.py_mcp_client_connect_sse, url)

    async def mcp_client_connect_stdio(self, command: list[str]) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_connect_stdio``."""
        return await asyncio.to_thread(self._native.py_mcp_client_connect_stdio, command)

    async def mcp_client_disconnect(self, handle: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_disconnect``."""
        return await asyncio.to_thread(self._native.py_mcp_client_disconnect, handle)

    async def mcp_client_info(self, handle: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_info``."""
        return await asyncio.to_thread(self._native.py_mcp_client_info, handle)

    async def mcp_client_invoke(
        self, handle: str, tool_name: str, input: dict[str, Any], context_id: str, identity_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_invoke``."""
        return await asyncio.to_thread(
            self._native.py_mcp_client_invoke, handle, tool_name, input, context_id, identity_did
        )

    async def mcp_client_list_tools(self, handle: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_list_tools``."""
        return await asyncio.to_thread(self._native.py_mcp_client_list_tools, handle)

    async def mcp_load_contexts(self, identity_did: str, _relay_url: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_load_contexts``."""
        return await asyncio.to_thread(self._native.py_mcp_load_contexts, identity_did, _relay_url)

    async def mcp_register_tool_handler(self, context_id: str, tool_name: str, handler: Any) -> Any:
        """Delegate to ``_scp_core.SCP.mcp_register_tool_handler``."""
        return await asyncio.to_thread(
            self._native.mcp_register_tool_handler, context_id, tool_name, handler
        )

    async def mcp_serve(
        self,
        identity_did: str,
        context_ids: list[str],
        transport: str,
        ucan_token: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_serve``."""
        return await asyncio.to_thread(
            self._native.py_mcp_serve, identity_did, context_ids, transport, ucan_token
        )

    async def mcp_server_info(self, handle: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_server_info``."""
        return await asyncio.to_thread(self._native.py_mcp_server_info, handle)

    async def mcp_server_stop(self, handle: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_server_stop``."""
        return await asyncio.to_thread(self._native.py_mcp_server_stop, handle)

    async def mcp_server_wait(self, handle: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_server_wait``."""
        return await asyncio.to_thread(self._native.py_mcp_server_wait, handle)

    async def registry_cleanup(self) -> Any:
        """Delegate to ``_scp_core.SCP.py_registry_cleanup``."""
        return await asyncio.to_thread(self._native.py_registry_cleanup)

    async def registry_stats(self) -> Any:
        """Delegate to ``_scp_core.SCP.py_registry_stats``."""
        return await asyncio.to_thread(self._native.py_registry_stats)

    # endregion MCP

    # region Transport

    async def configure_relay_transport(self, relay_url: str, local_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.configure_relay_transport``."""
        return await asyncio.to_thread(self._native.configure_relay_transport, relay_url, local_did)

    async def transport_adapter_count(self) -> Any:
        """Delegate to ``_scp_core.SCP.transport_adapter_count``."""
        return await asyncio.to_thread(self._native.transport_adapter_count)

    async def transport_add_relay(self, relay_url: str, source: str = "explicit") -> Any:
        """Delegate to ``_scp_core.SCP.transport_add_relay``."""
        return await asyncio.to_thread(self._native.transport_add_relay, relay_url, source)

    async def transport_assign_relay_set(self, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.transport_assign_relay_set``."""
        return await asyncio.to_thread(self._native.transport_assign_relay_set, context_id)

    async def transport_connect(self, relay_url: str, source: str = "explicit") -> Any:
        """Delegate to ``_scp_core.SCP.transport_connect``."""
        return await asyncio.to_thread(self._native.transport_connect, relay_url, source)

    async def transport_disconnect(self) -> Any:
        """Delegate to ``_scp_core.SCP.transport_disconnect``."""
        return await asyncio.to_thread(self._native.transport_disconnect)

    async def transport_reliability(self, adapter_index: int) -> Any:
        """Delegate to ``_scp_core.SCP.transport_reliability``."""
        return await asyncio.to_thread(self._native.transport_reliability, adapter_index)

    async def transport_status(self) -> Any:
        """Delegate to ``_scp_core.SCP.transport_status``."""
        return await asyncio.to_thread(self._native.transport_status)

    # endregion Transport

    # region Event Log

    async def event_log_checkpoint(self, context_id: str, identity_did: str, epoch: int) -> Any:
        """Delegate to ``_scp_core.SCP.event_log_checkpoint``."""
        return await asyncio.to_thread(
            self._native.event_log_checkpoint, context_id, identity_did, epoch
        )

    async def event_log_query(self, context_id: str, filter: dict[str, Any] | None = None) -> Any:
        """Delegate to ``_scp_core.SCP.event_log_query``."""
        return await asyncio.to_thread(self._native.event_log_query, context_id, filter)

    async def event_log_verify(self, context_id: str, claim: dict[str, Any]) -> Any:
        """Delegate to ``_scp_core.SCP.event_log_verify``."""
        return await asyncio.to_thread(self._native.event_log_verify, context_id, claim)

    # endregion Event Log

    # region Economy

    async def economy_antispam_escalated_cost(
        self,
        context_id: str,
        sender_did: str,
        now: int,
        base_cost: int,
        thresholds_json: str,
        floor: int | None = None,
        cap: int | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.economy_antispam_escalated_cost``."""
        return await asyncio.to_thread(
            self._native.economy_antispam_escalated_cost,
            context_id,
            sender_did,
            now,
            base_cost,
            thresholds_json,
            floor,
            cap,
        )

    async def economy_antispam_record(
        self, context_id: str, sender_did: str, timestamp: int
    ) -> Any:
        """Delegate to ``_scp_core.SCP.economy_antispam_record``."""
        return await asyncio.to_thread(
            self._native.economy_antispam_record, context_id, sender_did, timestamp
        )

    async def economy_antispam_velocity(self, context_id: str, sender_did: str, now: int) -> Any:
        """Delegate to ``_scp_core.SCP.economy_antispam_velocity``."""
        return await asyncio.to_thread(
            self._native.economy_antispam_velocity, context_id, sender_did, now
        )

    async def economy_budget_grant(self, context_id: str, did: str, amount: int) -> Any:
        """Delegate to ``_scp_core.SCP.economy_budget_grant``."""
        return await asyncio.to_thread(self._native.economy_budget_grant, context_id, did, amount)

    async def economy_budget_record_spend(self, context_id: str, did: str, amount: int) -> Any:
        """Delegate to ``_scp_core.SCP.economy_budget_record_spend``."""
        return await asyncio.to_thread(
            self._native.economy_budget_record_spend, context_id, did, amount
        )

    async def economy_budget_remaining(self, context_id: str, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.economy_budget_remaining``."""
        return await asyncio.to_thread(self._native.economy_budget_remaining, context_id, did)

    # endregion Economy

    # region Trust

    async def aggregate_trust_input(
        self,
        context_id: str,
        subject_did: str,
        events_json: str,
        merkle_root_json: str,
        consequence_rules_json: str,
        threshold_requirements_json: str,
        attestor_sets_json: str,
        cached_attestations_json: str,
        challenge_results_json: str,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.aggregate_trust_input``."""
        return await asyncio.to_thread(
            self._native.aggregate_trust_input,
            context_id,
            subject_did,
            events_json,
            merkle_root_json,
            consequence_rules_json,
            threshold_requirements_json,
            attestor_sets_json,
            cached_attestations_json,
            challenge_results_json,
        )

    async def trust_query_score(self, did: str, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.trust_query_score``."""
        return await asyncio.to_thread(self._native.trust_query_score, did, context_id)

    # endregion Trust

    # region SCPID

    async def scpid_challenge(self, audience: str, ttl_seconds: int) -> Any:
        """Delegate to ``_scp_core.SCP.scpid_challenge``."""
        return await asyncio.to_thread(self._native.scpid_challenge, audience, ttl_seconds)

    async def scpid_sign(self, did: str, signing_key_id: str, challenge_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.scpid_sign``."""
        return await asyncio.to_thread(self._native.scpid_sign, did, signing_key_id, challenge_json)

    async def scpid_verify(self, response_json: str, challenge_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.scpid_verify``."""
        return await asyncio.to_thread(self._native.scpid_verify, response_json, challenge_json)

    # endregion SCPID

    # region Provenance

    async def evaluate_provenance_quality(
        self,
        source_context: str | None = None,
        source_type: str = "persistent",
        context_state: str = "unknown",
        counterparties: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.evaluate_provenance_quality``."""
        return await asyncio.to_thread(
            self._native.evaluate_provenance_quality,
            source_context,
            source_type,
            context_state,
            counterparties,
        )

    async def provenance_attach(
        self,
        source_context_id: str,
        source_type: str,
        memory_scope: str,
        members: list[str],
        target_context_id: str,
        actor_did: str,
        existing_chain_depth: int | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.provenance_attach``."""
        return await asyncio.to_thread(
            self._native.provenance_attach,
            source_context_id,
            source_type,
            memory_scope,
            members,
            target_context_id,
            actor_did,
            existing_chain_depth,
        )

    async def provenance_check_chain_depth(
        self, chain_depth: int, max_depth: int | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.provenance_check_chain_depth``."""
        return await asyncio.to_thread(
            self._native.provenance_check_chain_depth, chain_depth, max_depth
        )

    async def provenance_pseudonymize_counterparties(
        self, provenance_json: str, pseudonym_key_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.provenance_pseudonymize_counterparties``."""
        return await asyncio.to_thread(
            self._native.provenance_pseudonymize_counterparties, provenance_json, pseudonym_key_hex
        )

    async def provenance_redact_counterparties(self, provenance_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.provenance_redact_counterparties``."""
        return await asyncio.to_thread(
            self._native.provenance_redact_counterparties, provenance_json
        )

    async def provenance_update_source_type(self, provenance_json: str, new_state: str) -> Any:
        """Delegate to ``_scp_core.SCP.provenance_update_source_type``."""
        return await asyncio.to_thread(
            self._native.provenance_update_source_type, provenance_json, new_state
        )

    # endregion Provenance

    # region Tools

    async def tool_interface_accept(self, context_id: str, interface_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.tool_interface_accept``."""
        return await asyncio.to_thread(
            self._native.tool_interface_accept, context_id, interface_json
        )

    async def tool_interface_expose(
        self,
        context_id: str,
        tool_id: str,
        target_context_id: str,
        rate_limit_json: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.tool_interface_expose``."""
        return await asyncio.to_thread(
            self._native.tool_interface_expose,
            context_id,
            tool_id,
            target_context_id,
            rate_limit_json,
        )

    async def tool_interface_revoke(self, context_id: str, interface_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.tool_interface_revoke``."""
        return await asyncio.to_thread(
            self._native.tool_interface_revoke, context_id, interface_id_hex
        )

    async def tool_invoke(
        self,
        context_id: str,
        tool_id: str,
        input: dict[str, Any],
        identity_did: str,
        ucan_token: str,
        proof_tokens: list[str] | None = None,
        spending_ucan: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.tool_invoke``."""
        return await asyncio.to_thread(
            self._native.tool_invoke,
            context_id,
            tool_id,
            input,
            identity_did,
            ucan_token,
            proof_tokens,
            spending_ucan,
        )

    async def tool_invoke_cross_context(
        self,
        source_context_id: str,
        target_context_id: str,
        tool_id: str,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str,
        chain_depth: int,
        proof_tokens: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.tool_invoke_cross_context``."""
        return await asyncio.to_thread(
            self._native.tool_invoke_cross_context,
            source_context_id,
            target_context_id,
            tool_id,
            input,
            invoker_did,
            ucan_token,
            chain_depth,
            proof_tokens,
        )

    async def tool_register(self, context_id: str, registration: dict[str, Any]) -> Any:
        """Delegate to ``_scp_core.SCP.tool_register``."""
        return await asyncio.to_thread(self._native.tool_register, context_id, registration)

    async def tool_session_close(self, context_id: str, session_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.tool_session_close``."""
        return await asyncio.to_thread(self._native.tool_session_close, context_id, session_id)

    async def tool_session_create(
        self, context_id: str, tool_id: str, source_context_id: str, ttl_seconds: int | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.tool_session_create``."""
        return await asyncio.to_thread(
            self._native.tool_session_create, context_id, tool_id, source_context_id, ttl_seconds
        )

    async def tool_session_invoke(
        self,
        context_id: str,
        session_id: str,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str,
        proof_tokens: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.tool_session_invoke``."""
        return await asyncio.to_thread(
            self._native.tool_session_invoke,
            context_id,
            session_id,
            input,
            invoker_did,
            ucan_token,
            proof_tokens,
        )

    async def tool_verify(self, context_id: str, tool_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.tool_verify``."""
        return await asyncio.to_thread(self._native.tool_verify, context_id, tool_id)

    # endregion Tools

    # region Fullstack

    async def fullstack_add_member(self, node: Any, context_id: str, member_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_add_member``."""
        return await asyncio.to_thread(
            self._native.fullstack_add_member, node, context_id, member_did
        )

    async def fullstack_create_context(self, node: Any, context_id: str, ceiling_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_create_context``."""
        return await asyncio.to_thread(
            self._native.fullstack_create_context, node, context_id, ceiling_json
        )

    async def fullstack_create_node(self, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_create_node``."""
        return await asyncio.to_thread(self._native.fullstack_create_node, did)

    async def fullstack_decrypt_message(
        self, node: Any, context_id: str, ciphertext: Any, sender_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_decrypt_message``."""
        return await asyncio.to_thread(
            self._native.fullstack_decrypt_message, node, context_id, ciphertext, sender_did
        )

    async def fullstack_join_from_welcome(self, node: Any, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_join_from_welcome``."""
        return await asyncio.to_thread(self._native.fullstack_join_from_welcome, node, context_id)

    async def fullstack_remove_member(self, node: Any, context_id: str, member_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_remove_member``."""
        return await asyncio.to_thread(
            self._native.fullstack_remove_member, node, context_id, member_did
        )

    async def fullstack_reset_network(self) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_reset_network``."""
        return await asyncio.to_thread(self._native.fullstack_reset_network)

    async def fullstack_send_message(self, node: Any, context_id: str, payload: Any) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_send_message``."""
        return await asyncio.to_thread(
            self._native.fullstack_send_message, node, context_id, payload
        )

    async def fullstack_sync_sender_keys(self, node_a: Any, node_b: Any, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_sync_sender_keys``."""
        return await asyncio.to_thread(
            self._native.fullstack_sync_sender_keys, node_a, node_b, context_id
        )

    # endregion Fullstack

    # region Discovery

    async def address_resolve(
        self, owner_did: str, address: str, known_contexts_json: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.address_resolve``."""
        return await asyncio.to_thread(
            self._native.address_resolve, owner_did, address, known_contexts_json
        )

    async def handle_deregister(self, discovery_context_id: str, handle: str, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.handle_deregister``."""
        return await asyncio.to_thread(
            self._native.handle_deregister, discovery_context_id, handle, did
        )

    async def handle_lookup(
        self, discovery_context_id: str, handle: str, type_filter: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.handle_lookup``."""
        return await asyncio.to_thread(
            self._native.handle_lookup, discovery_context_id, handle, type_filter
        )

    async def handle_register(
        self,
        discovery_context_id: str,
        handle: str,
        target_json: str,
        registrant_did: str,
        description: str | None = None,
        tags: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.handle_register``."""
        return await asyncio.to_thread(
            self._native.handle_register,
            discovery_context_id,
            handle,
            target_json,
            registrant_did,
            description,
            tags,
        )

    async def petname_get_for_context(self, owner_did: str, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_get_for_context``."""
        return await asyncio.to_thread(self._native.petname_get_for_context, owner_did, context_id)

    async def petname_get_for_did(self, owner_did: str, target_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_get_for_did``."""
        return await asyncio.to_thread(self._native.petname_get_for_did, owner_did, target_did)

    async def petname_remove(self, owner_did: str, target_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_remove``."""
        return await asyncio.to_thread(self._native.petname_remove, owner_did, target_did)

    async def petname_remove_context(self, owner_did: str, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_remove_context``."""
        return await asyncio.to_thread(self._native.petname_remove_context, owner_did, context_id)

    async def petname_resolve_context(self, owner_did: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_resolve_context``."""
        return await asyncio.to_thread(self._native.petname_resolve_context, owner_did, name)

    async def petname_resolve_did(self, owner_did: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_resolve_did``."""
        return await asyncio.to_thread(self._native.petname_resolve_did, owner_did, name)

    async def petname_set(self, owner_did: str, target_did: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_set``."""
        return await asyncio.to_thread(self._native.petname_set, owner_did, target_did, name)

    async def petname_set_context(self, owner_did: str, context_id: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_set_context``."""
        return await asyncio.to_thread(
            self._native.petname_set_context, owner_did, context_id, name
        )

    async def scope_deregister(self, scope_context_id: str, name: str, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.scope_deregister``."""
        return await asyncio.to_thread(self._native.scope_deregister, scope_context_id, name, did)

    async def scope_lookup(self, scope_context_id: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.scope_lookup``."""
        return await asyncio.to_thread(self._native.scope_lookup, scope_context_id, name)

    async def scope_register(
        self,
        scope_context_id: str,
        name: str,
        target_context_id: str,
        relay_urls: list[str],
        registrant_did: str,
        description: str | None = None,
        tags: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.scope_register``."""
        return await asyncio.to_thread(
            self._native.scope_register,
            scope_context_id,
            name,
            target_context_id,
            relay_urls,
            registrant_did,
            description,
            tags,
        )

    # endregion Discovery

    # region Server

    async def node_start_in_memory(self, identity_did: str | None = None) -> Any:
        """Delegate to ``_scp_core.SCP.node_start_in_memory``."""
        return await asyncio.to_thread(self._native.node_start_in_memory, identity_did)

    async def node_start_local(
        self, data_dir: str, identity_did: str | None = None, passphrase: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.node_start_local``."""
        return await asyncio.to_thread(
            self._native.node_start_local, data_dir, identity_did, passphrase
        )

    async def relay_start_in_memory(self) -> Any:
        """Delegate to ``_scp_core.SCP.relay_start_in_memory``."""
        return await asyncio.to_thread(self._native.relay_start_in_memory)

    async def relay_start_local(self, data_dir: str) -> Any:
        """Delegate to ``_scp_core.SCP.relay_start_local``."""
        return await asyncio.to_thread(self._native.relay_start_local, data_dir)

    # endregion Server

    # region Bridge

    async def bridge_create_shadow(
        self, bridge_id: str, platform_handle: str, bridge_mode: str, context_id: str = "ctx-shadow"
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_create_shadow``."""
        return await asyncio.to_thread(
            self._native.bridge_create_shadow, bridge_id, platform_handle, bridge_mode, context_id
        )

    async def bridge_credential_delete_key(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_delete_key``."""
        return await asyncio.to_thread(self._native.bridge_credential_delete_key, bridge_id)

    async def bridge_credential_get_key(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_get_key``."""
        return await asyncio.to_thread(self._native.bridge_credential_get_key, bridge_id)

    async def bridge_credential_list(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_list``."""
        return await asyncio.to_thread(self._native.bridge_credential_list, bridge_id)

    async def bridge_credential_provision(
        self, bridge_id: str, credential_type: str, plaintext: bytes, bridge_credential_key: bytes
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_provision``."""
        return await asyncio.to_thread(
            self._native.bridge_credential_provision,
            bridge_id,
            credential_type,
            plaintext,
            bridge_credential_key,
        )

    async def bridge_credential_retrieve(
        self, bridge_id: str, credential_type: str, bridge_credential_key: bytes
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_retrieve``."""
        return await asyncio.to_thread(
            self._native.bridge_credential_retrieve,
            bridge_id,
            credential_type,
            bridge_credential_key,
        )

    async def bridge_credential_revoke(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_revoke``."""
        return await asyncio.to_thread(self._native.bridge_credential_revoke, bridge_id)

    async def bridge_credential_rotate(
        self,
        bridge_id: str,
        credential_type: str,
        new_plaintext: bytes,
        bridge_credential_key: bytes,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_rotate``."""
        return await asyncio.to_thread(
            self._native.bridge_credential_rotate,
            bridge_id,
            credential_type,
            new_plaintext,
            bridge_credential_key,
        )

    async def bridge_credential_store_key(self, bridge_id: str, key: bytes) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_store_key``."""
        return await asyncio.to_thread(self._native.bridge_credential_store_key, bridge_id, key)

    # endregion Bridge

    def __repr__(self) -> str:
        """Developer-facing repr including the native ``instance_id``."""
        return f"SCP(instance_id={self.instance_id})"
