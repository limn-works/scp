"""Bridge connector operations for the SCP Python SDK.

Provides functions for registering bridge connectors, evaluating bridge
trust levels, and creating shadow identities for external platform
participants.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See spec section 12 (Bridge System) and ADR-023.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ScpError
from scp_sdk.types import BridgeMode, ShadowStatus

if TYPE_CHECKING:
    from scp_sdk.scp import SCP


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily.

    Used for the pure-function bridge operations (``bridge_register``,
    ``bridge_evaluate_trust``) that do not require an :class:`SCP`
    instance. See :func:`create_shadow` for the stateful variant.
    """
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


def register(
    context_id: str,
    operator_did: str,
    governance_did: str,
    platform: str,
    mode: BridgeMode | str,
) -> dict[str, Any]:
    """Register a bridge connector with a context.

    Creates a registration request and immediately approves it using the
    provided governance DID.

    Args:
        context_id: Context to register the bridge in.
        operator_did: DID of the human operator accountable for the bridge.
        governance_did: DID of the governance authority approving the
            registration.  Must differ from *operator_did* (self-approval
            is forbidden per ADR-023).
        platform: External platform name (e.g., ``"discord"``, ``"slack"``).
        mode: Bridge mode.  Accepts a :class:`~scp_sdk.types.BridgeMode`
            enum member or a raw string (``"relay"``, ``"puppet"``,
            ``"api"``, or ``"cooperative"``).

    Returns:
        A dict with ``bridge_id``, ``operator_did``, ``platform``,
        ``mode``, ``status``, ``context_id``.

    Raises:
        ValidationError: If *mode* is not recognized.
        ContextError: If registration or approval fails (including
            self-approval).
    """
    bridge = _bridge()
    mode_str = mode.value if isinstance(mode, BridgeMode) else mode
    return dict(
        bridge.bridge_register(context_id, operator_did, governance_did, platform, mode_str)
    )


def evaluate_trust(
    *,
    is_bridged: bool = False,
    is_native_transport: bool = True,
    shadow_status: ShadowStatus | str = ShadowStatus.SHADOW,
) -> int:
    """Evaluate the trust level for an action based on bridge provenance.

    Returns an integer (0--3) representing the trust tier:

    - ``0`` -- ``ShadowBridged`` (weakest).
    - ``1`` -- ``ClaimedBridged``.
    - ``2`` -- ``NativeBridged``.
    - ``3`` -- ``NativeNative`` (strongest).

    Args:
        is_bridged: Whether the action has bridge provenance.
        is_native_transport: Whether the transport is native SCP.
        shadow_status: Shadow provenance status.  Accepts a
            :class:`~scp_sdk.types.ShadowStatus` enum member or a raw
            string (``"shadow"`` or ``"claimed"``).  Only meaningful
            when *is_bridged* is ``True``.

    Returns:
        Trust tier as an integer (0--3).

    Raises:
        ValidationError: If *shadow_status* is invalid.
    """
    bridge = _bridge()
    status_str = shadow_status.value if isinstance(shadow_status, ShadowStatus) else shadow_status
    return bridge.bridge_evaluate_trust(is_bridged, is_native_transport, status_str)


def create_shadow(
    scp: SCP,
    bridge_id: str,
    platform_handle: str,
    bridge_mode: BridgeMode | str,
    context_id: str = "ctx-shadow",
) -> dict[str, Any]:
    """Create a shadow identity for an external platform participant.

    Args:
        scp: The :class:`scp_sdk.SCP` instance that owns the bridge state.
        bridge_id: The bridge connector ID that owns this shadow.
        platform_handle: External platform handle (e.g., ``"@user#1234"``).
        bridge_mode: Bridge mode.  Accepts a
            :class:`~scp_sdk.types.BridgeMode` enum member or a raw
            string (``"relay"``, ``"puppet"``, ``"api"``, or
            ``"cooperative"``).
        context_id: Context the shadow is being created in.

    Returns:
        A dict with ``shadow_id``, ``platform_handle``, ``bridge_id``,
        ``attributed_role``, ``provenance_status``.

    Raises:
        ValidationError: If *bridge_mode* is invalid.
        ContextError: If shadow creation fails.
    """
    native = scp._native
    mode_str = bridge_mode.value if isinstance(bridge_mode, BridgeMode) else bridge_mode
    return dict(native.bridge_create_shadow(bridge_id, platform_handle, mode_str, context_id))


__all__ = [
    "create_shadow",
    "evaluate_trust",
    "register",
]
