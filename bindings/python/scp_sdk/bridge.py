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
    pass


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily.

    Used for the pure-function bridge operations (``bridge_register``,
    ``bridge_provenance_tier``) that do not require an :class:`SCP`
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


def bridge_provenance_tier(
    *,
    is_bridged: bool = False,
    is_native_transport: bool = True,
    shadow_status: ShadowStatus | str = ShadowStatus.SHADOW,
) -> int:
    """Evaluate the bridge-provenance trust tier for an action.

    This is the bridge-provenance signal (spec §12 / ADR-023), distinct from
    the four-layer trust evaluation :func:`scp_sdk.trust.evaluate_trust`. It
    returns an integer (0--3) representing the trust tier:

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


__all__ = [
    "bridge_provenance_tier",
    "register",
]
