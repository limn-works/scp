"""Bridge connector operations for the SCP Python SDK.

Provides functions for registering bridge connectors, evaluating bridge
trust levels, and creating shadow identities for external platform
participants.

All operations delegate to the ``_scp_core`` PyO3 bridge layer.

See spec section 12 (Bridge System) and ADR-023.
"""

from __future__ import annotations

from typing import Any

from scp_sdk.errors import ScpError


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-sdk with: pip install scp-sdk",
            code="SCP-UNKNOWN-0001",
        ) from exc


def register(
    context_id: str,
    operator_did: str,
    platform: str,
    mode: str,
) -> dict[str, Any]:
    """Register a bridge connector with a context.

    Creates a registration request and immediately approves it.

    Args:
        context_id: Context to register the bridge in.
        operator_did: DID of the human operator accountable for the bridge.
        platform: External platform name (e.g., ``"discord"``, ``"slack"``).
        mode: Bridge mode: ``"relay"``, ``"puppet"``, ``"api"``, or
            ``"cooperative"``.

    Returns:
        A dict with ``bridge_id``, ``operator_did``, ``platform``,
        ``mode``, ``status``, ``context_id``.

    Raises:
        ValidationError: If *mode* is not recognized.
        ContextError: If registration fails.
    """
    bridge = _bridge()
    return dict(bridge.bridge_register(context_id, operator_did, platform, mode))


def evaluate_trust(
    *,
    is_bridged: bool = False,
    is_native_transport: bool = True,
    shadow_status: str = "shadow",
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
        shadow_status: ``"shadow"`` or ``"claimed"`` (only if *is_bridged*).

    Returns:
        Trust tier as an integer (0--3).

    Raises:
        ValidationError: If *shadow_status* is invalid.
    """
    bridge = _bridge()
    return bridge.bridge_evaluate_trust(is_bridged, is_native_transport, shadow_status)


def create_shadow(
    bridge_id: str,
    platform_handle: str,
    bridge_mode: str,
    context_id: str = "ctx-shadow",
) -> dict[str, Any]:
    """Create a shadow identity for an external platform participant.

    Args:
        bridge_id: The bridge connector ID that owns this shadow.
        platform_handle: External platform handle (e.g., ``"@user#1234"``).
        bridge_mode: Bridge mode: ``"relay"``, ``"puppet"``, ``"api"``, or
            ``"cooperative"``.
        context_id: Context the shadow is being created in.

    Returns:
        A dict with ``shadow_id``, ``platform_handle``, ``bridge_id``,
        ``attributed_role``, ``provenance_status``.

    Raises:
        ValidationError: If *bridge_mode* is invalid.
        ContextError: If shadow creation fails.
    """
    bridge = _bridge()
    return dict(bridge.bridge_create_shadow(bridge_id, platform_handle, bridge_mode, context_id))


__all__ = [
    "create_shadow",
    "evaluate_trust",
    "register",
]
