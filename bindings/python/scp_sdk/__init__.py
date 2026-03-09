"""SCP Python SDK -- Shared Context Protocol.

This package provides Pythonic wrappers around the ``_scp_core`` PyO3
extension module, offering typed dataclasses, an exception hierarchy,
and shared enums for building agents and applications on top of SCP.

Usage::

    import scp_sdk
    from scp_sdk import Identity, Context, ToolDefinition, evaluate_trust

    # Or via namespace alias:
    import scp_sdk as scp
    identity = await scp.Identity.create()

See ``.docs/adrs/phase-3.md`` ADR-014 for the full SDK design.
"""

from __future__ import annotations

from scp_sdk.context import Context, Membership
from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    ContextError,
    CryptoError,
    IdentityError,
    ScpError,
    ToolError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.event_log import Checkpoint, Event, EventLog, Proof
from scp_sdk.governance import (
    GovernanceActionResult,
    execute_governance_action,
    handle_ttl_expiry,
    propose_ttl_extension,
    reset_ttl_timer,
)
from scp_sdk.identity import DIDDocument, Identity
from scp_sdk.mcp import (
    McpClient,
    McpProvenance,
    McpServer,
    McpToolDefinition,
    McpToolResult,
    configure_stdio_allowlist,
    disable_stdio_allowlist,
    get_stdio_allowlist,
    register_tool_handler,
    registry_cleanup,
    registry_stats,
    reset_stdio_allowlist,
    serve_mcp,
)
from scp_sdk.sync import run_sync
from scp_sdk.tools import TestVector, ToolDefinition
from scp_sdk.transport import TransportConfig, TransportStatus, connect_relay, relay_status
from scp_sdk.trust import (
    Attestation,
    BehavioralRecord,
    CapabilityValidation,
    ChallengeResult,
    Endorsement,
    TrustEvaluation,
    evaluate_trust,
)
from scp_sdk.types import (
    Capability,
    CeilingPolicy,
    ContextMode,
    DiscoveryMethod,
    MemberRole,
    MemoryScope,
    Message,
    PromotionPolicy,
    Provenance,
    ProvenanceQuality,
    SourceType,
)
from scp_sdk.ucan import UcanToken, delegate, mint, revoke, validate

__version__ = "0.1.0"

__all__ = [
    "BRIDGE_ERROR_MAP",
    "Attestation",
    "BehavioralRecord",
    "Capability",
    "CapabilityValidation",
    "CeilingPolicy",
    "ChallengeResult",
    "Checkpoint",
    "Context",
    "ContextError",
    "ContextMode",
    "CryptoError",
    "DIDDocument",
    "DiscoveryMethod",
    "Endorsement",
    "Event",
    "EventLog",
    "GovernanceActionResult",
    "Identity",
    "IdentityError",
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "MemberRole",
    "Membership",
    "MemoryScope",
    "Message",
    "PromotionPolicy",
    "Proof",
    "Provenance",
    "ProvenanceQuality",
    "ScpError",
    "SourceType",
    "TestVector",
    "ToolDefinition",
    "ToolError",
    "TransportConfig",
    "TransportError",
    "TransportStatus",
    "TrustEvaluation",
    "UcanPermissionError",
    "UcanToken",
    "ValidationError",
    "__version__",
    "configure_stdio_allowlist",
    "connect_relay",
    "delegate",
    "disable_stdio_allowlist",
    "evaluate_trust",
    "execute_governance_action",
    "get_stdio_allowlist",
    "handle_ttl_expiry",
    "mint",
    "propose_ttl_extension",
    "register_tool_handler",
    "registry_cleanup",
    "registry_stats",
    "relay_status",
    "reset_stdio_allowlist",
    "reset_ttl_timer",
    "revoke",
    "run_sync",
    "serve_mcp",
    "validate",
]
